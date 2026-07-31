import json
import time
import logging
from typing import Dict, Optional

from parser import normalizar_evento_wazuh, normalizar_evento_suricata, leer_nuevos_eventos
from rule_engine import RuleEngine
from ai_analyzer import analizar_evento
from database import guardar_evento, inicializar_db
from telegram_bot import enviar_alerta
from config import ALERT_MIN_RISK, RISK_LEVELS, POLL_INTERVAL_SECONDS
from utils import ahora_iso, log_coloreado

logger = logging.getLogger(__name__)


class EventTracker:
    def __init__(self, window_seconds: int = 60, threshold: int = 3):
        self.window = window_seconds
        self.threshold = threshold
        self.buckets = {}

    def track(self, normalizado: dict, resultado_reglas: dict) -> bool:
        fuente = normalizado.get("fuente", "")
        ip = normalizado.get("ip_origen", normalizado.get("agente_ip", normalizado.get("raw_log", "")))
        ataque = resultado_reglas.get("ataque", "")
        key = f"{fuente}|{ip}|{ataque}"
        now = time.time()

        if key not in self.buckets:
            self.buckets[key] = []

        self.buckets[key] = [t for t in self.buckets[key] if now - t < self.window]
        self.buckets[key].append(now)

        count = len(self.buckets[key])
        triggered = count >= self.threshold

        if triggered and count == self.threshold:
            log_coloreado("WARNING", f"  [PATRON] {ataque} desde {ip}: {count} veces en {self.window}s")

        return triggered


class AlertRateLimiter:
    def __init__(self, cooldown_seconds: int = 300):
        self.cooldown = cooldown_seconds
        self.last_alert = {}

    def puede_enviar(self, key: str) -> bool:
        now = time.time()
        last = self.last_alert.get(key, 0)
        if now - last >= self.cooldown:
            self.last_alert[key] = now
            return True
        return False


class EventProcessor:
    def __init__(self):
        self.rule_engine = RuleEngine()
        self.tracker = EventTracker(window_seconds=60, threshold=3)
        self.rate_limiter = AlertRateLimiter(cooldown_seconds=300)
        self._db_ok = False

    def iniciar(self):
        log_coloreado("INICIO", "Inicializando base de datos...")
        inicializar_db()
        self._db_ok = True
        log_coloreado("INICIO", "Procesador de eventos listo.")

    def procesar_por_lote(self) -> int:
        contador = 0
        for raw in leer_nuevos_eventos():
            try:
                self._procesar_unico(raw)
                contador += 1
            except Exception as e:
                logger.error("Error procesando evento: %s", e)
                log_coloreado("ERROR", str(e))
        return contador

    def _procesar_unico(self, raw: dict):
        fuente = raw.get("fuente", "")
        evento = raw.get("evento", {})

        if fuente == "WAZUH":
            normalizado = normalizar_evento_wazuh(evento)
            normalizado["id_registro"] = normalizado.get("id_regla")
        elif fuente == "SURICATA":
            normalizado = normalizar_evento_suricata(evento)
        else:
            return

        desc = normalizado.get("descripcion", "")
        log_coloreado("DEBUG", f"Evento: {fuente} | {desc[:80]}")

        # Reglas locales
        resultado_reglas = self.rule_engine.analizar(normalizado)
        riesgo = resultado_reglas.get("riesgo", "BAJO")
        log_coloreado("INFO", f"  Riesgo: {riesgo} | {resultado_reglas.get('ataque')}")

        # Patrones: solo subir riesgo si ya era MEDIO o ALTO
        es_patron = self.tracker.track(normalizado, resultado_reglas)
        if es_patron and riesgo in ("MEDIO", "ALTO"):
            resultado_reglas["riesgo"] = "ALTO"
            resultado_reglas["ataque"] = f"{resultado_reglas.get('ataque')} (+3 repetidos)"

        riesgo_final = resultado_reglas.get("riesgo", riesgo)

        # IA solo si ALTO o CRITICO
        resultado_ia = {
            "modelo": "N/A",
            "resumen": "",
            "severidad": riesgo_final,
            "recomendacion": resultado_reglas.get("recomendacion", ""),
            "tecnicas_mitre": [],
            "falso_positivo": False,
        }

        if self._debe_notificar(riesgo_final):
            log_coloreado("INFO", "  -> Consultando IA...")
            resultado_ia = analizar_evento(normalizado, resultado_reglas)
            log_coloreado("INFO", f"  IA: {resultado_ia.get('resumen', '')[:100]}")

        # Guardar siempre en DB
        if self._db_ok:
            guardar_evento(normalizado, resultado_reglas, resultado_ia)

        # Telegram con rate limit: 1 alerta igual cada 5 min max
        if self._debe_notificar(riesgo_final):
ip = normalizado.get("ip_origen", normalizado.get("agente_ip", normalizado.get("raw_log", "")))
            alert_key = f"{resultado_reglas.get('ataque','')}|{ip}"
            if self.rate_limiter.puede_enviar(alert_key):
                enviar_alerta(normalizado, resultado_reglas, resultado_ia)

    def _debe_notificar(self, riesgo: str) -> bool:
        return RISK_LEVELS.get(riesgo.upper(), 0) >= RISK_LEVELS.get(ALERT_MIN_RISK.upper(), 2)