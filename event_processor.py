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


class EventProcessor:
    def __init__(self):
        self.rule_engine = RuleEngine()
        self.tracker = EventTracker(window_seconds=60, threshold=3)
        self._db_ok = False

    def iniciar(self):
        log_coloreado("INICIO", "Inicializando base de datos...")
        inicializar_db()
        self._db_ok = True
        log_coloreado("INICIO", "Estado de procesamiento de eventos listo.")

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

        # 1. Normalizar
        if fuente == "WAZUH":
            normalizado = normalizar_evento_wazuh(evento)
            normalizado["id_registro"] = normalizado.get("id_regla")
        elif fuente == "SURICATA":
            normalizado = normalizar_evento_suricata(evento)
        else:
            return

        log_coloreado("DEBUG", f"Nuevo evento: {fuente} | {normalizado.get('descripcion', '')[:80]}")

        # 2. Reglas locales
        resultado_reglas = self.rule_engine.analizar(normalizado)
        riesgo = resultado_reglas.get("riesgo", "MEDIO")
        log_coloreado("INFO", f"  Riesgo local: {riesgo} | {resultado_reglas.get('ataque')} | MITRE: {resultado_reglas.get('mitre')}")

        # 3. Verificar patrones repetidos
        es_patron = self.tracker.track(normalizado, resultado_reglas)
        if es_patron:
            resultado_reglas["riesgo"] = "ALTO"
            resultado_reglas["ataque"] = f"{resultado_reglas.get('ataque')} (Patron: >=3 eventos)"

        riesgo_final = resultado_reglas.get("riesgo", riesgo)

        # 4. IA si riesgo-lo amerita
        resultado_ia = {
            "modelo": "N/A",
            "resumen": f"No analizado por IA (riesgo: {riesgo_final})",
            "severidad": riesgo_final,
            "recomendacion": resultado_reglas.get("recomendacion", ""),
            "tecnicas_mitre": [],
            "falso_positivo": False,
        }

        if self._debe_notificar(riesgo_final):
            log_coloreado("INFO", "  Consultando IA NVIDIA...")
            resultado_ia = analizar_evento(normalizado, resultado_reglas)
            log_coloreado("INFO", f"  IA respondio: {resultado_ia.get('resumen', '')[:100]}")
        else:
            log_coloreado("INFO", f"  Riesgo {riesgo_final} < {ALERT_MIN_RISK}, se omite IA y Telegram.")

        # 5. Guardar en DB
        if self._db_ok:
            guardar_evento(normalizado, resultado_reglas, resultado_ia)

    def _debe_notificar(self, riesgo: str) -> bool:
        return RISK_LEVELS.get(riesgo.upper(), 0) >= RISK_LEVELS.get(ALERT_MIN_RISK.upper(), 2)