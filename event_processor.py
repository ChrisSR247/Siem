import json
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


class EventProcessor:
    def __init__(self):
        self.rule_engine = RuleEngine()
        self._db_ok = False

    def iniciar(self):
        log_coloreado("INICIO", "Inicializando base de datos...")
        inicializar_db()
        self._db_ok = True
        log_coloreado("INICIO", "Modelo de procesamiento de eventos listo.")

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

        # 3. IA si riesgo >= umbral
        resultado_ia = {
            "modelo": "N/A",
            "resumen": "No analizado por IA (riesgo bajo)",
            "severidad": riesgo,
            "recomendacion": resultado_reglas.get("recomendacion", ""),
            "tecnicas_mitre": [],
            "falso_positivo": False,
        }

        if self._debe_consultar_ia(riesgo):
            log_coloreado("INFO", "  Consultando IA NVIDIA...")
            resultado_ia = analizar_evento(normalizado, resultado_reglas)
            log_coloreado("INFO", f"  IA respondio: {resultado_ia.get('resumen', '')[:100]}")
        else:
            log_coloreado("INFO", f"  Riesgo {riesgo} < {ALERT_MIN_RISK}, se omite IA.")

        # 4. Guardar en DB
        if self._db_ok:
            guardar_evento(normalizado, resultado_reglas, resultado_ia)

        # 5. Enviar Telegram
        enviar_alerta(normalizado, resultado_reglas, resultado_ia)

    def _debe_consultar_ia(self, riesgo: str) -> bool:
        return RISK_LEVELS.get(riesgo.upper(), 0) >= RISK_LEVELS.get(ALERT_MIN_RISK.upper(), 2)