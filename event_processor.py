import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional

from parser import (
    normalizar_evento_wazuh,
    normalizar_evento_suricata,
    leer_nuevos_eventos,
    leer_todos_los_eventos_csv,
    analizar_pcap_basico,
)
from rule_engine import RuleEngine
from correlator import ThreatCorrelator
from ai_analyzer import analizar_evento, analizar_incidente_forense
from database import (
    guardar_evento,
    guardar_lote_eventos,
    guardar_incidente_correlacionado,
    inicializar_db,
)
from report_generator import (
    generar_informe_forense_md,
    generar_dashboard_html,
    generar_iocs_json,
    generar_linea_tiempo_csv,
    generar_reporte_json,
)
from telegram_bot import enviar_alerta
from config import ALERT_MIN_RISK, RISK_LEVELS, POLL_INTERVAL_SECONDS, EVIDENCIAS_DIR
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
        log_coloreado("INFO", "Inicializando base de datos del SIEM...")
        inicializar_db()
        self._db_ok = True
        log_coloreado("INFO", "Procesador de eventos listo.")

    def procesar_evidencias_hackathon(self, evidencias_dir: Optional[Path] = None) -> dict:
        """
        Procesa de principio a fin el lote de evidencias del Hackathon (Operación Huella Digital).
        1. Ingesta y normaliza los 5 CSVs.
        2. Analiza los flujos de tráfico en el archivo PCAP.
        3. Aplica el motor de correlación multifuente ThreatCorrelator.
        4. Realiza síntesis pericial con el analizador de incidentes (IA/Heurística local).
        5. Persiste eventos, incidentes, IoCs y línea de tiempo en SQLite.
        6. Genera los informes ejecutivos (Markdown, Dashboard HTML, JSON, CSV).
        """
        self.iniciar()
        t_inicio = time.time()

        base_dir = Path(evidencias_dir or EVIDENCIAS_DIR)
        log_coloreado("INFO", f"Iniciando análisis forense sobre: {base_dir}")

        # 1. Cargar y ordenar eventos de todos los CSVs
        eventos = leer_todos_los_eventos_csv(base_dir)
        if not eventos:
            log_coloreado("ERROR", "No se encontraron eventos CSV para analizar.")
            return {"error": "Sin eventos"}

        # 2. Analizar PCAP
        log_coloreado("INFO", "Analizando paquetes y flujos en captura PCAP...")
        pcap_info = analizar_pcap_basico(base_dir / "suspicious-traffic.pcap")
        if pcap_info.get("evidencia_confirmada"):
            log_coloreado("INFO", f"  PCAP: {pcap_info.get('resumen')}")

        # 3. Correlación Multifuente
        correlador = ThreatCorrelator(eventos, pcap_info)
        incidente = correlador.ejecutar_analisis_completo()

        # 4. Síntesis y Evaluación de IA
        log_coloreado("INFO", "Generando análisis de impacto, contención y recomendaciones...")
        analisis_ia = analizar_incidente_forense(incidente)
        incidente["analisis_ia"] = analisis_ia
        incidente["resumen_ia"] = analisis_ia.get("resumen_ejecutivo", "")

        # 5. Persistencia en Base de Datos
        log_coloreado("INFO", "Almacenando evidencias e incidente correlacionado en base de datos SQLite...")
        guardar_lote_eventos(eventos)
        guardar_incidente_correlacionado(incidente, analisis_ia.get("resumen_ejecutivo", ""))

        # 6. Generar Reportes y Entregables del Hackathon
        log_coloreado("INFO", "Generando informes forenses y dashboards ejecutivos...")
        path_md = generar_informe_forense_md(incidente, analisis_ia)
        path_html = generar_dashboard_html(incidente, analisis_ia)
        path_iocs = generar_iocs_json(incidente)
        path_timeline = generar_linea_tiempo_csv(incidente)
        path_report_json = generar_reporte_json(f"incidente_{incidente['incidente_id']}.json")

        # 7. Generar Suite de Prevención Activa y Hardening Empresarial
        log_coloreado("INFO", "Construyendo suite de prevención, contención SOAR y hardening empresarial...")
        from preventer import EnterprisePreventer
        preventer = EnterprisePreventer(incidente)
        suite_prevencion = preventer.generar_suite_prevencion_completa()

        t_total = time.time() - t_inicio
        log_coloreado("INFO", f"Análisis forense y generación de defensas completados en {t_total:.2f} segundos.")

        # Notificar por Telegram si está configurado
        try:
            ev_dummy = {
                "fuente": "CORRELATOR_ACE",
                "timestamp": ahora_iso(),
                "ip_origen": incidente.get("ip_host", ""),
                "ip_destino": "203.0.113.77",
                "agente": incidente.get("host_comprometido", ""),
                "categoria": "EXFILTRACION_CRITICA",
            }
            reglas_dummy = {
                "ataque": incidente.get("titulo", ""),
                "riesgo": "CRITICO",
                "mitre": "T1566 / T1059 / T1071 / T1039 / T1041",
                "recomendacion": "Aislar FIN-PC07 y revocar credenciales de dtorres inmediatamente.",
            }
            ia_dummy = {
                "modelo": analisis_ia.get("modelo", ""),
                "resumen": analisis_ia.get("resumen_ejecutivo", "")[:280],
                "severidad": "CRITICO",
            }
            enviar_alerta(ev_dummy, reglas_dummy, ia_dummy)
        except Exception as e:
            logger.debug("Notificación telegram opcional: %s", e)

        return {
            "incidente": incidente,
            "tiempo_segundos": t_total,
            "reportes": {
                "informe_md": path_md,
                "dashboard_html": path_html,
                "iocs_json": path_iocs,
                "timeline_csv": path_timeline,
                "reporte_json": path_report_json,
            },
            "prevencion": suite_prevencion,
        }

    def procesar_por_lote(self) -> int:
        """Modo de monitoreo continuo para Wazuh y Suricata."""
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

        resultado_reglas = self.rule_engine.analizar(normalizado)
        riesgo = resultado_reglas.get("riesgo", "BAJO")

        if RISK_LEVELS.get(riesgo, 0) >= RISK_LEVELS.get("MEDIO", 2):
            log_coloreado("DEBUG", f"Evento: {fuente} | {desc[:80]}")
            log_coloreado("INFO", f"  Riesgo: {riesgo} | {resultado_reglas.get('ataque')}")

        es_patron = self.tracker.track(normalizado, resultado_reglas)
        if es_patron and riesgo in ("MEDIO", "ALTO"):
            resultado_reglas["riesgo"] = "ALTO"
            resultado_reglas["ataque"] = f"{resultado_reglas.get('ataque')} (+3 repetidos)"

        riesgo_final = resultado_reglas.get("riesgo", riesgo)

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
            resumen_ia = resultado_ia.get("resumen", "").strip()
            if resumen_ia:
                log_coloreado("INFO", f"  IA: {resumen_ia[:100]}")
            else:
                log_coloreado("WARNING", "  IA: No disponible")

        if self._db_ok:
            guardar_evento(normalizado, resultado_reglas, resultado_ia)

        if self._debe_notificar(riesgo_final):
            ip = normalizado.get("ip_origen", normalizado.get("agente_ip", normalizado.get("raw_log", "")))
            alert_key = f"{resultado_reglas.get('ataque','')}|{ip}"
            if self.rate_limiter.puede_enviar(alert_key):
                enviar_alerta(normalizado, resultado_reglas, resultado_ia)

    def _debe_notificar(self, riesgo: str) -> bool:
        return RISK_LEVELS.get(riesgo.upper(), 0) >= RISK_LEVELS.get(ALERT_MIN_RISK.upper(), 2)
