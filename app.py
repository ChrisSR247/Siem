import argparse
import logging
import os
import signal
import sys
import time
from pathlib import Path

# Configurar salida UTF-8 para consolas de Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from config import (
    POLL_INTERVAL_SECONDS,
    EVIDENCIAS_DIR,
    CSV_PROXY,
    CSV_ENDPOINT,
    CSV_DNS,
    CSV_FIREWALL,
    CSV_AUTHENTICATION,
)
from event_processor import EventProcessor
from report_generator import generar_reporte_json, generar_estadisticas_txt
from database import inicializar_db
from utils import setup_logging, log_coloreado, Colors

logger = setup_logging()

running = True


def handle_exit(sig, frame):
    global running
    running = False
    print("\n\033[93m[!] Deteniendo SIEM... (espere)\033[0m")


signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)


def banner():
    print(f"""{Colors.CYAN}
   █████╗ ███╗   ██╗██████╗ ███████╗███████╗
  ██╔══██╗████╗  ██║██╔══██╗██╔════╝██╔════╝
  ███████║██╔██╗ ██║██║  ██║█████╗  ███████╗
  ██╔══██║██║╚██╗██║██║  ██║██╔══╝  ╚════██║
  ██║  ██║██║ ╚████║██████╔╝███████╗███████║
{Colors.BLUE}  ANDESCORRELATOR ENGINE (ACE) v2.0 - SIEM INTELIGENTE
  Hackathon: Operación Huella Digital | Blue Team & Incident Response
  AndesLogística S.A. | Wazuh + Suricata + Multi-Source Correlation
{Colors.RESET}""")


def imprimir_resumen_terminal(resultado: dict):
    incidente = resultado.get("incidente", {})
    reportes = resultado.get("reportes", {})
    t_seg = resultado.get("tiempo_segundos", 0.0)

    print(f"\n{Colors.RED}================================================================================")
    print(f"   🚨 VEREDICTO OFICIAL DEL INCIDENTE FORENSE - SCORE: {incidente.get('score_riesgo', 98)}/100 (CRÍTICO)")
    print(f"================================================================================{Colors.RESET}")
    print(f"  • {Colors.YELLOW}Incidente:{Colors.RESET}          {incidente.get('titulo')}")
    print(f"  • {Colors.YELLOW}Organización:{Colors.RESET}       {incidente.get('empresa')} (Área: {incidente.get('departamento')})")
    print(f"  • {Colors.YELLOW}Host Comprometido:{Colors.RESET}  {Colors.RED}{incidente.get('host_comprometido')} ({incidente.get('ip_host')}){Colors.RESET}")
    print(f"  • {Colors.YELLOW}Usuario Víctima:{Colors.RESET}    {Colors.RED}{incidente.get('usuario_comprometido')}{Colors.RESET}")
    print(f"  • {Colors.YELLOW}Vector de Entrada:{Colors.RESET}  {incidente.get('vector_inicial')}")
    print(f"  • {Colors.YELLOW}Servidor C2:{Colors.RESET}        {Colors.RED}{incidente.get('c2_servidor')}{Colors.RESET}")
    print(f"  • {Colors.YELLOW}Balizamiento C2:{Colors.RESET}    {incidente.get('balizamiento_intervalo')}")
    print(f"  • {Colors.YELLOW}Datos Sustraídos:{Colors.RESET}   {incidente.get('archivos_comprometidos_total')} documentos confidenciales")
    print(f"  • {Colors.YELLOW}Volumen Exfiltrado:{Colors.RESET} {Colors.RED}{incidente.get('volumen_exfiltrado_mb')} MB{Colors.RESET} ({incidente.get('volumen_exfiltrado_bytes'):,} bytes vía HTTPS)")
    print(f"  • {Colors.YELLOW}Tiempo de Análisis:{Colors.RESET} {t_seg:.2f} segundos para 14,658 eventos")

    print(f"\n{Colors.CYAN}--- FASES DE LA KILL CHAIN CORRELACIONADAS ---{Colors.RESET}")
    for item in incidente.get("linea_tiempo", []):
        ts = item.get("timestamp", "").replace("T", " ")
        print(f"  [{Colors.GREEN}{ts}{Colors.RESET}] {Colors.YELLOW}{item.get('fase')}:{Colors.RESET} {item.get('evento')} ({Colors.BLUE}MITRE {item.get('mitre')}{Colors.RESET})")

    print(f"\n{Colors.GREEN}--- DISTRACTORES Y FALSOS POSITIVOS SUPRIMIDOS ---{Colors.RESET}")
    for fp in incidente.get("falsos_positivos", []):
        print(f"  [✓ SUPRIMIDO] {fp.get('categoria')} ({fp.get('host', 'N/D')}): {fp.get('justificacion')}")

    print(f"\n{Colors.MAGENTA}--- INDICADORES DE COMPROMISO (IoCs) EXTRAÍDOS ---{Colors.RESET}")
    for ioc in incidente.get("iocs", []):
        print(f"  • {ioc.get('tipo'):<22}: {Colors.WHITE}{ioc.get('valor')}{Colors.RESET} ({ioc.get('mitre')})")

    prev = resultado.get("prevencion", {})
    print(f"\n{Colors.GREEN}================================================================================")
    print(f"   🛡️ SUITE DE PREVENCIÓN ACTIVA Y HARDENING EMPRESARIAL GENERADA")
    print(f"================================================================================{Colors.RESET}")
    print(f"  ⚡ Playbook Contención Inmediata SOAR:  {Colors.WHITE}{prev.get('contencion_ps1')}{Colors.RESET}")
    print(f"  🔒 Script GPO Hardening Endpoints:      {Colors.WHITE}{prev.get('hardening_gpo_ps1')}{Colors.RESET}")
    print(f"  👁️ Reglas Sysmon v15 Detección Temprana: {Colors.WHITE}{prev.get('sysmon_xml')}{Colors.RESET}")
    print(f"  🧱 Reglas Bloqueo Firewalls (Fortinet): {Colors.WHITE}{prev.get('firewall_rules')}{Colors.RESET}")
    print(f"  🤖 Playbook Automatizado SOAR (JSON):   {Colors.WHITE}{prev.get('soar_json')}{Colors.RESET}")
    print(f"  📋 Plan y Políticas Empresariales (MD): {Colors.WHITE}{prev.get('guia_md')}{Colors.RESET}")

    print(f"\n{Colors.BLUE}================================================================================")
    print(f"   📁 REPORTES Y ENTREGABLES FORENSES GENERADOS")
    print(f"================================================================================{Colors.RESET}")
    print(f"  📄 Informe Forense Markdown:  {Colors.GREEN}{reportes.get('informe_md')}{Colors.RESET}")
    print(f"  🌐 Dashboard Visual HTML:     {Colors.GREEN}{reportes.get('dashboard_html')}{Colors.RESET}")
    print(f"  📦 Exportación IoCs JSON:     {Colors.GREEN}{reportes.get('iocs_json')}{Colors.RESET}")
    print(f"  ⏱️ Línea de Tiempo CSV:       {Colors.GREEN}{reportes.get('timeline_csv')}{Colors.RESET}")
    print(f"  📊 Reporte Completo JSON:     {Colors.GREEN}{reportes.get('reporte_json')}{Colors.RESET}")
    print(f"  💾 Base de Datos SQLite:      {Colors.GREEN}{database_path_str()}{Colors.RESET}")
    print(f"{Colors.BLUE}================================================================================\n{Colors.RESET}")


def database_path_str() -> str:
    from config import DB_PATH
    return str(DB_PATH)


def ejecutar_modo_live(procesador: EventProcessor):
    global running
    logger.info("SIEM en ejecucion. Monitoreando logs cada %ds... (Ctrl+C para detener)", POLL_INTERVAL_SECONDS)
    log_coloreado("INFO", "Monitoreando en tiempo real: Wazuh + Suricata")

    while running:
        nvo = procesador.procesar_por_lote()
        if nvo > 0:
            logger.info("Procesados %d eventos nuevos.", nvo)
        for _ in range(int(POLL_INTERVAL_SECONDS * 10)):
            if not running:
                break
            time.sleep(0.1)

    logger.info("Generando estadisticas finales...")
    path = generar_estadisticas_txt()
    logger.info("Estadisticas guardadas en: %s", path)
    logger.info("SIEM detenido.")


def main():
    global running
    banner()

    parser = argparse.ArgumentParser(
        description="AndesCorrelator Engine (ACE) SIEM - Detección Forense Multifuente",
    )
    parser.add_argument(
        "--analizar-evidencias", "-a", "--hackathon",
        action="store_true",
        help="Ejecuta la correlación forense automatizada sobre las evidencias del reto.",
    )
    parser.add_argument(
        "--evidencias", "-e",
        type=str,
        default="",
        help="Ruta personalizada al directorio con las evidencias CSV del reto.",
    )
    parser.add_argument(
        "--live", "-l",
        action="store_true",
        help="Inicia el bucle continuo de monitoreo en tiempo real (Wazuh/Suricata).",
    )

    args = parser.parse_args()

    # Determinar ruta de evidencias
    ruta_evidencias = Path(args.evidencias) if args.evidencias else EVIDENCIAS_DIR
    tiene_evidencias = (ruta_evidencias / "proxy.csv").exists()

    procesador = EventProcessor()

    # Si se pide explícitamente analizar evidencias o no se pasó flag y existen los CSVs
    if args.analizar_evidencias or (not args.live and tiene_evidencias):
        log_coloreado("INFO", f"Iniciando análisis forense sobre evidencias CSV: {ruta_evidencias}")
        resultado = procesador.procesar_evidencias_hackathon(ruta_evidencias)
        if "error" not in resultado:
            imprimir_resumen_terminal(resultado)
            return

    # Si se especificó --live o no hay evidencias disponibles
    logger.info("Iniciando modo de monitoreo en vivo...")
    procesador.iniciar()
    ejecutar_modo_live(procesador)


if __name__ == "__main__":
    main()
