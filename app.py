import time
import signal
import sys
import logging

from config import POLL_INTERVAL_SECONDS
from event_processor import EventProcessor
from report_generator import generar_reporte_json, generar_estadisticas_txt
from database import inicializar_db
from utils import setup_logging, log_coloreado

logger = setup_logging()

running = True


def handle_exit(sig, frame):
    global running
    running = False
    print("\n\033[93m[!] Deteniendo SIEM... (espere)\033[0m")

signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)


def banner():
    print("""
   ____ ____  _   _ ____   ___    __
  / ___|  _ \\| | | |  _ \\ / _ \\  / /
 | |  _| |_) | | | | |_) | | | |/ /
 | |_| |  _ <| |_| |  __/| |_| |_|
  \\____|_| \\_\\\\___/|_|    \\___/(_)

   SIEM Inteligente - Grupo 6
   Wazuh + Suricata + NVIDIA AI
""")


def main():
    global running
    running = True

    banner()
    logger.info("Iniciando SIEM Inteligente...")

    inicializar_db()
    logger.info("Base de datos lista.")

    procesador = EventProcessor()
    procesador.iniciar()

    logger.info("SIEM en ejecucion. Monitoreando logs cada %ds... (Ctrl+C para detener)", POLL_INTERVAL_SECONDS)
    log_coloreado("INFO", "Monitoreando: Wazuh + Suricata")

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


if __name__ == "__main__":
    main()