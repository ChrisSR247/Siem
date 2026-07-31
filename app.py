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


def banner():
    print(""""
  _____ _____ _______ __  __
 / ____|_   _|__   __|  \\/  |
| (___   | |    | |  | \\  / |
 \\___ \\  | |    | |  | |\\/| |
 ____) |_| |_   | |  | |  | |
|_____/|_____|  |_|  |_|  |_|

  SIEM Inteligente v1.0
  Wazuh + Suricata + NVIDIA AI
""")


def main():
    banner()
    logger.info("Iniciando SIEM Inteligente...")

    inicializar_db()
    logger.info("Base de datos lista.")

    procesador = EventProcessor()
    procesador.iniciar()

    running = True

    def señal_handler(sig, frame):
        nonlocal running
        running = False
        print("\n\033[93m[!] Deteniendo SIEM...\033[0m")

    signal.signal(signal.SIGINT, señal_handler)
    signal.signal(signal.SIGTERM, señal_handler)

    logger.info("SIEM en ejecución. Monitoreando logs cada %ds... (Ctrl+C para detener)", POLL_INTERVAL_SECONDS)
    log_coloreado("INFORME", f"Monitoreando:\n  - Wazuh\\n  - Suricata")

    try:
        while running:
            nvo = procesador.procesar_por_lote()
            if nvo > 0:
                logger.info("Procesados %d eventos nuevos.", nvo)
            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Generando estadisticas finales...")
        path = generar_estadisticas_txt()
        logger.info("Estadisticas guardadas en: %s", path)
        logger.info("SIEM detenido.")


if __name__ == "__main__":
    main()