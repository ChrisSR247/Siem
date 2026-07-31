import json
from pathlib import Path
from typing import Dict, Generator, Optional

from config import WAZUH_LOG, SURICATA_LOG, WAZUH_CURSOR, SURICATA_CURSOR
from utils import cargar_json, leer_cursor, guardar_cursor


def leer_wazuh_como_eventos() -> Generator[dict, None, None]:
    wazuh_path = Path(WAZUH_LOG)
    if not wazuh_path.exists():
        return
    try:
        with open(wazuh_path, "r", encoding="utf-8") as f:
            for linea in f:
                linea = linea.strip()
                if not linea:
                    continue
                try:
                    evento = json.loads(linea)
                    yield evento
                except json.JSONDecodeError:
                    continue
    except OSError:
        return


def leer_suricata_como_eventos() -> Generator[dict, None, None]:
    suricata_path = Path(SURICATA_LOG)
    if not suricata_path.exists():
        return
    try:
        with open(suricata_path, "r", encoding="utf-8") as f:
            for linea in f:
                linea = linea.strip()
                if not linea:
                    continue
                try:
                    evento = json.loads(linea)
                    if evento.get("event_type") == "alert":
                        yield evento
                except json.JSONDecodeError:
                    continue
    except OSError:
        return


def leer_ultima_linea_wazuh() -> Optional[dict]:
    wazuh_path = Path(WAZUH_LOG)
    if not wazuh_path.exists():
        return None
    cursor = leer_cursor(WAZUH_CURSOR)
    eventos = list(leer_wazuh_como_eventos())
    if cursor >= len(eventos):
        return None
    ultimo = eventos[-1]
    guardar_cursor(WAZUH_CURSOR, len(eventos))
    return ultimo


def leer_ultima_linea_suricata() -> Optional[dict]:
    suricata_path = Path(SURICATA_LOG)
    if not suricata_path.exists():
        return None
    cursor = leer_cursor(SURICATA_CURSOR)
    eventos = list(leer_suricata_como_eventos())
    if cursor >= len(eventos):
        return None
    ultimo = eventos[-1]
    guardar_cursor(SURICATA_CURSOR, len(eventos))
    return ultimo


def leer_nuevos_eventos() -> Generator[dict, None, None]:
    wazuh_path = Path(WAZUH_LOG)
    suricata_path = Path(SURICATA_LOG)

    wazuh_cursor = leer_cursor(WAZUH_CURSOR)
    suricata_cursor = leer_cursor(SURICATA_CURSOR)

    # Wazuh
    if wazuh_path.exists():
        try:
            with open(wazuh_path, "r", encoding="utf-8") as f:
                lineas = f.readlines()
            for i in range(wazuh_cursor, len(lineas)):
                linea = lineas[i].strip()
                if not linea:
                    continue
                try:
                    evento = json.loads(linea)
                    yield {"fuente": "WAZUH", "evento": evento}
                except json.JSONDecodeError:
                    continue
            guardar_cursor(WAZUH_CURSOR, len(lineas))
        except OSError:
            pass

    # Suricata
    if suricata_path.exists():
        try:
            with open(suricata_path, "r", encoding="utf-8") as f:
                lineas = f.readlines()
            for idx in range(suricata_cursor, len(lineas)):
                linea = lineas[idx].strip()
                if not linea:
                    continue
                try:
                    evento = json.loads(linea)
                    if evento.get("event_type") == "alert":
                        yield {"fuente": "SURICATA", "evento": evento}
                except json.JSONDecodeError:
                    continue
            guardar_cursor(SURICATA_CURSOR, len(lineas))
        except OSError:
            pass


def normalizar_evento_wazuh(evento: dict) -> dict:
    rule = evento.get("rule", {})
    agent = evento.get("agent", {})
    data = evento.get("data", {})

    return {
        "fuente": "WAZUH",
        "timestamp": evento.get("timestamp", ""),
        "id_regla": str(rule.get("id", "")),
        "descripcion": rule.get("description", ""),
        "nivel_original": rule.get("level", 0),
        "agente": agent.get("name", agent.get("id", "")),
        "agente_ip": agent.get("ip", ""),
        "raw_log": data.get("srcip", data.get("dstip", "")),
    }


def normalizar_evento_suricata(evento: dict) -> dict:

    alert = evento.get("alert", {})
    src_ip = evento.get("src_ip", "")
    dest_ip = evento.get("dest_ip", "")
    flow = evento.get("flow", {})

    return {
        "fuente": "SURICATA",
        "timestamp": evento.get("timestamp", ""),
        "id_registro": str(alert.get("signature_id", "")),
        "descripcion": alert.get("signature", "")[:200],
        "nivel_original": alert.get("severity", 0),
        "categoria": alert.get("category", ""),
        "ip_origen": src_ip,
        "ip_destino": dest_ip,
    }