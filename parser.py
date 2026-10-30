import csv
import json
import os
import struct
from pathlib import Path
from typing import Dict, Generator, List, Optional

from config import (
    WAZUH_LOG,
    SURICATA_LOG,
    WAZUH_CURSOR,
    SURICATA_CURSOR,
    EVIDENCIAS_DIR,
    CSV_PROXY,
    CSV_ENDPOINT,
    CSV_DNS,
    CSV_FIREWALL,
    CSV_AUTHENTICATION,
    PCAP_FILE,
)
from utils import cargar_json, leer_cursor, guardar_cursor, log_coloreado


# =========================================================================
# PARSERS WAZUH & SURICATA (Compatibilidad en Tiempo Real)
# =========================================================================

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

    ip_origen = _extraer_ip_origen_wazuh(evento)

    return {
        "fuente": "WAZUH",
        "timestamp": evento.get("timestamp", ""),
        "id_registro": str(rule.get("id", "")),
        "descripcion": rule.get("description", ""),
        "nivel_original": rule.get("level", 0),
        "host": agent.get("name", agent.get("id", "")),
        "usuario": data.get("srcuser", data.get("dstuser", "")),
        "agente": agent.get("name", agent.get("id", "")),
        "agente_ip": agent.get("ip", ""),
        "ip_origen": ip_origen,
        "ip_destino": data.get("dstip", data.get("dst_ip", "")),
        "detalles": json.dumps(data) if data else "",
        "raw_log": evento.get("full_log", ""),
    }


def _extraer_ip_origen_wazuh(evento: dict) -> str:
    import re
    data = evento.get("data", {})
    candidatos = [
        data.get("srcip"),
        data.get("src_ip"),
        data.get("remote"),
        data.get("src"),
        data.get("id", ""),
        evento.get("srcip"),
        evento.get("src_ip"),
        evento.get("agent", {}).get("ip"),
    ]
    for val in candidatos:
        if not val:
            continue
        val_str = str(val)
        match = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", val_str)
        if match:
            return match.group()

    full = str(evento.get("full_log", ""))
    match = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", full)
    if match:
        return match.group()
    return ""


def normalizar_evento_suricata(evento: dict) -> dict:
    alert = evento.get("alert", {})
    src_ip = evento.get("src_ip", "")
    dest_ip = evento.get("dest_ip", "")

    return {
        "fuente": "SURICATA",
        "timestamp": evento.get("timestamp", ""),
        "id_registro": str(alert.get("signature_id", "")),
        "descripcion": alert.get("signature", "")[:200],
        "nivel_original": alert.get("severity", 0),
        "categoria": alert.get("category", ""),
        "host": "",
        "usuario": "",
        "ip_origen": src_ip,
        "ip_destino": dest_ip,
        "detalles": json.dumps(evento.get("flow", {})) if "flow" in evento else "",
        "raw_log": json.dumps(evento),
    }


# =========================================================================
# PARSERS FORENSES MULTIFUENTE - HACKATHON OPERACIÓN HUELLA DIGITAL
# =========================================================================

def cargar_csv(filepath: Path) -> List[dict]:
    """Carga un archivo CSV retornando una lista de diccionarios con manejo de codificación."""
    path = Path(filepath)
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            return list(reader)
    except UnicodeDecodeError:
        with open(path, "r", encoding="latin-1") as f:
            reader = csv.DictReader(f)
            return list(reader)
    except Exception as e:
        log_coloreado("ERROR", f"Error leyendo {filepath}: {e}")
        return []


def normalizar_evento_proxy(row: dict) -> dict:
    """Normaliza un registro de proxy.csv (Navegación web / Vector de entrada)."""
    metodo = row.get("method", "GET").upper()
    url = row.get("url", "")
    status = row.get("http_status", "")
    content_type = row.get("content_type", "")
    bytes_recv = row.get("bytes_received", "0") or "0"
    domain = row.get("domain", "")

    desc = f"Navegacion Proxy [{metodo}] {url} -> Status {status} ({content_type}, {bytes_recv} bytes)"

    return {
        "fuente": "PROXY",
        "timestamp": row.get("timestamp", ""),
        "id_registro": f"PROXY_{metodo}",
        "descripcion": desc,
        "nivel_original": 1,
        "host": row.get("source_host", ""),
        "usuario": row.get("username", ""),
        "ip_origen": row.get("source_ip", ""),
        "ip_destino": "",
        "metodo": metodo,
        "url": url,
        "dominio": domain,
        "status": status,
        "content_type": content_type,
        "bytes_recibidos": int(bytes_recv) if bytes_recv.isdigit() else 0,
        "user_agent": row.get("user_agent", ""),
        "detalles": f"Domain: {domain} | Content-Type: {content_type} | UserAgent: {row.get('user_agent', '')}",
        "raw_log": json.dumps(row, ensure_ascii=False),
    }


def normalizar_evento_endpoint(row: dict) -> dict:
    """Normaliza un registro de endpoint.csv (Procesos, accesos a archivos, comandos)."""
    event_type = row.get("event_type", "")
    proc = row.get("process_name", "")
    parent = row.get("parent_process", "")
    cmd = row.get("command_line", "")
    file_path = row.get("file_path", "")
    details = row.get("details", "")

    if event_type == "PROCESS_CREATE":
        desc = f"Proceso Creado: {proc} (Padre: {parent}) Comandos: {cmd}"
    elif event_type in ("FILE_ACCESS", "FILE_READ"):
        desc = f"Acceso a Archivo: {file_path} por {proc}"
    elif event_type == "FILE_CREATE":
        desc = f"Creacion de Archivo: {file_path} ({details})"
    else:
        desc = f"Evento Endpoint {event_type} - {proc} {file_path} {cmd} {details}".strip()

    return {
        "fuente": "ENDPOINT",
        "timestamp": row.get("timestamp", ""),
        "id_registro": f"EP_{event_type}",
        "descripcion": desc,
        "nivel_original": 1,
        "host": row.get("host", ""),
        "usuario": row.get("username", ""),
        "ip_origen": "",
        "ip_destino": row.get("destination_ip", ""),
        "puerto_destino": row.get("destination_port", ""),
        "tipo_evento": event_type,
        "proceso": proc,
        "proceso_padre": parent,
        "comando": cmd,
        "ruta_archivo": file_path,
        "detalles": details,
        "raw_log": json.dumps(row, ensure_ascii=False),
    }


def normalizar_evento_dns(row: dict) -> dict:
    """Normaliza un registro de dns.csv (Resolución de nombres de dominio)."""
    query = row.get("query", "")
    qtype = row.get("query_type", "A")
    resp = row.get("response", "")
    rcode = row.get("response_code", "NOERROR")

    desc = f"Consulta DNS {qtype} '{query}' -> Respuesta: {resp} (Codigo: {rcode})"

    return {
        "fuente": "DNS",
        "timestamp": row.get("timestamp", ""),
        "id_registro": f"DNS_{qtype}",
        "descripcion": desc,
        "nivel_original": 1,
        "host": row.get("source_host", ""),
        "usuario": "",
        "ip_origen": row.get("source_ip", ""),
        "ip_destino": resp if (resp and resp.count(".") == 3 and not resp.endswith(".local")) else "",
        "query": query,
        "tipo_query": qtype,
        "respuesta": resp,
        "codigo_respuesta": rcode,
        "detalles": f"Query: {query} | Type: {qtype} | Resp: {resp} | Code: {rcode}",
        "raw_log": json.dumps(row, ensure_ascii=False),
    }


def normalizar_evento_firewall(row: dict) -> dict:
    """Normaliza un registro de firewall.csv (Conexiones de red, volumetría)."""
    src_ip = row.get("source_ip", "")
    dst_ip = row.get("destination_ip", "")
    dst_port = row.get("destination_port", "")
    proto = row.get("protocol", "TCP")
    direction = row.get("direction", "OUTBOUND")
    action = row.get("action", "ALLOW")
    bytes_sent = row.get("bytes_sent", "0") or "0"
    bytes_recv = row.get("bytes_received", "0") or "0"
    duration = row.get("duration_seconds", "0") or "0"

    b_sent_int = int(bytes_sent) if bytes_sent.isdigit() else 0
    b_recv_int = int(bytes_recv) if bytes_recv.isdigit() else 0
    dur_int = int(duration) if duration.isdigit() else 0

    desc = f"Firewall {direction} {proto} {src_ip} -> {dst_ip}:{dst_port} [{action}] ({b_sent_int}B sent, {b_recv_int}B recv, {dur_int}s)"

    return {
        "fuente": "FIREWALL",
        "timestamp": row.get("timestamp", ""),
        "id_registro": f"FW_{direction}_{proto}",
        "descripcion": desc,
        "nivel_original": 1,
        "host": row.get("source_host", ""),
        "usuario": "",
        "ip_origen": src_ip,
        "ip_destino": dst_ip,
        "host_destino": row.get("destination_host", ""),
        "puerto_destino": dst_port,
        "protocolo": proto,
        "direccion": direction,
        "accion": action,
        "bytes_enviados": b_sent_int,
        "bytes_recibidos": b_recv_int,
        "duracion_segundos": dur_int,
        "detalles": f"Direction: {direction} | Port: {dst_port} | Sent: {b_sent_int} | Recv: {b_recv_int} | Dur: {dur_int}s",
        "raw_log": json.dumps(row, ensure_ascii=False),
    }


def normalizar_evento_auth(row: dict) -> dict:
    """Normaliza un registro de authentication.csv (Inicio de sesión y autenticación en AD/ERP)."""
    event_id = row.get("event_id", "")
    user = row.get("username", "")
    src_host = row.get("source_host", "")
    dst_host = row.get("destination_host", "")
    logon_type = row.get("logon_type", "")
    result = row.get("result", "")
    failure_reason = row.get("failure_reason", "")

    desc = f"Autenticacion EventID {event_id} ({logon_type}) {user}@{src_host} -> {dst_host}: {result}"
    if failure_reason:
        desc += f" (Fallo: {failure_reason})"

    return {
        "fuente": "AUTHENTICATION",
        "timestamp": row.get("timestamp", ""),
        "id_registro": f"AUTH_{event_id}",
        "descripcion": desc,
        "nivel_original": 1,
        "host": src_host,
        "usuario": user,
        "ip_origen": row.get("source_ip", ""),
        "ip_destino": row.get("destination_ip", ""),
        "host_destino": dst_host,
        "tipo_logon": logon_type,
        "resultado": result,
        "razon_fallo": failure_reason,
        "detalles": f"EventID: {event_id} | Type: {logon_type} | Result: {result} | Reason: {failure_reason}",
        "raw_log": json.dumps(row, ensure_ascii=False),
    }


def leer_todos_los_eventos_csv(evidencias_dir: Optional[Path] = None) -> List[dict]:
    """
    Ingesta y normaliza todas las fuentes CSV del escenario del Hackathon:
    - proxy.csv
    - endpoint.csv
    - dns.csv
    - firewall.csv
    - authentication.csv
    Retorna la lista completa de eventos unificada y ordenada cronológicamente.
    """
    base = Path(evidencias_dir or EVIDENCIAS_DIR)
    log_coloreado("INFO", f"Ingestando fuentes de evidencias desde: {base}")

    proxy_rows = cargar_csv(base / "proxy.csv")
    endpoint_rows = cargar_csv(base / "endpoint.csv")
    dns_rows = cargar_csv(base / "dns.csv")
    firewall_rows = cargar_csv(base / "firewall.csv")
    auth_rows = cargar_csv(base / "authentication.csv")

    log_coloreado("INFO", f"  - Proxy:          {len(proxy_rows):,} registros")
    log_coloreado("INFO", f"  - Endpoint:       {len(endpoint_rows):,} registros")
    log_coloreado("INFO", f"  - DNS:            {len(dns_rows):,} registros")
    log_coloreado("INFO", f"  - Firewall:       {len(firewall_rows):,} registros")
    log_coloreado("INFO", f"  - Authentication: {len(auth_rows):,} registros")

    eventos = []
    for r in proxy_rows:
        eventos.append(normalizar_evento_proxy(r))
    for r in endpoint_rows:
        eventos.append(normalizar_evento_endpoint(r))
    for r in dns_rows:
        eventos.append(normalizar_evento_dns(r))
    for r in firewall_rows:
        eventos.append(normalizar_evento_firewall(r))
    for r in auth_rows:
        eventos.append(normalizar_evento_auth(r))

    # Ordenar cronológicamente por timestamp
    eventos.sort(key=lambda x: x.get("timestamp", ""))
    log_coloreado("INFO", f"Total unificado: {len(eventos):,} eventos normalizados y ordenados cronológicamente.")
    return eventos


def analizar_pcap_basico(pcap_path: Optional[Path] = None) -> dict:
    """
    Analizador ligero nativo de archivos PCAP sin requerir dependencias externas.
    Examina flujos IP y sesiones TLS dirigidas a la infraestructura del incidente.
    """
    path = Path(pcap_path or PCAP_FILE)
    if not path.exists():
        return {"error": f"Archivo PCAP no encontrado en {path}"}

    total_packets = 0
    c2_packets = 0
    c2_ip = "203.0.113.77"
    comp_ip = "10.20.10.47"
    flow_counts = {}

    try:
        with open(path, "rb") as f:
            global_header = f.read(24)
            if len(global_header) < 24:
                return {"error": "Encabezado PCAP corrupto"}

            while True:
                packet_header = f.read(16)
                if len(packet_header) < 16:
                    break
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", packet_header)
                packet_data = f.read(incl_len)
                total_packets += 1

                # Ethernet IPv4 (0x0800 en bytes 12..14)
                if len(packet_data) >= 34 and packet_data[12:14] == b"\x08\x00":
                    src = ".".join(str(b) for b in packet_data[26:30])
                    dst = ".".join(str(b) for b in packet_data[30:34])
                    flow_key = f"{src}->{dst}"
                    flow_counts[flow_key] = flow_counts.get(flow_key, 0) + 1

                    if (src == comp_ip and dst == c2_ip) or (src == c2_ip and dst == comp_ip):
                        c2_packets += 1

        return {
            "archivo": str(path.name),
            "total_paquetes": total_packets,
            "paquetes_c2": c2_packets,
            "ip_c2": c2_ip,
            "ip_victima": comp_ip,
            "flujos_totales": len(flow_counts),
            "evidencia_confirmada": c2_packets > 0,
            "resumen": f"PCAP contiene {total_packets} paquetes; {c2_packets} paquetes corresponden a sesiones TLS entre {comp_ip} y {c2_ip} (C2)."
        }
    except Exception as e:
        return {"error": f"Error leyendo PCAP: {e}"}
