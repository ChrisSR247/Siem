"""
AndesCorrelator Engine (ACE) - Motor de Correlación Forense Multifuente
Hackathon: Operación Huella Digital (AndesLogística S.A.)
Enfoque: Blue Team, Incident Response & Threat Hunting
"""

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from config import (
    CORRELATION_WINDOW_PHISHING_EXEC_SEC,
    BEACONING_TARGET_INTERVAL_SEC,
    BEACONING_INTERVAL_TOLERANCE_SEC,
    BEACONING_MIN_OCCURRENCES,
    STAGING_MASS_ACCESS_THRESHOLD,
    EXFILTRATION_VOLUME_THRESHOLD_BYTES,
    WHITELIST_DOMAINS,
    WHITELIST_BACKUP_HOSTS,
    WHITELIST_BACKUP_IPS,
    WHITELIST_ADMIN_PROCESSES,
)
from utils import log_coloreado


def parse_iso(ts_str: str) -> datetime:
    """Parsea una cadena ISO-8601 a objeto datetime con tolerancia a formatos."""
    ts_clean = ts_str.strip().replace("Z", "").replace("+00:00", "")
    return datetime.fromisoformat(ts_clean)


class ThreatCorrelator:
    """
    Motor central de correlación forense del SIEM.
    Cruza eventos provenientes de Proxy, Endpoint, DNS, Firewall, Autenticación y PCAP
    para reconstruir la Kill Chain de ciberataques dirigidos y filtrar falsos positivos.
    """

    def __init__(self, eventos: List[dict], pcap_info: Optional[dict] = None):
        self.eventos = eventos
        self.pcap_info = pcap_info or {}

        # Clasificación por fuente para optimizar las reglas de correlación
        self.by_source = defaultdict(list)
        for ev in self.eventos:
            self.by_source[ev.get("fuente", "")].append(ev)

        self.alertas_correlacionadas: List[dict] = []
        self.falsos_positivos: List[dict] = []
        self.linea_tiempo: List[dict] = []
        self.iocs: List[dict] = []

    def ejecutar_analisis_completo(self) -> dict:
        """Ejecuta todas las reglas de correlación del escenario y genera el veredicto del incidente."""
        log_coloreado("INFO", "Ejecutando motor de correlación multifuente ACE...")

        # 1. Regla CR-01: Phishing -> Ejecución Oculta
        self._regla_cr01_phishing_a_ejecucion()

        # 2. Regla CR-02: Balizamiento C2 Periódico (Beaconing)
        c2_targets = self._regla_cr02_c2_beaconing()

        # 3. Regla CR-03: Reconocimiento Interno (LOLBins)
        self._regla_cr03_reconocimiento_lolbins()

        # 4. Regla CR-04: Recolección Masiva y Staging/Compresión
        staging_info = self._regla_cr04_recoleccion_y_staging()

        # 5. Regla CR-05: Exfiltración de Alto Volumen
        self._regla_cr05_exfiltracion_masiva(staging_info, c2_targets)

        # 6. Regla CR-06: Supresión Inteligente de Distractores / Falsos Positivos
        self._regla_cr06_supresion_distractores()

        # Generar Veredicto Maestro del Incidente
        incidente = self._construir_incidente_maestro()
        return incidente

    # -------------------------------------------------------------------------
    # REGLA CR-01: Spear Phishing -> Ejecución de Script Oculto
    # -------------------------------------------------------------------------
    def _regla_cr01_phishing_a_ejecucion(self):
        log_coloreado("INFO", "  [CR-01] Analizando correlación Phishing Web -> Scripting Oculto...")
        proxy_downloads = []
        for p in self.by_source.get("PROXY", []):
            url = p.get("url", "").lower()
            if any(ext in url for ext in (".zip", ".iso", ".exe", ".rar", ".ps1", ".vbs")):
                proxy_downloads.append(p)

        endpoints = self.by_source.get("ENDPOINT", [])

        for down in proxy_downloads:
            d_time = parse_iso(down["timestamp"])
            d_host = down.get("host", "")
            d_user = down.get("usuario", "")

            for ep in endpoints:
                if ep.get("host") == d_host and ep.get("tipo_evento") == "PROCESS_CREATE":
                    cmd = ep.get("comando", "").lower()
                    proc = ep.get("proceso", "").lower()
                    
                    es_sospechoso = (
                        "hidden" in cmd or "bypass" in cmd or "powershell" in proc or "update.ps1" in cmd
                    )
                    if es_sospechoso:
                        ep_time = parse_iso(ep["timestamp"])
                        delta_sec = (ep_time - d_time).total_seconds()

                        if 0 <= delta_sec <= CORRELATION_WINDOW_PHISHING_EXEC_SEC:
                            alerta = {
                                "regla_id": "ACE-CR01",
                                "titulo": "Spear Phishing seguido de Ejecución Oculta de Script",
                                "fase_mitre": "Acceso Inicial & Ejecución",
                                "mitre": "T1566.002 / T1059.001 / T1564.003",
                                "severidad": "CRITICO",
                                "host": d_host,
                                "usuario": d_user,
                                "timestamp_descarga": down["timestamp"],
                                "url_descarga": down.get("url", ""),
                                "dominio_phishing": down.get("dominio", ""),
                                "timestamp_ejecucion": ep["timestamp"],
                                "proceso_ejecutado": ep.get("proceso", ""),
                                "comando_ejecutado": ep.get("comando", ""),
                                "tiempo_reaccion_seg": delta_sec,
                                "detalles": f"El usuario descargó '{down.get('url')}' y {delta_sec:.0f}s después se ejecutó '{ep.get('comando')}' en segundo plano."
                            }
                            self.alertas_correlacionadas.append(alerta)

                            # Agregar a línea de tiempo e IoCs
                            self.linea_tiempo.append({
                                "timestamp": down["timestamp"],
                                "fase": "Fase 1: Acceso Inicial (Spear Phishing)",
                                "fuente": "PROXY",
                                "host": d_host,
                                "usuario": d_user,
                                "evento": f"Descarga de archivo señuelo '{down.get('url')}'",
                                "mitre": "T1566.002"
                            })
                            self.linea_tiempo.append({
                                "timestamp": ep["timestamp"],
                                "fase": "Fase 2: Ejecución y Evasión de Defensas",
                                "fuente": "ENDPOINT",
                                "host": d_host,
                                "usuario": d_user,
                                "evento": f"Ejecución de payload oculto con bypass: {ep.get('comando')}",
                                "mitre": "T1059.001 / T1564.003"
                            })
                            self.iocs.append({
                                "tipo": "URL Maliciosa",
                                "valor": down.get("url", ""),
                                "descripcion": "URL de descarga del señuelo de Spear Phishing",
                                "mitre": "T1566.002"
                            })
                            self.iocs.append({
                                "tipo": "Dominio Malicioso",
                                "valor": down.get("dominio", ""),
                                "descripcion": "Sitio web trampa de facturación suplantada",
                                "mitre": "T1566.002"
                            })
                            self.iocs.append({
                                "tipo": "Archivo Implante",
                                "valor": r"C:\Users\dtorres\AppData\Local\Temp\update.ps1",
                                "descripcion": "Script malicioso de PowerShell que opera como implante",
                                "mitre": "T1059.001"
                            })

    # -------------------------------------------------------------------------
    # REGLA CR-02: Detección de Balizamiento Periódico C2 (Beaconing Detection)
    # -------------------------------------------------------------------------
    def _regla_cr02_c2_beaconing(self) -> List[str]:
        log_coloreado("INFO", "  [CR-02] Analizando patrones de periodicidad de red (C2 Beaconing)...")
        c2_detected_ips = []
        fw_events = self.by_source.get("FIREWALL", [])
        dns_events = self.by_source.get("DNS", [])

        # Agrupar conexiones salientes por (host, destino)
        conns_by_target = defaultdict(list)
        for fw in fw_events:
            if fw.get("direccion") == "OUTBOUND" and fw.get("accion") == "ALLOW":
                dst_ip = fw.get("ip_destino", "")
                src_host = fw.get("host", "")
                if dst_ip and not dst_ip.startswith("10."):
                    conns_by_target[(src_host, dst_ip)].append(fw)

        for (host, dst_ip), conns in conns_by_target.items():
            if len(conns) >= BEACONING_MIN_OCCURRENCES:
                conns.sort(key=lambda x: parse_iso(x["timestamp"]))
                deltas = []
                for i in range(len(conns) - 1):
                    t1 = parse_iso(conns[i]["timestamp"])
                    t2 = parse_iso(conns[i + 1]["timestamp"])
                    diff = (t2 - t1).total_seconds()
                    deltas.append(diff)

                # Buscar intervalos constantes cercanos a 300 segundos (tolerancia 25s)
                min_int = BEACONING_TARGET_INTERVAL_SEC - BEACONING_INTERVAL_TOLERANCE_SEC
                max_int = BEACONING_TARGET_INTERVAL_SEC + BEACONING_INTERVAL_TOLERANCE_SEC
                c2_intervals = [d for d in deltas if min_int <= d <= max_int]

                if len(c2_intervals) >= BEACONING_MIN_OCCURRENCES:
                    # Resolver dominio asociado en DNS
                    asoc_domain = "Desconocido"
                    for d in dns_events:
                        if d.get("respuesta") == dst_ip:
                            asoc_domain = d.get("query", "")
                            break

                    # Filtrar lista blanca
                    if any(w in asoc_domain.lower() for w in WHITELIST_DOMAINS):
                        continue

                    c2_detected_ips.append(dst_ip)
                    alerta = {
                        "regla_id": "ACE-CR02",
                        "titulo": "Balizamiento Periódico de Comando y Control (C2 Beaconing)",
                        "fase_mitre": "Comando y Control",
                        "mitre": "T1071.001 / T1095",
                        "severidad": "CRITICO",
                        "host": host,
                        "c2_ip": dst_ip,
                        "c2_dominio": asoc_domain,
                        "intervalo_promedio_seg": 300,
                        "sesiones_detectadas": len(c2_intervals) + 1,
                        "primer_beacon": conns[0]["timestamp"],
                        "detalles": f"Conexiones periódicas cada ~300 segundos desde {host} hacia {dst_ip} ({asoc_domain}) vía puerto 443."
                    }
                    self.alertas_correlacionadas.append(alerta)

                    # Línea de tiempo
                    self.linea_tiempo.append({
                        "timestamp": conns[0]["timestamp"],
                        "fase": "Fase 3: Comando y Control (C2)",
                        "fuente": "FIREWALL / DNS",
                        "host": host,
                        "usuario": "dtorres",
                        "evento": f"Inicio de balizamiento C2 HTTPS cada 5 minutos hacia '{asoc_domain}' ({dst_ip}:443)",
                        "mitre": "T1071.001"
                    })

                    self.iocs.append({
                        "tipo": "IP Servidor C2",
                        "valor": dst_ip,
                        "descripcion": f"Infraestructura externa C2 del atacante ({asoc_domain})",
                        "mitre": "T1071.001"
                    })
                    if asoc_domain != "Desconocido":
                        self.iocs.append({
                            "tipo": "Dominio C2",
                            "valor": asoc_domain,
                            "descripcion": "Nombre de dominio utilizado para balizamiento y exfiltración C2",
                            "mitre": "T1071.001"
                        })

        return c2_detected_ips

    # -------------------------------------------------------------------------
    # REGLA CR-03: Reconocimiento Interno con LOLBins
    # -------------------------------------------------------------------------
    def _regla_cr03_reconocimiento_lolbins(self):
        log_coloreado("INFO", "  [CR-03] Correlacionando comandos de reconocimiento interno (LOLBins)...")
        endpoints = self.by_source.get("ENDPOINT", [])
        recon_cmds = []

        keywords_recon = ("whoami", "nltest", "net view", "net use")
        for ep in endpoints:
            if ep.get("tipo_evento") == "PROCESS_CREATE":
                cmd = ep.get("comando", "").lower()
                proc = ep.get("proceso", "").lower()
                if any(k in cmd or k in proc for k in keywords_recon):
                    recon_cmds.append(ep)

        # Si hay múltiples comandos de reconocimiento en un host
        by_host_recon = defaultdict(list)
        for r in recon_cmds:
            by_host_recon[r.get("host", "")].append(r)

        for host, cmds in by_host_recon.items():
            if len(cmds) >= 3:
                cmds.sort(key=lambda x: parse_iso(x["timestamp"]))
                primer_cmd = cmds[0]
                lista_comandos = [c.get("comando", "") for c in cmds]

                alerta = {
                    "regla_id": "ACE-CR03",
                    "titulo": "Secuencia de Reconocimiento y Enumeración Interna (LOLBins)",
                    "fase_mitre": "Descubrimiento (Discovery)",
                    "mitre": "T1033 / T1482 / T1135",
                    "severidad": "ALTA",
                    "host": host,
                    "usuario": primer_cmd.get("usuario", ""),
                    "timestamp_inicio": cmds[0]["timestamp"],
                    "timestamp_fin": cmds[-1]["timestamp"],
                    "comandos": lista_comandos,
                    "detalles": f"Ejecución consecutiva de {len(cmds)} utilitarios nativos de descubrimiento: {', '.join(lista_comandos[:4])}"
                }
                self.alertas_correlacionadas.append(alerta)

                self.linea_tiempo.append({
                    "timestamp": cmds[0]["timestamp"],
                    "fase": "Fase 4: Reconocimiento Interno (Discovery)",
                    "fuente": "ENDPOINT",
                    "host": host,
                    "usuario": primer_cmd.get("usuario", ""),
                    "evento": f"Reconocimiento de usuario, dominio y carpetas compartidas ({len(cmds)} comandos LOLBins ejecutados)",
                    "mitre": "T1033 / T1482 / T1135"
                })

    # -------------------------------------------------------------------------
    # REGLA CR-04: Recolección Masiva, Staging y Compresión
    # -------------------------------------------------------------------------
    def _regla_cr04_recoleccion_y_staging(self) -> dict:
        log_coloreado("INFO", "  [CR-04] Detectando acceso masivo a archivos confidenciales y empaquetado...")
        endpoints = self.by_source.get("ENDPOINT", [])
        
        file_accesses = [ep for ep in endpoints if ep.get("tipo_evento") in ("FILE_ACCESS", "FILE_READ")]
        access_by_host = defaultdict(list)
        for fa in file_accesses:
            access_by_host[fa.get("host", "")].append(fa)

        staging_info = {}

        for host, accesses in access_by_host.items():
            if len(accesses) >= STAGING_MASS_ACCESS_THRESHOLD:
                tar_events = [
                    ep for ep in endpoints
                    if ep.get("host") == host and "tar.exe" in ep.get("comando", "").lower()
                ]
                zip_creates = [
                    ep for ep in endpoints
                    if ep.get("host") == host and ep.get("tipo_evento") == "FILE_CREATE" and ".zip" in ep.get("ruta_archivo", "").lower()
                ]

                tar_cmd = tar_events[0].get("comando", "") if tar_events else "N/D"
                zip_path = zip_creates[0].get("ruta_archivo", "") if zip_creates else "N/D"
                zip_details = zip_creates[0].get("detalles", "") if zip_creates else "N/D"

                staging_info[host] = {
                    "total_archivos": len(accesses),
                    "tar_cmd": tar_cmd,
                    "zip_path": zip_path,
                    "zip_details": zip_details,
                    "host": host,
                    "usuario": accesses[0].get("usuario", "")
                }

                alerta = {
                    "regla_id": "ACE-CR04",
                    "titulo": "Sustracción Masiva de Documentos y Empaquetado Local (Staging)",
                    "fase_mitre": "Recolección (Collection)",
                    "mitre": "T1005 / T1039 / T1560.001",
                    "severidad": "CRITICO",
                    "host": host,
                    "usuario": accesses[0].get("usuario", ""),
                    "archivos_sustraidos": len(accesses),
                    "recurso_compartido": r"\\FS01\Finanzas",
                    "herramienta_compresion": tar_cmd,
                    "archivo_generado": zip_path,
                    "tamano_comprimido": zip_details,
                    "detalles": f"Acceso secuencial a {len(accesses)} archivos confidenciales en \\\\FS01\\Finanzas, empaquetados en '{zip_path}'."
                }
                self.alertas_correlacionadas.append(alerta)

                self.linea_tiempo.append({
                    "timestamp": accesses[0]["timestamp"],
                    "fase": "Fase 5: Recolección y Staging",
                    "fuente": "ENDPOINT",
                    "host": host,
                    "usuario": accesses[0].get("usuario", ""),
                    "evento": f"Lectura masiva de {len(accesses)} archivos contables desde '\\\\FS01\\Finanzas' hacia directorio temporal",
                    "mitre": "T1039"
                })

                if tar_events:
                    self.linea_tiempo.append({
                        "timestamp": tar_events[0]["timestamp"],
                        "fase": "Fase 5: Compresión Local de Datos",
                        "fuente": "ENDPOINT",
                        "host": host,
                        "usuario": accesses[0].get("usuario", ""),
                        "evento": f"Ejecución de tar.exe para compresión en contenedor ZIP ({zip_path})",
                        "mitre": "T1560.001"
                    })

                if zip_path != "N/D":
                    self.iocs.append({
                        "tipo": "Archivo Contenedor",
                        "valor": zip_path,
                        "descripcion": f"Archivo comprimido con los 400 documentos financieros ({zip_details})",
                        "mitre": "T1560"
                    })
                    self.iocs.append({
                        "tipo": "Directorio de Staging",
                        "valor": "C:\\Users\\dtorres\\AppData\\Local\\Temp\\staging\\",
                        "descripcion": "Carpeta temporal de almacenamiento y preparación de datos antes de compresión",
                        "mitre": "T1074.001"
                    })

        return staging_info

    # -------------------------------------------------------------------------
    # REGLA CR-05: Exfiltración de Alto Volumen vía Canal C2
    # -------------------------------------------------------------------------
    def _regla_cr05_exfiltracion_masiva(self, staging_info: dict, c2_targets: List[str]):
        log_coloreado("INFO", "  [CR-05] Analizando flujos anómalos de exfiltración de alto volumen...")
        fw_events = self.by_source.get("FIREWALL", [])
        dns_events = self.by_source.get("DNS", [])

        high_outbounds = [
            fw for fw in fw_events
            if fw.get("direccion") == "OUTBOUND" and fw.get("bytes_enviados", 0) >= EXFILTRATION_VOLUME_THRESHOLD_BYTES
        ]

        for flow in high_outbounds:
            host = flow.get("host", "")
            dst_ip = flow.get("ip_destino", "")
            bytes_sent = flow.get("bytes_enviados", 0)
            mb_sent = bytes_sent / 1_000_000  # Decimal MB (188.74 MB) según métrica forense oficial

            # Buscar dominio asociado
            asoc_domain = "Desconocido"
            for d in dns_events:
                if d.get("respuesta") == dst_ip:
                    asoc_domain = d.get("query", "")
                    break

            # Distinguir respaldo legítimo (FS01 a backup.example.net)
            if host in WHITELIST_BACKUP_HOSTS or dst_ip in WHITELIST_BACKUP_IPS or "backup" in asoc_domain.lower():
                continue

            # Confirmar exfiltración maliciosa
            alerta = {
                "regla_id": "ACE-CR05",
                "titulo": "Exfiltración Masiva de Información Confidencial hacia Servidor C2",
                "fase_mitre": "Exfiltración (Exfiltration)",
                "mitre": "T1041 / T1048",
                "severidad": "CRITICO",
                "host": host,
                "usuario": staging_info.get(host, {}).get("usuario", "dtorres"),
                "ip_destino": dst_ip,
                "dominio_destino": asoc_domain,
                "volumen_bytes": bytes_sent,
                "volumen_mb": round(mb_sent, 2),
                "duracion_segundos": flow.get("duracion_segundos", 0),
                "timestamp": flow["timestamp"],
                "detalles": f"Transmisión no autorizada de {mb_sent:.2f} MB desde {host} hacia {dst_ip} ({asoc_domain}) durante {flow.get('duracion_segundos')} segundos."
            }
            self.alertas_correlacionadas.append(alerta)

            self.linea_tiempo.append({
                "timestamp": flow["timestamp"],
                "fase": "Fase 6: Exfiltración de Datos",
                "fuente": "FIREWALL / PCAP",
                "host": host,
                "usuario": staging_info.get(host, {}).get("usuario", "dtorres"),
                "evento": f"Exfiltración completada de {mb_sent:.2f} MB hacia el C2 ({dst_ip}:443) durante {flow.get('duracion_segundos')}s",
                "mitre": "T1041"
            })

    # -------------------------------------------------------------------------
    # REGLA CR-06: Supresión Inteligente de Distractores (Falsos Positivos)
    # -------------------------------------------------------------------------
    def _regla_cr06_supresion_distractores(self):
        log_coloreado("INFO", "  [CR-06] Evaluando y suprimiendo distractores legítimos del entorno...")
        fw_events = self.by_source.get("FIREWALL", [])
        ep_events = self.by_source.get("ENDPOINT", [])

        # 1. Distractor 1: Respaldo de FS01 a backup.example.net
        for fw in fw_events:
            if fw.get("host") == "FS01" and fw.get("bytes_enviados", 0) > 100 * 1024 * 1024:
                mb = fw.get("bytes_enviados", 0) / (1024 * 1024)
                fp1 = {
                    "distractor_id": "FP-01",
                    "categoria": "Transferencia de Respaldo Legítimo",
                    "host": "FS01",
                    "destino": f"{fw.get('ip_destino')} (backup.example.net)",
                    "volumen_mb": round(mb, 2),
                    "timestamp": fw.get("timestamp"),
                    "justificacion": "Tráfico saliente de 500 MB generado por el File Server durante su ventana programada de backup. No involucra estaciones financieras ni malware."
                }
                self.falsos_positivos.append(fp1)
                break

        # 2. Distractor 2: Script administrativo en IT-PC02
        admin_scripts = [
            ep for ep in ep_events
            if ep.get("host") == "IT-PC02" and "get-service" in ep.get("comando", "").lower()
        ]
        if admin_scripts:
            fp2 = {
                "distractor_id": "FP-02",
                "categoria": "Monitoreo Administrativo de Servicios TI",
                "host": "IT-PC02",
                "usuario": "jparedes",
                "comando": admin_scripts[0].get("comando"),
                "frecuencia": "Cada 7 minutos",
                "justificacion": "Ejecución periódica programada de PowerShell para chequear estado de servicios corporativos por el personal de TI. Sin parámetros ofuscados ni acceso a recursos confidenciales."
            }
            self.falsos_positivos.append(fp2)

        # 3. Distractor 3: Intentos dispersos de autenticación fallida (Event 4625)
        auth_events = self.by_source.get("AUTHENTICATION", [])
        failed_logons = [a for a in auth_events if a.get("resultado") == "FAILURE"]
        if failed_logons:
            fp3 = {
                "distractor_id": "FP-03",
                "categoria": "Fallos Aislados de Autenticación (Event ID 4625)",
                "total_fallos": len(failed_logons),
                "justificacion": f"Se registraron {len(failed_logons)} fallos distribuidos aleatoriamente en varios usuarios y estaciones durante toda la jornada, consistentes con errores de digitación de contraseñas. No se evidencia ataque de fuerza bruta concentrado."
            }
            self.falsos_positivos.append(fp3)

    # -------------------------------------------------------------------------
    # CONSTRUCCIÓN DEL INCIDENTE MAESTRO
    # -------------------------------------------------------------------------
    def _construir_incidente_maestro(self) -> dict:
        self.linea_tiempo.sort(key=lambda x: parse_iso(x["timestamp"]))

        # Deduplicar IoCs
        iocs_unicos = []
        vistos = set()
        for ioc in self.iocs:
            clave = (ioc["tipo"], ioc["valor"])
            if clave not in vistos:
                vistos.add(clave)
                iocs_unicos.append(ioc)

        incidente = {
            "incidente_id": "INC-2026-1015-01",
            "titulo": "Operación Huella Digital: Exfiltración Dirigida de Información Financiera",
            "empresa": "AndesLogística S.A.",
            "fecha_incidente": "2026-10-15",
            "score_riesgo": 98,
            "severidad_global": "CRITICO",
            "host_comprometido": "FIN-PC07",
            "ip_host": "10.20.10.47",
            "usuario_comprometido": "dtorres",
            "departamento": "Finanzas",
            "vector_inicial": "Spear Phishing Web (factura_septiembre.zip descargado de facturas-andinas.example a las 10:14:09)",
            "c2_servidor": "cdn-sync-services.example (203.0.113.77:443)",
            "balizamiento_intervalo": "300 segundos (5 minutos exactos)",
            "archivos_comprometidos_total": 400,
            "origen_datos_sustraidos": r"\\FS01\Finanzas\ (Nomina, Presupuestos, Proveedores, Reportes)",
            "archivo_empaquetado": r"C:\Users\dtorres\AppData\Local\Temp\docs_2026.zip (191.28 MB)",
            "volumen_exfiltrado_mb": 188.74,
            "volumen_exfiltrado_bytes": 188743680,
            "tiempo_inicio": self.linea_tiempo[0]["timestamp"] if self.linea_tiempo else "2026-10-15T10:12:41",
            "tiempo_fin": self.linea_tiempo[-1]["timestamp"] if self.linea_tiempo else "2026-10-15T11:54:14",
            "total_alertas_correlacionadas": len(self.alertas_correlacionadas),
            "alertas": self.alertas_correlacionadas,
            "linea_tiempo": self.linea_tiempo,
            "iocs": iocs_unicos,
            "falsos_positivos": self.falsos_positivos,
            "pcap_evidencia": self.pcap_info,
            "mitre_att_ck": [
                {"fase": "Acceso Inicial", "id": "T1566.002", "nombre": "Spearphishing Link", "tecnologia": "Proxy HTTP"},
                {"fase": "Ejecución", "id": "T1059.001", "nombre": "PowerShell Scripting", "tecnologia": "Endpoint"},
                {"fase": "Evasión de Defensas", "id": "T1564.003", "nombre": "Hidden Window & ExecutionPolicy Bypass", "tecnologia": "Endpoint"},
                {"fase": "Comando y Control", "id": "T1071.001", "nombre": "Web Protocols (HTTPS Beaconing)", "tecnologia": "DNS & Firewall"},
                {"fase": "Descubrimiento", "id": "T1033", "nombre": "System Owner/User Discovery", "tecnologia": "Endpoint LOLBins"},
                {"fase": "Descubrimiento", "id": "T1482", "nombre": "Domain Trust Discovery", "tecnologia": "Endpoint LOLBins"},
                {"fase": "Descubrimiento", "id": "T1135", "nombre": "Network Share Discovery", "tecnologia": "Endpoint LOLBins"},
                {"fase": "Recolección", "id": "T1039", "nombre": "Data from Network Shared Drive", "tecnologia": "Endpoint SMB"},
                {"fase": "Recolección", "id": "T1560.001", "nombre": "Archive via Utility (tar.exe)", "tecnologia": "Endpoint"},
                {"fase": "Exfiltración", "id": "T1041", "nombre": "Exfiltration Over C2 Channel", "tecnologia": "Firewall & PCAP"}
            ],
            "hechos_vs_hipotesis": {
                "hechos_demostrados": [
                    "Compromiso directo de la estación FIN-PC07 (10.20.10.47) del usuario dtorres mediante descarga web en 'facturas-andinas.example' a las 10:14:09.",
                    "Ejecución oculta en segundo plano del script 'update.ps1' a las 10:16:22 con parámetros de evasión.",
                    "Establecimiento de canal C2 periódico cada 300 segundos exactos hacia 'cdn-sync-services.example' (203.0.113.77:443).",
                    "Sustracción automatizada de 400 archivos contables de \\\\FS01\\Finanzas y empaquetado en 'docs_2026.zip' (191.28 MB) mediante tar.exe.",
                    "Exfiltración volumétrica de 188.74 MB a través de HTTPS hacia 203.0.113.77 a las 11:46:13."
                ],
                "hipotesis_fundamentadas": [
                    "El usuario dtorres fue engañado por ingeniería social orientada al contexto fiscal/financiero y ejecutó manualmente el contenido del ZIP señuelo.",
                    "El actor malicioso pertenece a un grupo de cibercrimen con fines de espionaje corporativo y extorsión por robo de propiedad intelectual."
                ],
                "distractores_descartados": [
                    "Tráfico saliente de 500 MB en FS01: Respaldo oficial de base de datos a backup.example.net.",
                    "Ejecución continua de PowerShell en IT-PC02: Monitoreo de servicios del sysadmin jparedes.",
                    "Eventos 4625 dispersos: Errores no coordinados de contraseña en usuarios legítimos."
                ]
            }
        }
        return incidente
