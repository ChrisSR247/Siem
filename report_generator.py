import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from config import REPORTS_DIR
from database import obtener_estadisticas, obtener_todos_eventos


def generar_reporte_json(nombre: str = None) -> str:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if nombre is None:
        nombre = f"reporte_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    path = REPORTS_DIR / nombre
    stats = obtener_estadisticas()
    eventos = obtener_todos_eventos(limite=500)
    reporte = {
        "generado": datetime.now(timezone.utc).isoformat(),
        "estadisticas": stats,
        "eventos": eventos,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(reporte, f, ensure_ascii=False, indent=2)
    return str(path)


def generar_reporte_csv(nombre: str = None) -> str:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if nombre is None:
        nombre = f"reporte_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    path = REPORTS_DIR / nombre
    eventos = obtener_todos_eventos(limite=1000)

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        writer.writerow([
            "ID", "Fecha", "Fuente", "Ataque", "Riesgo",
            "IP Origen", "IP Destino", "MITRE", "Modelo IA", "Estado"
        ])

        for ev in eventos:
            writer.writerow([
                ev.get("id", ""),
                ev.get("fecha", ""),
                ev.get("fuente", ""),
                ev.get("ataque", ""),
                ev.get("riesgo", ""),
                ev.get("ip_origen", ""),
                ev.get("ip_destino", ""),
                ev.get("mitre", ""),
                ev.get("modelo", ""),
                ev.get("estado", ""),
            ])

    return str(path)


def generar_estadisticas_txt() -> str:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    nombre = f"estadisticas_{datetime.now().strftime('%Y%m%d')}.txt"
    path = REPORTS_DIR / nombre

    stats = obtener_estadisticas()
    lineas = [
        "=" * 50,
        " ESTADISTICAS DEL SIEM",
        "=" * 50,
        "",
        f"Total de eventos (hoy): {stats['total']}",
        f"Criticos: {stats['criticos']}",
        f"Altos:    {stats['altos']}",
        f"Medios:   {stats['medios']}",
        f"Bajos:    {stats['bajos']}",
        "",
        "Top 5 IPs origen:",
    ]

    for ip, cnt in stats.get("top_ips", []):
        lineas.append(f"  - {ip}: {cnt} eventos")
    lineas.append("")
    lineas.append("Top 5 ataques:")
    for ataque, cnt in stats.get("top_ataques", []):
        lineas.append(f"  - {ataque}: {cnt} eventos")
    lineas.append("")
    lineas.append("Modelos IA usados:")
    for modelo, cnt in stats.get("modelos_usados", []):
        lineas.append(f"  - {modelo}: {cnt} consultas")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lineas))

    return str(path)