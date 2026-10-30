import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

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


# =========================================================================
# REPORTES ESPECIALIZADOS DE INCIDENTE FORENSE - HACKATHON
# =========================================================================

def generar_informe_forense_md(incidente: dict, analisis_ia: Optional[dict] = None, nombre: Optional[str] = None) -> str:
    """Genera el informe forense completo y profesional en formato Markdown."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if nombre is None:
        nombre = f"informe_forense_{incidente.get('incidente_id', 'INC01')}.md"
    path = REPORTS_DIR / nombre

    ai = analisis_ia or {}
    resumen_ejecutivo = ai.get("resumen_ejecutivo", incidente.get("resumen_ia", ""))
    impacto = ai.get("impacto_empresarial", "")
    contencion = ai.get("acciones_contencion", [])
    erradicacion = ai.get("acciones_erradicacion", [])

    md = [
        f"# INFORME DE INVESTIGACIÓN FORENSE Y RESPUESTA A INCIDENTES",
        f"**Caso:** {incidente.get('titulo')}",
        f"**Organización Afectada:** {incidente.get('empresa')}",
        f"**Fecha del Incidente:** {incidente.get('fecha_incidente')} | **ID Incidente:** `{incidente.get('incidente_id')}`",
        f"**Nivel de Severidad Global:** **{incidente.get('severidad_global')}** (Score: {incidente.get('score_riesgo')}/100)",
        "",
        "---",
        "",
        "## 1. Resumen Ejecutivo del Incidente",
        resumen_ejecutivo,
        "",
        "### 🎯 Resumen de Activos Comprometidos",
        f"- **Estación de Trabajo:** `{incidente.get('host_comprometido')}` (IP: `{incidente.get('ip_host')}`)",
        f"- **Usuario Comprometido:** `{incidente.get('usuario_comprometido')}` (Área: {incidente.get('departamento')})",
        f"- **Vector de Infección Inicial:** {incidente.get('vector_inicial')}",
        f"- **Infraestructura de Comando y Control (C2):** `{incidente.get('c2_servidor')}`",
        f"- **Frecuencia de Balizamiento (Beaconing):** {incidente.get('balizamiento_intervalo')}",
        f"- **Datos Comprometidos:** {incidente.get('archivos_comprometidos_total')} archivos confidenciales ({incidente.get('origen_datos_sustraidos')})",
        f"- **Volumen Total Exfiltrado:** **{incidente.get('volumen_exfiltrado_mb')} MB** ({incidente.get('volumen_exfiltrado_bytes'):,} bytes)",
        "",
        "---",
        "",
        "## 2. Reconstrucción Cronológica del Ataque (Kill Chain)",
        "",
        "| Hora (UTC) | Fase del Ataque | Fuente | Host / Usuario | Detalle Técnico del Evento | Técnica MITRE |",
        "|---|---|---|---|---|---|"
    ]

    for item in incidente.get("linea_tiempo", []):
        ts = item.get("timestamp", "").replace("T", " ")
        fase = item.get("fase", "")
        fuente = item.get("fuente", "")
        actor = f"{item.get('host', '')} ({item.get('usuario', '')})"
        evento = item.get("evento", "")
        mitre = item.get("mitre", "")
        md.append(f"| `{ts}` | **{fase}** | `{fuente}` | {actor} | {evento} | `{mitre}` |")

    md += [
        "",
        "---",
        "",
        "## 3. Matriz Táctica MITRE ATT&CK Cubierta",
        "",
        "| Táctica MITRE | ID Técnica | Nombre de la Técnica | Evidencia / Tecnología Involucrada |",
        "|---|---|---|---|"
    ]

    for m in incidente.get("mitre_att_ck", []):
        md.append(f"| **{m.get('fase')}** | `{m.get('id')}` | {m.get('nombre')} | {m.get('tecnologia')} |")

    md += [
        "",
        "---",
        "",
        "## 4. Indicadores de Compromiso (IoCs)",
        "",
        "| Tipo de Indicador | Valor / Artefacto | Descripción y Contexto Forense | MITRE |",
        "|---|---|---|---|"
    ]

    for ioc in incidente.get("iocs", []):
        md.append(f"| **{ioc.get('tipo')}** | `{ioc.get('valor')}` | {ioc.get('descripcion')} | `{ioc.get('mitre')}` |")

    md += [
        "",
        "---",
        "",
        "## 5. Cuadro de Rigor Forense: Hechos Demostrados vs. Hipótesis vs. Distractores",
        "",
        "### ✅ Hechos Demostrados por la Evidencia Digital",
    ]
    for h in incidente.get("hechos_vs_hipotesis", {}).get("hechos_demostrados", []):
        md.append(f"- {h}")

    md += [
        "",
        "### 💡 Hipótesis Fundamentadas",
    ]
    for hip in incidente.get("hechos_vs_hipotesis", {}).get("hipotesis_fundamentadas", []):
        md.append(f"- {hip}")

    md += [
        "",
        "### 🛡️ Distractores y Falsos Positivos Suprimidos Inteligente por el SIEM",
    ]
    for d in incidente.get("falsos_positivos", []):
        md.append(f"- **{d.get('categoria')}** (`{d.get('host', 'N/D')}`): {d.get('justificacion')}")

    if impacto:
        md += [
            "",
            "---",
            "",
            "## 6. Evaluación de Impacto en el Negocio",
            impacto,
        ]

    if contencion:
        md += [
            "",
            "---",
            "",
            "## 7. Plan de Respuesta y Contención Inmediata",
        ]
        for c in contencion:
            md.append(f"- {c}")

    if erradicacion:
        md += [
            "",
            "### Plan de Erradicación y Recuperación",
        ]
        for e in erradicacion:
            md.append(f"- {e}")

    md += [
        "",
        "---",
        f"*Informe generado automáticamente por AndesCorrelator Engine (ACE) SIEM el {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}.*",
        ""
    ]

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    return str(path)


def generar_dashboard_html(incidente: dict, analisis_ia: Optional[dict] = None, nombre: Optional[str] = None) -> str:
    """Genera un dashboard interactivo de alta fidelidad visual en HTML (listo para presentar o exportar a PDF)."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if nombre is None:
        nombre = f"dashboard_incidente_{incidente.get('incidente_id', 'INC01')}.html"
    path = REPORTS_DIR / nombre

    ai = analisis_ia or {}
    resumen = ai.get("resumen_ejecutivo", incidente.get("resumen_ia", ""))

    # Filas de timeline
    timeline_rows = ""
    for item in incidente.get("linea_tiempo", []):
        ts = item.get("timestamp", "").replace("T", " ")
        timeline_rows += f"""
        <tr>
            <td class="mono">{ts}</td>
            <td><span class="badge badge-phase">{item.get('fase')}</span></td>
            <td><span class="badge badge-source">{item.get('fuente')}</span></td>
            <td>{item.get('host')} / {item.get('usuario')}</td>
            <td>{item.get('evento')}</td>
            <td class="mono text-mitre">{item.get('mitre')}</td>
        </tr>
        """

    # Filas de IoCs
    ioc_rows = ""
    for ioc in incidente.get("iocs", []):
        ioc_rows += f"""
        <tr>
            <td><strong>{ioc.get('tipo')}</strong></td>
            <td class="mono ioc-val">{ioc.get('valor')}</td>
            <td>{ioc.get('descripcion')}</td>
            <td class="mono text-mitre">{ioc.get('mitre')}</td>
        </tr>
        """

    # Filas de Falsos Positivos
    fp_cards = ""
    for fp in incidente.get("falsos_positivos", []):
        fp_cards += f"""
        <div class="fp-card">
            <h4>🛡️ {fp.get('categoria')} ({fp.get('host', 'N/D')})</h4>
            <p>{fp.get('justificacion')}</p>
        </div>
        """

    # HTML Template
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SIEM Report: {incidente.get('titulo')}</title>
    <style>
        :root {{
            --bg-main: #0b0f19;
            --bg-card: #151c2c;
            --bg-card-hover: #1c263c;
            --border: #23314d;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --accent-red: #ef4444;
            --accent-blue: #38bdf8;
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --accent-purple: #a855f7;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{ background: var(--bg-main); color: var(--text-main); padding: 30px; line-height: 1.6; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--border); padding-bottom: 20px; margin-bottom: 25px; }}
        .header h1 {{ font-size: 24px; color: var(--accent-red); display: flex; align-items: center; gap: 10px; }}
        .header .meta {{ color: var(--text-muted); font-size: 14px; text-align: right; }}
        .grid-stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 25px; }}
        .stat-card {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 18px; text-align: center; }}
        .stat-card .val {{ font-size: 28px; font-weight: 800; color: var(--accent-blue); margin-top: 5px; }}
        .stat-card .val.crit {{ color: var(--accent-red); }}
        .stat-card .val.warn {{ color: var(--accent-yellow); }}
        .stat-card .val.ok {{ color: var(--accent-green); }}
        .stat-card .label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); }}
        .section {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 22px; margin-bottom: 25px; }}
        .section h2 {{ font-size: 18px; margin-bottom: 15px; display: flex; align-items: center; gap: 8px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 10px; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background: #1a2336; color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 11px; }}
        tr:hover {{ background: var(--bg-card-hover); }}
        .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; display: inline-block; }}
        .badge-phase {{ background: rgba(56, 189, 248, 0.15); color: var(--accent-blue); }}
        .badge-source {{ background: rgba(168, 85, 247, 0.15); color: var(--accent-purple); }}
        .text-mitre {{ color: #fb923c; font-weight: bold; }}
        .ioc-val {{ color: #f472b6; word-break: break-all; }}
        .fp-card {{ background: #0f172a; border-left: 4px solid var(--accent-green); padding: 12px 16px; margin-bottom: 10px; border-radius: 0 6px 6px 0; }}
        .fp-card h4 {{ color: var(--accent-green); font-size: 14px; margin-bottom: 4px; }}
        .fp-card p {{ font-size: 13px; color: var(--text-muted); }}
        .summary-box {{ background: #1a2336; border-left: 4px solid var(--accent-red); padding: 16px; border-radius: 0 8px 8px 0; font-size: 14px; }}
        @media print {{ body {{ background: white; color: black; }} .section, .stat-card {{ border-color: #ccc; background: white; }} }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🚨 {incidente.get('titulo')}</h1>
            <p style="color: var(--text-muted); font-size: 14px; margin-top: 5px;">Plataforma de Detección y Respuesta a Incidentes — AndesCorrelator Engine (ACE)</p>
        </div>
        <div class="meta">
            <div><strong>Empresa:</strong> {incidente.get('empresa')}</div>
            <div><strong>ID Caso:</strong> {incidente.get('incidente_id')}</div>
            <div><strong>Fecha Incidente:</strong> {incidente.get('fecha_incidente')}</div>
        </div>
    </div>

    <div class="grid-stats">
        <div class="stat-card">
            <div class="label">Riesgo Global</div>
            <div class="val crit">{incidente.get('score_riesgo')} / 100</div>
        </div>
        <div class="stat-card">
            <div class="label">Estación Comprometida</div>
            <div class="val crit">{incidente.get('host_comprometido')}</div>
        </div>
        <div class="stat-card">
            <div class="label">Usuario Comprometido</div>
            <div class="val crit">{incidente.get('usuario_comprometido')}</div>
        </div>
        <div class="stat-card">
            <div class="label">Datos Exfiltrados</div>
            <div class="val warn">{incidente.get('volumen_exfiltrado_mb')} MB</div>
        </div>
        <div class="stat-card">
            <div class="label">Archivos Sustraídos</div>
            <div class="val warn">{incidente.get('archivos_comprometidos_total')} docs</div>
        </div>
        <div class="stat-card">
            <div class="label">Falsos Positivos Filtrados</div>
            <div class="val ok">{len(incidente.get('falsos_positivos', []))}</div>
        </div>
    </div>

    <div class="section">
        <h2>📋 Resumen Ejecutivo Forense</h2>
        <div class="summary-box">
            {resumen}
        </div>
    </div>

    <div class="section">
        <h2>⏱️ Línea de Tiempo Unificada del Ataque (Kill Chain)</h2>
        <table>
            <thead>
                <tr>
                    <th>Timestamp (UTC)</th>
                    <th>Fase de Ataque</th>
                    <th>Fuente</th>
                    <th>Actor / Host</th>
                    <th>Detalle del Suceso Forense</th>
                    <th>MITRE ATT&CK</th>
                </tr>
            </thead>
            <tbody>
                {timeline_rows}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>🔍 Indicadores de Compromiso (IoCs)</h2>
        <table>
            <thead>
                <tr>
                    <th>Tipo de IoC</th>
                    <th>Valor / Artefacto</th>
                    <th>Descripción y Contexto</th>
                    <th>MITRE</th>
                </tr>
            </thead>
            <tbody>
                {ioc_rows}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>🛡️ Supresión Inteligente de Distractores y Falsos Positivos</h2>
        <p style="color: var(--text-muted); font-size: 13px; margin-bottom: 15px;">
            El motor de correlación contextual del SIEM diferenció automáticamente actividades anómalas pero legítimas, evitando fatiga de alertas:
        </p>
        {fp_cards}
    </div>

    <div class="section">
        <h2>🔒 Plan de Prevención Activa y Hardening Empresarial (Defense-in-Depth)</h2>
        <p style="color: var(--text-muted); font-size: 13px; margin-bottom: 15px;">
            Medidas estructurales para blindar la infraestructura corporativa frente a futuras tentativas de intrusión:
        </p>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 15px;">
            <div class="fp-card" style="border-left-color: var(--accent-blue);">
                <h4 style="color: var(--accent-blue);">1. Hardening PowerShell (GPO)</h4>
                <p>Activar <code>ConstrainedLanguageMode</code> (__PSLockdownPolicy=4), ScriptBlockLogging (EID 4104) y Transcripción centralizada.</p>
            </div>
            <div class="fp-card" style="border-left-color: var(--accent-blue);">
                <h4 style="color: var(--accent-blue);">2. Reglas ASR Windows Defender</h4>
                <p>Bloqueo de contenido ejecutable desde web/correo, scripts ofuscados y llamadas a Win32 desde scripts no firmados.</p>
            </div>
            <div class="fp-card" style="border-left-color: var(--accent-blue);">
                <h4 style="color: var(--accent-blue);">3. Bloqueo en %TEMP% y AppData</h4>
                <p>Políticas de restricción de software (AppLocker/WDAC) impidiendo ejecución de .ps1, .bat y ejecutables en carpetas temporales.</p>
            </div>
            <div class="fp-card" style="border-left-color: var(--accent-blue);">
                <h4 style="color: var(--accent-blue);">4. Auditoría SMB en File Server</h4>
                <p>Segmentación por roles en <code>\\\\FS01\\Finanzas</code> y umbral de alerta automática ante lectura masiva (>50 archivos/min).</p>
            </div>
        </div>
        <div style="margin-top: 15px; padding: 12px; background: #0f172a; border-radius: 6px; font-size: 13px;">
            <strong>Scripts generados en carpeta <code>prevention/</code>:</strong>
            <code>01_contencion_inmediata_soar.ps1</code> | <code>02_hardening_gpo_empresarial.ps1</code> | <code>03_reglas_sysmon_prevencion.xml</code> | <code>04_bloqueo_firewall_perimetral.txt</code>
        </div>
    </div>

</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    return str(path)


def generar_iocs_json(incidente: dict, nombre: Optional[str] = None) -> str:
    """Exporta los IoCs identificados en formato JSON estructurado."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if nombre is None:
        nombre = f"iocs_{incidente.get('incidente_id', 'INC01')}.json"
    path = REPORTS_DIR / nombre

    data = {
        "incidente_id": incidente.get("incidente_id"),
        "generado": datetime.now(timezone.utc).isoformat(),
        "total_iocs": len(incidente.get("iocs", [])),
        "iocs": incidente.get("iocs", []),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return str(path)


def generar_linea_tiempo_csv(incidente: dict, nombre: Optional[str] = None) -> str:
    """Exporta la línea de tiempo del incidente en formato CSV plano."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if nombre is None:
        nombre = f"timeline_{incidente.get('incidente_id', 'INC01')}.csv"
    path = REPORTS_DIR / nombre

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Fase", "Fuente", "Host", "Usuario", "Evento", "MITRE"])
        for it in incidente.get("linea_tiempo", []):
            writer.writerow([
                it.get("timestamp", ""),
                it.get("fase", ""),
                it.get("fuente", ""),
                it.get("host", ""),
                it.get("usuario", ""),
                it.get("evento", ""),
                it.get("mitre", ""),
            ])
    return str(path)
