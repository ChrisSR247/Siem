import logging
from typing import Optional

from config import TELEGRAM_TOKEN, TELEGRAM_CHAT_ID, ALERT_MIN_RISK, RISK_LEVELS

logger = logging.getLogger(__name__)


def _formatear_mensaje(evento_normalizado: dict, resultado_reglas: dict, resultado_ia: dict) -> str:
    riesgo = resultado_reglas.get("riesgo", "DESCONOCIDO")
    emoji = _emoji_riesgo(riesgo)

    ip_origen = evento_normalizado.get("ip_origen", evento_normalizado.get("agente_ip", "N/A"))
    ip_destino = evento_normalizado.get("ip_destino", "N/A")
    if not ip_origen:
        ip_origen = evento_normalizado.get("raw_log", "N/A")

    timestamp = evento_normalizado.get("timestamp", "N/A")
    agente = evento_normalizado.get("agente", "")
    categoria = evento_normalizado.get("categoria", "")

    # Recomendacion: priorizar IA, luego reglas
    rec = resultado_ia.get("recomendacion", "") or resultado_reglas.get("recomendacion", "")
    tecnicas_ia = resultado_ia.get("tecnicas_mitre", [])
    mitre_final = resultado_reglas.get("mitre", "")
    if tecnicas_ia:
        mitre_final += " (IA: " + ", ".join(tecnicas_ia) + ")"

    severidad_ia = resultado_ia.get("severidad", riesgo)
    falso_positivo = resultado_ia.get("falso_positivo", False)
    fp_texto = "\\u2704 Posible falso positivo" if falso_positivo else ""

    lineas = [
        f"\\U0001F6B0 *SIEM Inteligente* {emoji}",
        f"\\U0001F4C5 *Fecha:*         {timestamp}",
        f"\\U0001F4CA *Nivel:*         {riesgo} (IA: {severidad_ia})",
        f"\\U0001F4E1 *Fuente:*        {evento_normalizado.get('fuente', 'N/A')}",
    ]

    if agente:
        lineas.append(f"\\U0001F5A5 *Agente:*        {agente}")
    if categoria:
        lineas.append(f"\\U0001F4E6 *Categoria:*     {categoria}")

    lineas += [
        f"\\U0001F3AF *Ataque:*        {resultado_reglas.get('ataque', 'N/A')}",
        f"\\U0001F4DD *Descripcion:*   {evento_normalizado.get('descripcion', 'N/A')[:150]}",
        f"\\U0001F310 *IP origen:*     {ip_origen}",
        f"\\U0001F310 *IP destino:*    {ip_destino}",
        f"\\U0001F4A5 *MITRE ATT&CK:*  {mitre_final}",
    ]

    owasp = resultado_reglas.get("owasp")
    if owasp:
        lineas.append(f"\\U0001F939 *OWASP:*          {owasp}")

    lineas += [
        f"\\U0001F52D *CVSS estimado:* {resultado_reglas.get('cvss', 'N/A')}",
        f"\\U0001F4E2 *Prioridad:*      {resultado_reglas.get('prioridad', 'N/A')}",
        "",
        f"\\U0001F9EA *Analisis IA:*",
        f"  _\\\"{resultado_ia.get('resumen', 'No se pudo analizar con IA.')[:300]}\\\"_",
    ]

    if fp_label:
        lineas.append(f"  {fp_label}")

    lineas += [
        "",
        f"\\U0001F513 *Recomendacion:*",
        f"  1\\. {rec}",
        f"  2\\. Verificar logs completos en el SIEM",
        f"  3\\. Actualizar base de datos de amenazas",
        "",
        f"\\U0001F91U *Modelo IA:*      {resultado_ia.get('modelo', 'No disponible')}",
        f"\\U0001F4E0 *SIEM Inteligente :: Wazuh |> Suricata |> NVIDIA AI*",
    ]

    return "\n".join(lineas)


def _emoji_riesgo(riesgo: str) -> str:
    emojis = {
        "BAJO": "\\u26AB",
        "MEDIO": "\\u0001F50B",
        "ALTO": "\\u0001F50A",
        "CRITICO": "\\u0001F4A5",
    }
    return emojis.get(riesgo.upper(), "\\u2693")


def _deberia_enviar_alerta(resultado_reglas: dict) -> bool:
    riesgo_evento = resultado_reglas.get("riesgo", "BAJO").upper()
    return RISK_LEVELS.get(riesgo_evento, 0) >= RISK_LEVELS.get(ALERT_MIN_RISK.upper(), 2)


def enviar_alerta(evento_normalizado: dict, resultado_reglas: dict, resultado_ia: dict) -> bool:
    if not TELEGRAM_TOKEN or TELEGRAM_TOKEN == "TU_TOKEN_AQUI":
        logger.warning("Token de Telegram no configurado. No se enviare alerta.")
        return False

    if not _deberia_enviar_alerta(resultado_reglas):
        logger.debug("Riesgo %s no supera umbral %s. No se envia alerta.", resultado_reglas.get("riesgo"), ALERT_MIN_RISK)
        return False

    try:
        import requests
        mensaje = _formatear_mensaje(evento_normalizado, resultado_reglas, resultado_ia)
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": mensaje,
            "parse_mode": "Markdown",
        }
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code == 200:
            logger.info("Alerta Telegram enviada exitosamente")
            return True
        else:
            logger.error("Error al enviar Telegram: %s %s", resp.status_code, resp.text)
            return False
    except Exception as e:
        logger.error("Excepcion al enviar Telegram: %s", e)
        return False


def enviar_error(mensaje_error: str) -> bool:
    if not TELEGRAM_TOKEN or TELEGRAM_TOKEN == "TU_TOKEN_AQUI":
        return False
    try:
        import requests
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": f"\U0001F575 RC SIEM - Error del sistema:\n\n{mensaje_error}",
        }
        resp = requests.post(url, json=payload, timeout=10)
        return resp.status_code == 200
    except Exception:
        return False