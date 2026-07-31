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

    lineas = [
        f"\\U0001F6B0 SIEM Inteligente {emoji}",
        "",
        f"*Nivel:*          {riesgo}",
        f"*Fuente:*         {evento_normalizado.get('fuente', 'N/A')}",
        f"*Ataque:*         {resultado_reglas.get('ataque', 'N/A')}",
        f"*Descripcion:*    {evento_normalizado.get('descripcion', 'N/A')[:100]}",
        f"*IP origen:*      {ip_origen}",
        f"*IP destino:*     {ip_destino}",
        f"*MITRE:*          {resultado_reglas.get('mitre', 'N/A')}",
        f"*OWASP:*          {resultado_reglas.get('owasp') or 'N/A'}",
        f"*Prioridad:*      {resultado_reglas.get('prioridad', 'N/A')}",
        f"*CVSS:*           {resultado_reglas.get('cvss', 'N/A')}",
        f"*Recomendacion:*  Resultado: {resultado_reglas.get('recomendacion', resultado_ia.get('recomendacion', ''))}",
        f"*Modelo IA:*      {resultado_ia.get('modelo', 'N/A')}",
    ]

    resumen_ia = resultado_ia.get("resumen", "")
    if resumen_ia:
        lineas.append(f"\n*Resumen IA:* {resumen_ia[:250]}")

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