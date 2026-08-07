import logging
import requests
from config import TELEGRAM_TOKEN, TELEGRAM_CHAT_ID

logger = logging.getLogger(__name__)

_telegram_fallo_red = False


def _emoji(riesgo: str) -> str:
    return {"BAJO": "\u26aa", "MEDIO": "\U0001f7e1", "ALTO": "\U0001f534", "CRITICO": "\U0001f4a3"}.get(riesgo.upper(), "\u2753")


def _formatear_mensaje(evento_normalizado: dict, resultado_reglas: dict, resultado_ia: dict) -> str:
    riesgo = resultado_reglas.get("riesgo", "?")
    ip_origen = evento_normalizado.get("ip_origen", evento_normalizado.get("agente_ip", evento_normalizado.get("raw_log", "N/D"))) or "N/D"
    ip_destino = evento_normalizado.get("ip_destino", "N/D") or "N/D"
    timestamp = evento_normalizado.get("timestamp", "")[:19]
    agente = evento_normalizado.get("agente", "")
    categoria = evento_normalizado.get("categoria", "")

    ia_model = resultado_ia.get("modelo", "N/D")
    ia_resumen = resultado_ia.get("resumen", "") or "(sin analisis IA)"
    ia_sev = resultado_ia.get("severidad", riesgo)

    rec = resultado_ia.get("recomendacion", "") or resultado_reglas.get("recomendacion", "Investigar.")
    mitre = resultado_reglas.get("mitre", "")

    msg = [
        f"\U0001f6a8 *ALERTA SIEM - Grupo 6* {_emoji(riesgo)}",
        "",
        f"*Riesgo:*  {riesgo} (IA: {ia_sev})",
        f"*Fuente:*  {evento_normalizado.get('fuente', 'N/D')}",
        f"*Ataque:*  {resultado_reglas.get('ataque', 'N/D')}",
        f"*Fecha:*   {timestamp}",
    ]

    if agente:
        msg.append(f"*Agente:* {agente}")
    if categoria:
        msg.append(f"*Categ:* {categoria}")

    msg += [
        f"*IP Origen:* {ip_origen}",
        f"*IP Dest:* {ip_destino}",
    ]

    if mitre:
        msg.append(f"*MITRE:* {mitre}")

    msg += [
        "",
        f"\U0001f9e0 *IA ({ia_model}):* {ia_resumen[:300]}",
        "",
        f"\U0001f6e1 *Recomendacion:* {rec}",
        f"",
        f"_SIEM Grupo 6 | Wazuh + Suricata + NVIDIA AI + Groq_",
    ]

    return "\n".join(msg)


def enviar_alerta(evento_normalizado: dict, resultado_reglas: dict, resultado_ia: dict) -> bool:
    global _telegram_fallo_red
    if not TELEGRAM_TOKEN:
        if not _telegram_fallo_red:
            logger.warning("Token Telegram no configurado.")
            _telegram_fallo_red = True
        return False

    try:
        mensaje = _formatear_mensaje(evento_normalizado, resultado_reglas, resultado_ia)
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": mensaje,
            "parse_mode": "Markdown",
        }
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code == 200:
            if _telegram_fallo_red:
                logger.info("Telegram: conexion restaurada.")
                _telegram_fallo_red = False
            logger.info("Alerta Telegram enviada.")
            return True
        else:
            if not _telegram_fallo_red:
                logger.error("Telegram error %s: %s", resp.status_code, resp.text[:100])
                _telegram_fallo_red = True
            return False
    except requests.exceptions.ConnectionError:
        if not _telegram_fallo_red:
            logger.error("Telegram: sin conexion a api.telegram.org. Verificar red/firewall.")
            _telegram_fallo_red = True
        return False
    except requests.exceptions.Timeout:
        if not _telegram_fallo_red:
            logger.error("Telegram: timeout de conexion.")
            _telegram_fallo_red = True
        return False
    except Exception as e:
        if not _telegram_fallo_red:
            logger.error("Telegram: %s", str(e)[:100])
            _telegram_fallo_red = True
        return False


def enviar_error(mensaje_error: str) -> bool:
    if not TELEGRAM_TOKEN:
        return False
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": f"\U0001f6a8 SIEM Error: {mensaje_error}",
        }
        resp = requests.post(url, json=payload, timeout=10)
        return resp.status_code == 200
    except Exception:
        return False