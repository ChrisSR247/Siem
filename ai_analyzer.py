import json
import logging
from pathlib import Path
from typing import Optional

from config import (
    NVIDIA_API_KEY,
    NVIDIA_BASE_URL,
    NVIDIA_MODELS,
    NVIDIA_TIMEOUT,
    NVIDIA_MAX_TOKENS,
    NVIDIA_TEMPERATURE,
    PROMPTS_PATH,
)
from utils import cargar_json

logger = logging.getLogger(__name__)


def _crear_cliente():
    try:
        from openai import OpenAI
        return OpenAI(
            base_url=NVIDIA_BASE_URL,
            api_key=NVIDIA_API_KEY,
        )
    except ImportError:
        logger.error("openai no instalado. pip install openai")
        return None


def crear_prompt(tipo: str, evento_normalizado: dict, resultado_reglas: dict) -> str:
    prompts = cargar_json(Path(PROMPTS_PATH))
    plantilla = prompts.get(tipo, prompts.get("general", {}))
    prompt_base = plantilla.get("prompt", prompts["general"]["prompt"])

    datos = {
        "evento": json.dumps(evento_normalizado, indent=2, ensure_ascii=False),
        "reglas": json.dumps(resultado_reglas, indent=2, ensure_ascii=False),
        "raw": json.dumps({"norm": evento_normalizado, "rule": resultado_reglas}, indent=2, ensure_ascii=False),
    }

    # Reemplazo simple de placeholders
    for key, val in datos.items():
        prompt_base = prompt_base.replace("{" + key + "}", val)

    return prompt_base


def consultar_nvidia(prompt: str, modelo_idx: int = 0) -> dict:
    response = None
    ultimo_error = None

    from openai import OpenAI

    for i in range(modelo_idx, len(NVIDIA_MODELS)):
        modelo = NVIDIA_MODELS[i]
        try:
            t = NVIDIA_TIMEOUT
            if "deepseek" in modelo:
                t = 15

            cliente = OpenAI(
                base_url=NVIDIA_BASE_URL,
                api_key=NVIDIA_API_KEY,
                timeout=t,
            )

            extra = {}
            if "deepseek" in modelo and "pro" in modelo:
                extra["extra_body"] = {"chat_template_kwargs": {"thinking": False}}

            response = cliente.chat.completions.create(
                model=modelo,
                messages=[
                    {"role": "system", "content": "Eres un analista de ciberseguridad. Responde solo en JSON valido."},
                    {"role": "user", "content": prompt},
                ],
                temperature=NVIDIA_TEMPERATURE,
                max_tokens=NVIDIA_MAX_TOKENS,
                **extra,
            )

            reasoning = getattr(response.choices[0].message, "reasoning", None) or getattr(response.choices[0].message, "reasoning_content", None)
            if reasoning and logger.isEnabledFor(logging.DEBUG):
                logger.debug("DeepSeek reasoning: %s", reasoning[:200])

            texto = response.choices[0].message.content.strip()
            resultado = _parsear_respuesta(texto, modelo)

            if resultado:
                resultado["modelo"] = modelo
                resultado["texto_raw"] = texto
                return resultado

            logger.warning("Modelo %s devolvio JSON invalido, intentando siguiente...", modelo)

        except Exception as e:
            ultimo_error = str(e)
            logger.warning("Error con modelo CLAVE %s: %s", modelo, e)
            continue

    logger.error("Failover agotado. Todos los modelos fallaron.", "")
    return {
        "modelo": "NINGUNO",
        "resumen": "Error de IA - todos los modelos fallaron",
        "severidad": "DESCONOCIDO",
        "recomendacion": "Revisar configuracion de API NVIDIA",
        "tecnicas_mitre": [],
        "falso_positivo": False,
        "texto_raw": "",
    }


def _parsear_respuesta(texto: str, modelo: str) -> Optional[dict]:
    if not texto:
        return None

    # Intentar parsear como JSON
    try:
        datos = json.loads(texto)
        return {
            "resumen": datos.get("resumen", datos.get("summary", "")),
            "severidad": datos.get("severidad", datos.get("severity", "MEDIO")),
            "recomendacion": datos.get("recomendacion", datos.get(
                "recommendation", "")),
            "tecnicas_mitre": datos.get("tecnicas_mitre", datos.get("techniques", [])),
            "falso_positivo": datos.get("falso_positivo", datos.get("false_positive", False)),
        }
    except json.JSONDecodeError:
        pass

    # Intentar extraer JSON entre llaves
    import re
    match = re.search(r"\{.*\}", texto, re.DOTALL)
    if match:
        try:
            datos = json.loads(match.group())
            return {
                "resumen": datos.get("resumen", datos.get("summary", "")),
                "severidad": datos.get("severidad", datos.get("severity", "MEDIO")),
                "recomendacion": datos.get("recomendacion", datos.get("recommendation", "")),
                "tecnicas_mitre": datos.get("tecnicas_mitre", datos.get("techniques", [])),
                "falso_positivo": datos.get("falso_positivo", datos.get("false_positive", False)),
            }
        except json.JSONDecodeError:
            pass

    # Fallback: usar texto como resumen
    return {
        "resumen": texto[:300],
        "severidad": "MEDIO",
        "recomendacion": "Respuesta no estructurada de la IA. Revisar manualmente.",
        "tecnicas_mitre": [],
        "falso_positivo": False,
    }


def analizar_evento(evento_normalizado: dict, resultado_reglas: dict) -> dict:
    tipo = _determinar_tipo_prompt(evento_normalizado, resultado_reglas)
    prompt = crear_prompt(tipo, evento_normalizado, resultado_reglas)
    return consultar_nvidia(prompt)


def _determinar_tipo_prompt(evento_normalizado: dict, resultado_reglas: dict) -> str:
    descripcion = resultado_reglas.get("ataque", "").lower()
    fuente = evento_normalizado.get("fuente", "").upper()

    if "ssh" in descripcion or "brute force" in descripcion:
        return "ssh"
    if "malware" in descripcion or "virus" in descripcion or "rootkit" in descripcion:
        return "malware"
    if "sql" in descripcion:
        return "sql_injection"
    if fuente == "SURICATA":
        return "suricata"
    if fuente == "WAZUH":
        return "wazuh"
    return "general"