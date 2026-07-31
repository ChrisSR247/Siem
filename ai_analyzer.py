import json
import logging
from pathlib import Path
from typing import Optional

from config import (
    AI_PROVIDERS,
    PROMPTS_PATH,
)
from utils import cargar_json, log_coloreado

logger = logging.getLogger(__name__)


def _crear_cliente(provider: dict):
    try:
        from openai import OpenAI
        return OpenAI(
            base_url=provider["base_url"],
            api_key=provider["api_key"],
            timeout=provider["timeout"],
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
    from openai import OpenAI

    errores = []

    for provider in AI_PROVIDERS:
        modelo = provider["model"]
        nombre = provider["name"]
        try:
            extra = {}
            if provider.get("deepseek"):
                extra["extra_body"] = {"chat_template_kwargs": {"thinking": False}}

            cliente = OpenAI(
                base_url=provider["base_url"],
                api_key=provider["api_key"],
                timeout=provider["timeout"],
            )

            response = cliente.chat.completions.create(
                model=modelo,
                messages=[
                    {"role": "system", "content": "Eres un analista de ciberseguridad. Responde solo en JSON valido."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=512,
                **extra,
            )

            texto = response.choices[0].message.content.strip()
            resultado = _parsear_respuesta(texto, modelo)

            if resultado:
                resultado["modelo"] = f"{nombre}:{modelo}"
                resultado["texto_raw"] = texto
                return resultado

            errores.append(f"{nombre}:{modelo} -> respuesta sin JSON valido")

        except Exception as e:
            msg = str(e)[:60]
            # Clasificar error
            if "429" in msg or "rate" in msg.lower():
                errores.append(f"{nombre}:{modelo} -> rate limit")
            elif "404" in msg:
                errores.append(f"{nombre}:{modelo} -> modelo no disponible")
            elif "timed out" in msg.lower() or "timeout" in msg.lower():
                errores.append(f"{nombre}:{modelo} -> timeout")
            elif "529" in msg or "overloaded" in msg.lower():
                errores.append(f"{nombre}:{modelo} -> sobrecargado")
            elif "410" in msg or "gone" in msg.lower():
                errores.append(f"{nombre}:{modelo} -> eliminado")
            else:
                errores.append(f"{nombre}:{modelo} -> {msg[:40]}")
            continue

    # Todos fallaron: resumen limpio
    causas = list(set(e.split(" -> ")[1] for e in errores if " -> " in e))
    causa_str = ", ".join(causas) if causas else "error desconocido"
    log_coloreado("WARNING", f"  IA: Todos los modelos fallaron ({causa_str})")

    return {
        "modelo": "NINGUNO",
        "resumen": "",
        "severidad": "DESCONOCIDO",
        "recomendacion": f"IA no disponible: {causa_str}. Revisar manualmente.",
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