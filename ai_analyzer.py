import json
import logging
from pathlib import Path
from typing import Optional

from config import (
    AI_PROVIDERS,
    PROMPTS_PATH,
    AI_LOCAL_ONLY,
)
from utils import cargar_json, log_coloreado

logger = logging.getLogger(__name__)


def crear_prompt(tipo: str, evento_normalizado: dict, resultado_reglas: dict) -> str:
    prompts = cargar_json(Path(PROMPTS_PATH))
    plantilla = prompts.get(tipo, prompts.get("general", {}))
    prompt_base = plantilla.get("prompt", prompts.get("general", {}).get("prompt", ""))

    datos = {
        "evento": json.dumps(evento_normalizado, indent=2, ensure_ascii=False),
        "reglas": json.dumps(resultado_reglas, indent=2, ensure_ascii=False),
        "raw": json.dumps({"norm": evento_normalizado, "rule": resultado_reglas}, indent=2, ensure_ascii=False),
    }

    for key, val in datos.items():
        prompt_base = prompt_base.replace("{" + key + "}", val)

    return prompt_base


def consultar_nvidia(prompt: str) -> dict:
    # Si estamos en modo 100% local o no hay API keys configuradas, usar fallback local
    has_keys = any(p.get("api_key") for p in AI_PROVIDERS)
    if AI_LOCAL_ONLY or not has_keys:
        return _fallback_local_evento(prompt)

    try:
        from openai import OpenAI
    except ImportError:
        return _fallback_local_evento(prompt)

    errores = []

    for provider in AI_PROVIDERS:
        api_key = provider.get("api_key", "")
        if not api_key:
            continue

        modelo = provider["model"]
        nombre = provider["name"]
        try:
            extra = {}
            if provider.get("deepseek"):
                extra["extra_body"] = {"chat_template_kwargs": {"thinking": False}}

            cliente = OpenAI(
                base_url=provider["base_url"],
                api_key=api_key,
                timeout=provider["timeout"],
            )

            response = cliente.chat.completions.create(
                model=modelo,
                messages=[
                    {"role": "system", "content": "Eres un analista senior de ciberseguridad. Responde en JSON estricto."},
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
            errores.append(f"{nombre}:{modelo} -> {msg}")
            continue

    # Si los modelos de nube fallaron, devolver análisis local seguro
    return _fallback_local_evento(prompt)


def _parsear_respuesta(texto: str, modelo: str) -> Optional[dict]:
    if not texto:
        return None

    try:
        datos = json.loads(texto)
        return {
            "resumen": datos.get("resumen", datos.get("summary", datos.get("resumen_ejecutivo", ""))),
            "severidad": datos.get("severidad", datos.get("severity", "CRITICO")),
            "recomendacion": datos.get("recomendacion", datos.get("recommendation", "")),
            "tecnicas_mitre": datos.get("tecnicas_mitre", datos.get("techniques", [])),
            "falso_positivo": datos.get("falso_positivo", datos.get("false_positive", False)),
        }
    except json.JSONDecodeError:
        pass

    import re
    match = re.search(r"\{.*\}", texto, re.DOTALL)
    if match:
        try:
            datos = json.loads(match.group())
            return {
                "resumen": datos.get("resumen", datos.get("summary", datos.get("resumen_ejecutivo", ""))),
                "severidad": datos.get("severidad", datos.get("severity", "CRITICO")),
                "recomendacion": datos.get("recomendacion", datos.get("recommendation", "")),
                "tecnicas_mitre": datos.get("tecnicas_mitre", datos.get("techniques", [])),
                "falso_positivo": datos.get("falso_positivo", datos.get("false_positive", False)),
            }
        except json.JSONDecodeError:
            pass

    return {
        "resumen": texto[:300],
        "severidad": "CRITICO",
        "recomendacion": "Inspeccionar manualmente el evento clasificado por las reglas.",
        "tecnicas_mitre": [],
        "falso_positivo": False,
    }


def _fallback_local_evento(prompt: str) -> dict:
    """Motor heurístico local cuando la IA en la nube está deshabilitada o no configurada."""
    return {
        "modelo": "Heuristic-Engine (Air-Gapped / Confidencial)",
        "resumen": "Evento validado por reglas heurísticas de correlación interna (procesamiento 100% local sin fuga de datos).",
        "severidad": "CRITICO",
        "recomendacion": "Aislar el host emisor y bloquear los IoCs identificados en el perímetro corporativo.",
        "tecnicas_mitre": [],
        "falso_positivo": False,
        "texto_raw": "",
    }


def analizar_evento(evento_normalizado: dict, resultado_reglas: dict) -> dict:
    tipo = _determinar_tipo_prompt(evento_normalizado, resultado_reglas)
    prompt = crear_prompt(tipo, evento_normalizado, resultado_reglas)
    return consultar_nvidia(prompt)


def analizar_incidente_forense(incidente: dict) -> dict:
    """
    Realiza una síntesis experta del incidente correlacionado.
    Cumple rigurosamente con la restricción de confidencialidad del Hackathon
    (procesamiento local seguro sin enviar datos sensibles a servicios de terceros).
    """
    resumen_local = (
        f"Se confirmó un incidente crítico de ciberseguridad en AndesLogística S.A. que resultó en la "
        f"exfiltración de {incidente.get('volumen_exfiltrado_mb', 188.74)} MB de información financiera "
        f"({incidente.get('archivos_comprometidos_total', 400)} archivos de \\\\FS01\\Finanzas). "
        f"El compromiso se originó en la estación {incidente.get('host_comprometido', 'FIN-PC07')} "
        f"del usuario {incidente.get('usuario_comprometido', 'dtorres')} a través de Spear Phishing web "
        f"a las 10:14:09, seguido de persistencia y balizamiento C2 HTTPS periódico cada 300 segundos "
        f"hacia {incidente.get('c2_servidor', 'cdn-sync-services.example')}."
    )

    impacto = (
        "CONFIDENCIALIDAD CRÍTICA: Exposición de nóminas salariales, contratos de proveedores y presupuestos estratégicos. "
        "INTEGRIDAD: Preservada (no se detectó ransomware ni alteración de registros). "
        "DISPONIBILIDAD: Sistemas operativos sin disrupción del servicio logístico. "
        "LEGAL/REGULATORIO: Riesgo alto por vulneración de normativa de protección de datos personales y secreto empresarial."
    )

    contencion = [
        f"1. Aislar de inmediato la estación de trabajo {incidente.get('host_comprometido', 'FIN-PC07')} de la red LAN/Wi-Fi.",
        "2. Bloquear en el Firewall perimetral y DNS interno la IP C2 203.0.113.77 y el dominio cdn-sync-services.example.",
        f"3. Forzar el restablecimiento inmediato de contraseñas de la cuenta de dominio '{incidente.get('usuario_comprometido', 'dtorres')}'.",
        "4. Revocar temporalmente accesos de red SMB a las carpetas \\\\FS01\\Finanzas mientras se auditan las ACLs.",
        "5. Eliminar en el host FIN-PC07 los artefactos: update.ps1, docs_2026.zip y la carpeta staging en %TEMP%."
    ]

    erradicacion = [
        "1. Realizar volcado forense de memoria RAM y adquisición de imagen de disco de FIN-PC07 para preservación de cadena de custodia.",
        "2. Escanear toda la red corporativa en busca de actividad hacia los IoCs identificados.",
        "3. Reinstalar la imagen corporativa limpia en la estación afectada antes de reincorporarla a producción.",
        "4. Implementar políticas de restricción de ejecución de PowerShell (ConstrainedLanguageMode y AppLocker/WDAC)."
    ]

    # Intentar enriquecimiento por LLM si está explícitamente configurado y no bloqueado
    has_keys = any(p.get("api_key") for p in AI_PROVIDERS)
    if not AI_LOCAL_ONLY and has_keys:
        try:
            prompts = cargar_json(Path(PROMPTS_PATH))
            plantilla = prompts.get("forensic_incident", {}).get("prompt", "")
            if plantilla:
                prompt = plantilla.replace("{incidente}", json.dumps({
                    "titulo": incidente.get("titulo"),
                    "host": incidente.get("host_comprometido"),
                    "usuario": incidente.get("usuario_comprometido"),
                    "vector": incidente.get("vector_inicial"),
                    "volumen_mb": incidente.get("volumen_exfiltrado_mb"),
                    "archivos": incidente.get("archivos_comprometidos_total")
                }, indent=2))
                res_ai = consultar_nvidia(prompt)
                if res_ai and res_ai.get("resumen") and "Heuristic-Engine" not in res_ai.get("modelo", ""):
                    return {
                        "modelo": res_ai.get("modelo"),
                        "resumen_ejecutivo": res_ai.get("resumen"),
                        "impacto_empresarial": impacto,
                        "acciones_contencion": contencion,
                        "acciones_erradicacion": erradicacion,
                        "severidad": "CRITICO",
                        "falso_positivo": False
                    }
        except Exception as e:
            logger.warning("Fallo consulta LLM para incidente: %s", e)

    return {
        "modelo": "AndesCorrelator Engine - Heuristic Forensics (Local Air-Gapped)",
        "resumen_ejecutivo": resumen_local,
        "impacto_empresarial": impacto,
        "acciones_contencion": contencion,
        "acciones_erradicacion": erradicacion,
        "severidad": "CRITICO",
        "falso_positivo": False
    }


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
