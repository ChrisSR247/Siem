import json
from pathlib import Path
from typing import Dict, Optional

from config import ATTACK_MAP_PATH
from utils import cargar_json


class RuleEngine:
    def __init__(self):
        self.attack_map = self._cargar_attack_map()

    def _cargar_attack_map(self) -> dict:
        return cargar_json(Path(ATTACK_MAP_PATH))

    def recargar_reglas(self) -> None:
        self.attack_map = self._cargar_attack_map()

    def analizar(self, evento_normalizado: dict) -> dict:
        fuente = evento_normalizado.get("fuente", "")
        id_regla = str(evento_normalizado.get("id_registro", ""))
        descripcion = evento_normalizado.get("descripcion", "").lower()

        regla = self._buscar_regla(id_regla, descripcion, fuente)

        resultado = {
            "ataque": regla.get("ataque", "Evento Desconocido"),
            "riesgo": regla.get("riesgo", "MEDIO"),
            "mitre": regla.get("mitre", ""),
            "owasp": regla.get("owasp"),
            "cvss": regla.get("cvss", 5.0),
            "prioridad": regla.get("prioridad", "Media"),
            "recomendacion": regla.get("recomendacion", "Investigar manualmente."),
        }

        # Ajustar riesgo por nivel Wazuh
        if fuente == "WAZUH":
            nivel = int(evento_normalizado.get("nivel_original", 0))
            if nivel >= 12:
                resultado["riesgo"] = "CRITICO"
                resultado["prioridad"] = "Critica"
            elif nivel >= 10:
                resultado["riesgo"] = "ALTO"
                resultado["prioridad"] = "Alta"

        # Ajustar riesgo por severidad Suricata
        if fuente == "SURICATA":
            severity = int(evento_normalizado.get("nivel_original", 0))
            if severity >= 4:
                resultado["riesgo"] = "CRITICO"
                resultado["prioridad"] = "Critica"
            elif severity >= 3:
                resultado["riesgo"] = "ALTO"
                resultado["prioridad"] = "Alta"

        return resultado

    def _buscar_regla(self, id_regla: str, descripcion: str, fuente: str) -> dict:
        mapa_fuente = self.attack_map.get(fuente, {})
        keywords_map = self.attack_map.get("keywords", {})

        # 1. Buscar por ID exacto en la seccion de la fuente
        if id_regla in mapa_fuente:
            return mapa_fuente[id_regla]

        # 2. Buscar por palabra clave en descripcion
        for kw, info in keywords_map.items():
            if kw in descripcion:
                if isinstance(info, dict) and "riesgo" in info:
                    return info
                if isinstance(info, dict) and "map" in info:
                    target_map = self.attack_map.get(info["map"], {})
                    if info["key"] in target_map:
                        return target_map[info["key"]]

        # 3. Default
        default_key = "DEFAULT_SURICATA" if "SURICAT" in fuente.upper() else "DEFAULT_WAZUH"
        return mapa_fuente.get(default_key, {})