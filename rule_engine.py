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

        es_from_keyword = regla.get("__from_keyword", False)

        # Si la keyword ya definio un riesgo explicito, respetarlo sin override de severidad
        if es_from_keyword:
            return resultado

        # Ajustar riesgo por nivel critico del evento (solo para defaults, no para keywords explicitas)
        niveles_riesgo = {"BAJO": 0, "MEDIO": 1, "ALTO": 2, "CRITICO": 3}

        if fuente == "WAZUH":
            nivel = int(evento_normalizado.get("nivel_original", 0))
            if nivel >= 12:
                nuevo = "CRITICO"
            elif nivel >= 10:
                nuevo = "ALTO"
            else:
                nuevo = resultado["riesgo"]
            if niveles_riesgo.get(nuevo, 0) > niveles_riesgo.get(resultado["riesgo"], 0):
                resultado["riesgo"] = nuevo
                resultado["prioridad"] = "Critica" if nuevo == "CRITICO" else "Alta"

        if fuente == "SURICATA":
            severity = int(evento_normalizado.get("nivel_original", 0))
            if severity >= 4:
                nuevo = "CRITICO"
            elif severity >= 3:
                nuevo = "ALTO"
            else:
                nuevo = resultado["riesgo"]
            if niveles_riesgo.get(nuevo, 0) > niveles_riesgo.get(resultado["riesgo"], 0):
                resultado["riesgo"] = nuevo
                resultado["prioridad"] = "Critica" if nuevo == "CRITICO" else "Alta"

        return resultado

    def _buscar_regla(self, id_regla: str, descripcion: str, fuente: str) -> dict:
        mapa_fuente = self.attack_map.get(fuente, {})
        keywords_map = self.attack_map.get("keywords", {})

        # 1. Buscar por ID exacto en la seccion de la fuente
        if id_regla in mapa_fuente:
            return mapa_fuente[id_regla]

        # 2. Buscar por keyword mas larga primero (mas especifica)
        sorted_kw = sorted(keywords_map.items(), key=lambda x: -len(x[0]))
        best = None
        for kw, info in sorted_kw:
            if kw in descripcion:
                if isinstance(info, dict) and "riesgo" in info:
                    best = dict(info)
                    best["__from_keyword"] = True
                    break
                if isinstance(info, dict) and "map" in info and best is None:
                    target_map = self.attack_map.get(info["map"], {})
                    if info["key"] in target_map:
                        best = target_map[info["key"]]

        if best:
            return best

        # 3. Default
        default_key = "DEFAULT_SURICATA" if "SURICAT" in fuente.upper() else "DEFAULT_WAZUH"
        return mapa_fuente.get(default_key, {})