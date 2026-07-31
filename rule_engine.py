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
        if id_regla in self.attack_map:
            return self.attack_map[id_regla]

        # Búsqueda por palabra clave en descripción
        keywords = {
            "brute force": "5710",
            "fuerza bruta": "5710",
            "nmap": "2001219",
            "sql injection": "2012357",
            "sql inject": "2012357",
            "malware": "2012311",
            "virus": "2012311",
            "rootkit": "1002",
            "exploit": "2019504",
            "path traversal": "2010937",
            "port scan": "2012645",
            "escaneo": "2012645",
        }

        for kw, rule_id in keywords.items():
            if kw in descripcion and rule_id in self.attack_map:
                return self.attack_map[rule_id]

        default_key = "DEFAULT_SURICATA" if fuente == "SURICATA" else "DEFAULT_WAZUH"
        return self.attack_map.get(default_key, {})