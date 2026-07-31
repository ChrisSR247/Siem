import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def ahora_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ahora_local_str(fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    return datetime.now().strftime(fmt)


def cargar_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def guardar_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def leer_cursor(path: Path) -> int:
    try:
        if path.exists():
            return int(path.read_text(encoding="utf-8").strip() or 0)
    except (ValueError, OSError):
        pass
    return 0


def guardar_cursor(path: Path, valor: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(valor), encoding="utf-8")


def riesgo_a_valor(riesgo: str) -> int:
    levels = {"BAJO": 1, "MEDIO": 2, "ALTO": 3, "CRITICO": 4}
    return levels.get(str(riesgo).upper(), 0)


# Colores para consola (Windows compatible)
class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


def color_string(text: str, color: str) -> str:
    return f"{color}{text}{Colors.RESET}"


def log_coloreado(nivel: str, msg: str) -> None:
    color_map = {
        "DEBUG": Colors.BLUE,
        "INFO": Colors.GREEN,
        "WARNING": Colors.YELLOW,
        "ERROR": Colors.RED,
        "CRITICAL": Colors.MAGENTA,
    }
    c = color_map.get(nivel.upper(), Colors.RESET)
    print(f"{c}[{nivel}]{Colors.RESET} {msg}")


def setup_logging(nombre: str = "siem", nivel: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(nombre)
    logger.setLevel(nivel)
    if not logger.handlers:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter(
            "%(asctime)s  [%(levelname)-8s]  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        logger.addHandler(h)
    return logger