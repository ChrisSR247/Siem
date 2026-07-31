import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


# ============================================================
# API NVIDIA NIM
# ============================================================
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "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")
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"

# Lista de modelos con failover automático (se prueban en orden)
NVIDIA_MODELS = [
    "nvidia/llama-3.3-nemotron-super-49b-v1",
    "meta/llama-3.3-70b-instruct",
    "deepseek-ai/deepseek-r1",
    "mistralai/mistral-large",
    "qwen/qwen3-235b-a22b",
]

NVIDIA_TIMEOUT = int(os.getenv("NVIDIA_TIMEOUT", "20"))
NVIDIA_MAX_TOKENS = 512
NVIDIA_TEMPERATURE = 0.2

# ============================================================
# Telegram
# ============================================================
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "8702469745:AAGX7W_SDTM6mIbkVrEHodYXSZkA9AJw9HY")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "1862795174")

# ============================================================
# Rutas
# ============================================================
LOG_DIR = BASE_DIR / "logs"
WAZUH_LOG = Path("/var/ossec/logs/alerts/alerts.json")
SURICATA_LOG = Path("/var/log/suricata/eve.json")

DB_DIR = BASE_DIR / "database"
DB_PATH = DB_DIR / "siem.db"

REPORTS_DIR = BASE_DIR / "reports"

MODELS_DIR = BASE_DIR / "models"
ATTACK_MAP_PATH = MODELS_DIR / "attack_map.json"
PROMPTS_PATH = MODELS_DIR / "prompts.json"

# Paths para trackear la última línea leída de cada log
WAZUH_CURSOR = LOG_DIR / ".wazuh_cursor"
SURICATA_CURSOR = LOG_DIR / ".suricata_cursor"

# ============================================================
# Umbrales de alerta
# ============================================================
ALERT_MIN_RISK = "MEDIO"  # Solo se envían alertas de nivel >= MEDIO por Telegram
RISK_LEVELS = {
    "BAJO": 1,
    "MEDIO": 2,
    "ALTO": 3,
    "CRITICO": 4,
}

# ============================================================
# Ciclo principal
# ============================================================
POLL_INTERVAL_SECONDS = 2