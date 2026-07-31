import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


# ============================================================
# API NVIDIA NIM
# ============================================================
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "")
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"

# ============================================================
# API Groq
# ============================================================
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_BASE_URL = "https://api.groq.com/openai/v1"

# ============================================================
# Proveedores y modelos con failover
# ============================================================
AI_PROVIDERS = [
    {"name": "nvidia", "base_url": NVIDIA_BASE_URL, "api_key": NVIDIA_API_KEY, "model": "nvidia/llama-3.3-nemotron-super-49b-v1", "timeout": 10},
    {"name": "groq",   "base_url": GROQ_BASE_URL,   "api_key": GROQ_API_KEY,   "model": "llama-3.3-70b-versatile",          "timeout": 8},
    {"name": "nvidia", "base_url": NVIDIA_BASE_URL, "api_key": NVIDIA_API_KEY, "model": "meta/llama-3.3-70b-instruct", "timeout": 10},
    {"name": "nvidia", "base_url": NVIDIA_BASE_URL, "api_key": NVIDIA_API_KEY, "model": "deepseek-ai/deepseek-v4-flash", "timeout": 12, "deepseek": True},
    {"name": "nvidia", "base_url": NVIDIA_BASE_URL, "api_key": NVIDIA_API_KEY, "model": "deepseek-ai/deepseek-v4-pro", "timeout": 12, "deepseek": True},
]

# ============================================================
# Telegram
# ============================================================
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

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