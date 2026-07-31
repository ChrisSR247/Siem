import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

#holaaaaaaaaaaaaaaa
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
    # Groq (mas rapido primero)
    {"name": "groq",   "base_url": GROQ_BASE_URL,   "api_key": GROQ_API_KEY,   "model": "llama-3.3-70b-versatile",          "timeout": 8},

    # NVIDIA NIM - ordenados del mas ligero/rapido al mas pesado
    {"name": "nvidia", "base_url": NVIDIA_BASE_URL, "api_key": NVIDIA_API_KEY, "model": "inference/laguna-xs-2.1",             "timeout": 10},
    {"name": "nvidia", "base_url": NVIDIA_BASE_URL, "api_key": NVIDIA_API_KEY, "model": "z-ai/inkling",                       "timeout": 10},
    {"name": "nvidia", "base_url": NVIDIA_BASE_URL, "api_key": NVIDIA_API_KEY, "model": "google/gemma-4-31b-it",            "timeout": 10},
    {"name": "nvidia", "base_url": NVIDIA_BASE_URL, "api_key": NVIDIA_API_KEY, "model": "mistralai/mistral-medium-3.5",      "timeout": 10},
    {"name": "nvidia", "base_url": NVIDIA_BASE_URL, "api_key": NVIDIA_API_KEY, "model": "deepseek-ai/deepseek-v4-flash",     "timeout": 12, "deepseek": True},
    {"name": "nvidia", "base_url": NVIDIA_BASE_URL, "api_key": NVIDIA_API_KEY, "model": "deepseek-ai/deepseek-v4-pro",       "timeout": 12, "deepseek": True},
    {"name": "nvidia", "base_url": NVIDIA_BASE_URL, "api_key": NVIDIA_API_KEY, "model": "qwen/qwen3.5-122b-a10b",           "timeout": 15},
    {"name": "nvidia", "base_url": NVIDIA_BASE_URL, "api_key": NVIDIA_API_KEY, "model": "z-ai/glm-5.2",                      "timeout": 15},
    {"name": "nvidia", "base_url": NVIDIA_BASE_URL, "api_key": NVIDIA_API_KEY, "model": "minimax/minimax-m3",                "timeout": 15},
    {"name": "nvidia", "base_url": NVIDIA_BASE_URL, "api_key": NVIDIA_API_KEY, "model": "nvidia/nemotron-3-ultra-550b-a55b","timeout": 20},
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
ALERT_MIN_RISK = "ALTO"  # Solo se envían alertas de nivel >= ALTO por Telegram
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