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
    # Groq (mas rapido primero)
    {"name": "groq",   "base_url": GROQ_BASE_URL,   "api_key": GROQ_API_KEY,   "model": "llama-3.3-70b-versatile",          "timeout": 8},

    # NVIDIA NIM - solo modelos que existen (verificados)
    {"name": "nvidia", "base_url": NVIDIA_BASE_URL, "api_key": NVIDIA_API_KEY, "model": "deepseek-ai/deepseek-v4-flash",     "timeout": 12, "deepseek": True},
    {"name": "nvidia", "base_url": NVIDIA_BASE_URL, "api_key": NVIDIA_API_KEY, "model": "google/gemma-4-31b-it",            "timeout": 12},
    {"name": "nvidia", "base_url": NVIDIA_BASE_URL, "api_key": NVIDIA_API_KEY, "model": "z-ai/glm-5.2",                      "timeout": 15},
    {"name": "nvidia", "base_url": NVIDIA_BASE_URL, "api_key": NVIDIA_API_KEY, "model": "deepseek-ai/deepseek-v4-pro",       "timeout": 15, "deepseek": True},
]

# ============================================================
# Telegram
# ============================================================
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# ============================================================
# Rutas del Sistema
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
# Rutas Evidencias Forenses - Hackathon Operación Huella Digital
# ============================================================
HACKATHON_DEFAULT_DIR = BASE_DIR / "Hackaton" / "Hackaton" / "recursos" / "operacion-huella-digital-evidencias"
EVIDENCIAS_DIR = Path(os.getenv("EVIDENCIAS_DIR", str(HACKATHON_DEFAULT_DIR)))

CSV_PROXY = EVIDENCIAS_DIR / "proxy.csv"
CSV_ENDPOINT = EVIDENCIAS_DIR / "endpoint.csv"
CSV_DNS = EVIDENCIAS_DIR / "dns.csv"
CSV_FIREWALL = EVIDENCIAS_DIR / "firewall.csv"
CSV_AUTHENTICATION = EVIDENCIAS_DIR / "authentication.csv"
PCAP_FILE = EVIDENCIAS_DIR / "suspicious-traffic.pcap"

# ============================================================
# Parámetros del Motor de Correlación Forense
# ============================================================
CORRELATION_WINDOW_PHISHING_EXEC_SEC = 300   # 5 minutos entre descarga y ejecución
BEACONING_TARGET_INTERVAL_SEC = 300          # 5 minutos exactos de balizamiento C2
BEACONING_INTERVAL_TOLERANCE_SEC = 25        # Margen de tolerancia jitter (275s - 325s)
BEACONING_MIN_OCCURRENCES = 3                # Mínimo de balizas periódicas
STAGING_MASS_ACCESS_THRESHOLD = 50           # Umbral de accesos SMB anómalos
EXFILTRATION_VOLUME_THRESHOLD_BYTES = 50 * 1024 * 1024  # 50 MB

# Listas blancas para supresión contextual de falsos positivos (Distractores)
WHITELIST_DOMAINS = (
    "microsoft", "google", "uide.edu.ec", "dropbox",
    "andes.local", "backup.example.net", "updates.example.net"
)
WHITELIST_BACKUP_HOSTS = ("FS01",)
WHITELIST_BACKUP_IPS = ("198.51.100.44",)
WHITELIST_ADMIN_PROCESSES = ("powershell.exe get-service",)

# Privacidad de datos del Hackathon: Modo IA local / desconectada para evitar fuga de evidencias
AI_LOCAL_ONLY = os.getenv("SIEM_AI_LOCAL_ONLY", "false").lower() in ("true", "1", "yes")

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
