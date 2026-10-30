# AndesCorrelator Engine (ACE) — SIEM & SOAR Forense

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20%7C%20D3FEND-orange.svg)](https://attack.mitre.org/)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)]()

> **Caso de Estudio:** AndesLogística S.A. — *Operación Huella Digital*  
> **Enfoque:** Blue Team, Detección Multifuente, Incident Response & Hardening Empresarial.  
> **Autores:** Christian Salinas & Alddrin Venegas  

---

## 📌 Descripción General

**AndesCorrelator Engine (ACE)** es una plataforma ligera de **SIEM & SOAR** desarrollada para resolver el problema de las islas de información en entornos corporativos. El sistema ingesta, normaliza y correlaciona de forma causal telemetría procedente de múltiples fuentes heterogéneas (**Proxy, Endpoint, DNS, Firewall, Autenticación y capturas de red PCAP**).

En el escenario evaluado, el motor procesa **14,658 eventos** en **menos de 1 segundo**, reconstruyendo la cadena completa de intrusión (*Kill Chain*), calculando el nivel de riesgo global, extrayendo Indicadores de Compromiso (IoCs) y suprimiendo falsos positivos mediante análisis contextual.

---

## 🏗️ Arquitectura del Sistema

```
                      FUENTES DE TELEMETRÍA DIGITAL
    Proxy (HTTP) │ Endpoint (Sysmon) │ DNS │ Firewall │ Auth (AD) │ PCAP
                                 │
                                 ▼
    ┌─────────────────────────────────────────────────────────────┐
    │ 1. INGESTA Y NORMALIZACIÓN (parser.py)                      │
    │    • Normalización temporal con marcas de tiempo ISO-8601   │
    │    • Mapeo universal de entidades (Host, Usuario, IPs)     │
    │    • Lector binario nativo de flujos y sesiones TLS PCAP   │
    └────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
    ┌─────────────────────────────────────────────────────────────┐
    │ 2. MOTOR DE CORRELACIÓN FORENSE (correlator.py)             │
    │    • Regla CR-01: Phishing -> Ejecución Oculta (<= 300s)   │
    │    • Regla CR-02: Detección de Balizamiento C2 (~300s)     │
    │    • Regla CR-03: Reconocimiento Interno LOLBins            │
    │    • Regla CR-04: Recolección Masiva SMB y Compresión Tar   │
    │    • Regla CR-05: Exfiltración de Alto Volumen vía C2       │
    │    • Regla CR-06: Supresión Contextual de Falsos Positivos │
    └────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
    ┌─────────────────────────────────────────────────────────────┐
    │ 3. ANÁLISIS PERICIAL Y PRIVACIDAD AIR-GAPPED (ai_analyzer)  │
    │    • Modo 100% Air-Gapped Local (Cero fuga de telemetría)   │
    │    • Mapeo ontológico contra MITRE ATT&CK & D3FEND          │
    │    • Failover a LLMs (Groq / NVIDIA) para SOC híbrido       │
    └────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
    ┌─────────────────────────────────────────────────────────────┐
    │ 4. RESPUESTA SOAR & REPORTABILIDAD (database / reports)     │
    │    • Base de datos SQLite relacional indexada (siem.db)    │
    │    • Dashboard visual interactivo en HTML                   │
    │    • Informe pericial técnico en Markdown y LaTeX           │
    │    • Suite de contención activa y directivas GPO            │
    └─────────────────────────────────────────────────────────────┘
```

---

## ⚡ Inicio Rápido

### Requisitos
* Python 3.10 o superior.
* Sistema operativo: Windows, Linux o macOS.

### Instalación
```bash
git clone https://github.com/ChrisSR247/Siem.git
cd Siem
pip install -r requirements.txt
```

### Ejecución del Análisis Forense Automatizado
Para procesar las evidencias del incidente, indexar la base de datos y compilar los reportes:
```bash
python app.py
```

### Modo de Monitoreo Continuo (Wazuh / Suricata)
Para ejecutar el SIEM en modo escucha en tiempo real:
```bash
python app.py --live
```

---

## 🔍 Resumen del Incidente Comprobado

* **Host Afectado:** `FIN-PC07` (IP: `10.20.10.47`)
* **Usuario Comprometido:** `dtorres` (Área Financiera)
* **Vector de Infección:** Spear Phishing web a las **10:14:09** mediante descarga de `factura_septiembre.zip` desde `https://facturas-andinas.example`.
* **Ejecución y Evasión:** A las **10:16:22**, ejecución en segundo plano de `update.ps1` con evasión `-WindowStyle Hidden -ExecutionPolicy Bypass`.
* **Comando y Control (C2):** Balizamiento HTTPS recurrente cada **300 segundos exactos (5 minutos)** hacia `cdn-sync-services.example` (`203.0.113.77:443`). Confirmado por 33 paquetes TLS en `suspicious-traffic.pcap`.
* **Reconocimiento:** A las **10:42**, ejecución de LOLBins (`whoami.exe`, `nltest.exe /dclist:andes.local`, `net view`, `net use \\FS01\Finanzas`).
* **Sustracción Masiva:** Entre **11:15 y 11:35**, acceso a **400 archivos contables** confidenciales en `\\FS01\Finanzas\` copiados a la carpeta temporal `staging`.
* **Compresión:** A las **11:41:27**, consolidación con `tar.exe` en `docs_2026.zip` (191.28 MB).
* **Exfiltración:** A las **11:46:13**, transmisión saliente de **188.74 MB** hacia el servidor C2 vía HTTPS en 481 segundos.
* **Falsos Positivos Descartados:**
  1. *Tráfico de 500 MB en FS01 (11:20):* Respaldo programado legítimo hacia `backup.example.net` (`198.51.100.44`).
  2. *PowerShell en IT-PC02:* Monitoreo administrativo de `jparedes` (`Get-Service`) ejecutado cada 7 minutos.
  3. *87 Fallos Event ID 4625:* Errores tipográficos aislados, sin patrón de fuerza bruta.

---

## 🛡️ Suite de Prevención y Hardening (`prevention/`)

El sistema incluye controles defensivos proactivos para mitigar de raíz cada etapa del ataque:

| Archivo | Propósito | Tecnología |
|---|---|---|
| `01_contencion_inmediata_soar.ps1` | Aislamiento de red del host, terminación de procesos maliciosos y cuarentena en <15s. | PowerShell / Host Firewall |
| `02_hardening_gpo_empresarial.ps1` | Directivas GPO: Constrained Language Mode en PowerShell, bloqueo de `%TEMP%` y reglas ASR. | Active Directory GPO |
| `03_reglas_sysmon_prevencion.xml` | Monitoreo granular de procesos ocultos (EID 1), conexiones C2 (EID 3) y archivos ZIP (EID 11). | Sysmon v15 |
| `04_bloqueo_firewall_perimetral.txt` | Reglas de bloqueo listas para desplegar en equipos de borde. | Fortinet, Palo Alto, IPtables |
| `05_playbook_soar_cortex_shuffle.json` | Playbook de respuesta automatizada ante incidentes críticos. | Cortex XSOAR / Shuffle |
| `PLAN_PREVENCION_Y_HARDENING_EMPRESARIAL.md` | Guía de diagnóstico de causa raíz y matriz de controles MITRE D3FEND. | Documentación técnica |

---

## 📁 Estructura del Repositorio

```
Siem/
├── app.py                      # Punto de entrada y orquestador CLI
├── config.py                   # Configuración del entorno y rutas
├── parser.py                   # Ingesta multiformato (CSV, PCAP, Wazuh, Suricata)
├── correlator.py               # Motor de correlación causal y reglas heurísticas
├── rule_engine.py              # Motor de clasificación MITRE ATT&CK
├── event_processor.py          # Procesamiento de eventos en lote y tiempo real
├── preventer.py                # Compilador de la suite de prevención SOAR
├── report_generator.py         # Generador de reportes (HTML, MD, CSV, JSON)
├── ai_analyzer.py              # Evaluador pericial (Modo Local / LLM Failover)
├── database.py                 # Capa de persistencia SQLite
├── requirements.txt            # Dependencias del proyecto
├── .env.example                # Plantilla de variables de entorno
├── .gitignore                  # Exclusiones de Git
│
├── models/                     # Mapeos de ataque y plantillas de análisis
│   ├── attack_map.json
│   └── prompts.json
│
├── prevention/                 # Suite de contención y hardening empresarial
│   ├── 01_contencion_inmediata_soar.ps1
│   ├── 02_hardening_gpo_empresarial.ps1
│   ├── 03_reglas_sysmon_prevencion.xml
│   ├── 04_bloqueo_firewall_perimetral.txt
│   ├── 05_playbook_soar_cortex_shuffle.json
│   └── PLAN_PREVENCION_Y_HARDENING_EMPRESARIAL.md
│
├── reports/                    # Entregables oficiales generados automáticamente
│   ├── dashboard_incidente_INC-2026-1015-01.html
│   ├── informe_forense_INC-2026-1015-01.md
│   ├── iocs_INC-2026-1015-01.json
│   └── timeline_INC-2026-1015-01.csv
│
├── docs/                       # Documentación formal y presentación
│   ├── INFORME_FINAL_HACKATHON.tex   # Informe técnico en LaTeX (XeLaTeX / Arial)
│   ├── compilar_pdf.bat              # Script de compilación local del PDF
│   └── GUIA_DEFENSA_PITCH.md         # Guion de exposición de 3 min y Q&A del jurado
│
└── Hackaton/                   # Recursos y fuentes de evidencia del reto
    └── Hackaton/recursos/operacion-huella-digital-evidencias/
```

---

## 👥 Autores

* **Christian Salinas** — Lead Security Developer / Threat Hunter
* **Alddrin Venegas** — Forensics & Incident Response Specialist

---

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo `LICENSE` para más detalles.
