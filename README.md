# 🛡️ AndesCorrelator Engine (ACE) — SIEM Inteligente Multifuente
**Reto:** Operación Huella Digital — Investigación y Detección de un Incidente Corporativo  
**Organización:** AndesLogística S.A.  
**Categoría:** Blue Team & Incident Response | SIEM & Correlación de Ciberamenazas  

---

## 📌 Descripción del Proyecto

**AndesCorrelator Engine (ACE)** es una plataforma de **SIEM Inteligente y Correlación Forense Multifuente** diseñada específicamente para resolver el desafío de ciberseguridad corporativo de **AndesLogística S.A.**

Frente a la limitación histórica de analizar logs de forma aislada y manual, el sistema implementa un pipeline unificado de ingesta, normalización, correlación temporal de eventos y evaluación contextual de riesgo. El sistema analiza automáticamente **14,658 eventos** distribuidos en 5 fuentes CSV heterogéneas (`proxy`, `endpoint`, `dns`, `firewall`, `authentication`) y una captura de red `suspicious-traffic.pcap` en **menos de 1 segundo**, reconstruyendo la cadena completa del ataque (*Kill Chain*) y descartando distractores y falsos positivos.

---

## 🚀 Inicio Rápido (Modo de Uso)

### 1. Requisitos Previos
* Python 3.10 o superior (compatible con Windows, Linux y macOS).
* Dependencias instaladas:
  ```bash
  pip install -r requirements.txt
  ```

### 2. Ejecutar la Correlación Forense Automatizada
Para procesar las evidencias del reto y generar los entregables oficiales:
```bash
python app.py
```
*(O de manera explícita: `python app.py --analizar-evidencias`)*

### 3. Modo de Monitoreo en Tiempo Real (Wazuh / Suricata)
Para ejecutar el SIEM en modo escucha continua para entornos operativos:
```bash
python app.py --live
```

---

## 🏗️ Arquitectura de la Solución

```
   ┌─────────────────────────────────────────────────────────────┐
   │                FUENTES DE EVIDENCIA DIGITAL                 │
   │  Proxy.csv │ Endpoint.csv │ DNS.csv │ Firewall.csv │ Auth  │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
                                  ▼
   ┌─────────────────────────────────────────────────────────────┐
   │ 1. PARSER & NORMALIZADOR MULTIFUENTE (parser.py)           │
   │    • Estandarización ISO-8601                              │
   │    • Mapeo Unificado (Host, Usuario, IPs, Puertos, Eventos) │
   │    • Analizador Binario de Tráfico TLS PCAP                 │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
                                  ▼
   ┌─────────────────────────────────────────────────────────────┐
   │ 2. MOTOR DE CORRELACIÓN FORENSE ACE (correlator.py)         │
   │    • Regla CR-01: Spear Phishing -> Ejecución Oculta        │
   │    • Regla CR-02: Balizamiento C2 Periódico (Beaconing)     │
   │    • Regla CR-03: Reconocimiento Interno (LOLBins)          │
   │    • Regla CR-04: Staging Masivo SMB y Compresión Tar       │
   │    • Regla CR-05: Exfiltración Volumétrica vía C2           │
   │    • Regla CR-06: Supresión Contextual de Falsos Positivos │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
                                  ▼
   ┌─────────────────────────────────────────────────────────────┐
   │ 3. EVALUADOR DE RIESGO & ANÁLISIS DE INCIDENTES (AI/Local)  │
   │    • ontology mapping bajo MITRE ATT&CK                    │
   │    • Procesamiento local Air-Gapped (100% Confidencialidad) │
   │    • Failover a LLMs (Groq / NVIDIA) si se habilita        │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
                                  ▼
   ┌─────────────────────────────────────────────────────────────┐
   │ 4. PERSISTENCIA & ENTREGABLES (database.py / reports)       │
   │    • Base de Datos SQLite (Eventos, Incidentes, IoCs)       │
   │    • Dashboard Interactivo HTML                             │
   │    • Informe Forense Técnico en Markdown                    │
   │    • Exportación de IoCs (JSON) y Línea de Tiempo (CSV)     │
   └─────────────────────────────────────────────────────────────┘
```

---

## 🔍 Resumen del Incidente Comprobado (Veredicto Forense)

* **Estación Afectada:** `FIN-PC07` (IP: `10.20.10.47`)
* **Usuario Comprometido:** `dtorres` (Departamento Financiero)
* **Vector de Acceso Inicial:** Spear Phishing web a las **10:14:09**, descarga del señuelo `factura_septiembre.zip` desde `https://facturas-andinas.example`.
* **Ejecución y Evasión:** A las **10:16:22**, ejecución en segundo plano y con bypass de directivas (`-WindowStyle Hidden -ExecutionPolicy Bypass`) del script `update.ps1` en `%TEMP%`.
* **Comando y Control (C2):** Balizamiento HTTPS recurrente cada **300 segundos exactos (5 minutos)** hacia `cdn-sync-services.example` (`203.0.113.77:443`). Confirmado por 33 paquetes TLS en `suspicious-traffic.pcap`.
* **Descubrimiento Interno:** A las **10:42**, ejecución secuencial de utilitarios nativos LOLBins (`whoami.exe`, `nltest.exe /dclist:andes.local`, `net.exe net view`, `net use \\FS01\Finanzas`).
* **Recolección Masiva:** Entre **11:15 y 11:35**, acceso y copia de **400 archivos contables** confidenciales desde `\\FS01\Finanzas\` (carpetas de Nómina, Proveedores, Presupuestos y Reportes) hacia la carpeta local `staging`.
* **Empaquetado:** A las **11:41:27**, consolidación mediante `tar.exe` generando el contenedor `C:\Users\dtorres\AppData\Local\Temp\docs_2026.zip` (191.28 MB).
* **Exfiltración de Datos:** A las **11:46:13**, transmisión de **188.74 MB** hacia el servidor C2 `203.0.113.77:443` durante 481 segundos (~8 minutos).
* **Falsos Positivos Descartados:**
  1. *Tráfico de 500 MB en FS01:* Respaldo rutinario programado del servidor de archivos a `backup.example.net` (`198.51.100.44`).
  2. *PowerShell en IT-PC02:* Monitoreo administrativo recurrente de servicios por `jparedes`.
  3. *Eventos 4625:* Errores normales de digitación distribuidos a lo largo del día.

---

## 📊 Matriz de Cobertura MITRE ATT&CK

| Táctica | ID Técnica | Nombre | Evidencia Correlacionada |
|---|---|---|---|
| **Acceso Inicial** | `T1566.002` | Spearphishing Link | `proxy.csv` (10:14:09) |
| **Ejecución** | `T1059.001` | PowerShell Scripting | `endpoint.csv` (10:16:22) |
| **Evasión de Defensas** | `T1564.003` | Hidden Window & Bypass | `endpoint.csv` (10:16:22) |
| **Comando y Control** | `T1071.001` | Web Protocols (HTTPS Beaconing) | `dns.csv` / `firewall.csv` / `pcap` (10:17+) |
| **Descubrimiento** | `T1033` | System Owner Discovery | `endpoint.csv` (whoami - 10:42:03) |
| **Descubrimiento** | `T1482` | Domain Trust Discovery | `endpoint.csv` (nltest - 10:42:19) |
| **Descubrimiento** | `T1135` | Network Share Discovery | `endpoint.csv` (net view/use - 10:42:51) |
| **Recolección** | `T1039` | Data from Network Shared Drive | `endpoint.csv` (400 archivos SMB) |
| **Recolección** | `T1560.001` | Archive via Utility | `endpoint.csv` (tar.exe -> docs_2026.zip) |
| **Exfiltración** | `T1041` | Exfiltration Over C2 Channel | `firewall.csv` (188.74 MB a 203.0.113.77) |

---

## 📁 Entregables Generados por la Solución

Al ejecutar la herramienta, se generan automáticamente en la carpeta `reports/`:
* 🌐 `dashboard_incidente_INC-2026-1015-01.html`: Dashboard visual e interactivo listo para imprimir en PDF o proyectar en pantalla completa.
* 📄 `informe_forense_INC-2026-1015-01.md`: Informe técnico forense exhaustivo según los estándares de Incident Response.
* 📦 `iocs_INC-2026-1015-01.json`: Exportación de IoCs para integración directa con firewalls y EDRs.
* ⏱️ `timeline_INC-2026-1015-01.csv`: Línea de tiempo estructurada para auditoría forense.
* 💾 `database/siem.db`: Base de datos relacional SQLite con todos los registros y relaciones del incidente.

---

## 🏆 Cumplimiento de Criterios de Evaluación (100 Puntos)

* **Comprensión del problema (10 pts):** Identificación exacta del alcance, vector y datos sustraídos de AndesLogística S.A.
* **Innovación (20 pts):** Motor de correlación temporal probabilístico capaz de unir la Kill Chain completa a través de 5 fuentes independientes y suprimir ruido operativo.
* **Viabilidad técnica (20 pts):** Código Python 3 optimizado, rápido (<1s para 14k eventos), sin dependencias complejas y compatible con Windows/Linux.
* **Impacto empresarial (15 pts):** Reducción de tiempos de investigación de horas a segundos y mitigación de multas regulatorias de protección de datos.
* **Seguridad de la solución (15 pts):** Modo local *Air-Gapped* que garantiza cero fuga de telemetría o evidencias hacia servicios de terceros (cumplimiento estricto de la regla 12 del Hackathon).
* **Escalabilidad (10 pts):** Arquitectura modular desacoplada basada en generadores y base de datos indexada.
* **Calidad del pitch y documentación (10 pts):** Entregables listos, guion de 3 minutos e informe de auditoría generado automáticamente.

