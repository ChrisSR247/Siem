# FICHA TÉCNICA DE LA SOLUCIÓN
**Reto:** Operación Huella Digital — Investigación y Detección de un Incidente Corporativo  
**Caso:** AndesLogística S.A.  
**Categoría:** Universitarios | **Enfoque:** Blue Team & Incident Response  

---

## 1. Datos Generales del Proyecto
* **Nombre de la Solución:** **AndesCorrelator Engine (ACE)** — *Plataforma Ligera de Correlación Forense Multifuente y Detección Temprana de Exfiltración*
* **Versión:** 1.0 (Prototipo Funcional)
* **Lenguaje y Stack:** Python 3, Motor de Reglas Heurísticas/Sigma, Parser Multiformato (CSV/PCAP), Interfaz CLI y Dashboard Markdown/HTML.

---

## 2. Resumen Ejecutivo del Incidente Analizado
Durante la mañana del 15 de octubre de 2026, la estación de trabajo **FIN-PC07** (`10.20.10.47`) perteneciente al usuario `dtorres` (área Financiera) sufrió un compromiso mediante Spear Phishing a las 10:14:09 (`factura_septiembre.zip`). 

A las 10:16:22 se ejecutó de forma oculta un script PowerShell (`update.ps1`) que estableció persistencia y balizamiento C2 HTTPS cada 5 minutos hacia `cdn-sync-services.example` (`203.0.113.77`). El atacante reconoció el entorno con LOLBins (`whoami`, `nltest`, `net`), sustrajo 400 archivos de nómina, proveedores y presupuestos desde `\\FS01\Finanzas`, los comprimió en `docs_2026.zip` (191.28 MB) mediante `tar.exe` a las 11:41:27, y exfiltró **188.74 MB** a las 11:46:13 vía TCP/443. 

Se descartó exitosamente como distractor (falso positivo) el tráfico de 500 MB de las 11:20:00 entre `FS01` y `198.51.100.44`, al verificarse que correspondía a un respaldo legítimo hacia `backup.example.net`.

---

## 3. Impacto Empresarial y Análisis de Riesgo

| Dimensión | Nivel | Justificación Técnica |
|---|---|---|
| **Confidencialidad** | **Crítico** | 400 hojas de cálculo confidenciales sustraídas que contienen nóminas de empleados, costos de proveedores y presupuestos estratégicos de AndesLogística S.A. |
| **Integridad** | **Medio-Bajo** | No se evidenció alteración de bases de datos ni cifrado de tipo ransomware; el objetivo primordial fue el espionaje corporativo y robo de propiedad intelectual. |
| **Disponibilidad** | **Bajo** | La operación logística y los sistemas de producción (ERP01, DC01) no sufrieron interrupciones operativas. |
| **Riesgo Regulatorio / Legal** | **Alto** | Exposición de datos personales y comerciales protegidos por leyes de protección de datos personales y secreto empresarial. |

---

## 4. Descripción de la Solución Propuesta: AndesCorrelator Engine (ACE)

### 4.1. Problema que Resuelve
Actualmente, AndesLogística S.A. analiza logs de manera aislada y manual. Esto impidió que el equipo de seguridad detectara la correlación causal entre:
1. La descarga web por el proxy a las 10:14.
2. El proceso oculto en el endpoint a las 10:16.
3. El balizamiento DNS/Firewall a las 10:17.
4. El acceso masivo a archivos en el File Server a las 11:31.
5. El pico anómalo de subida en el firewall a las 11:46.

### 4.2. Arquitectura de la Solución
**AndesCorrelator Engine (ACE)** implementa un pipeline automatizado de 4 capas:

```
[Fuentes de Datos] -> [Normalizador & Parser] -> [Motor de Correlación & Reglas] -> [Alertas, Timeline & IoCs]
 - proxy.csv            - Estandarización ISO8601  - Regla R1: Phishing -> Hidden Exec  - Score de Riesgo (0-100)
 - endpoint.csv         - Normalización de IPs     - Regla R2: C2 Periodic Beaconing    - Línea de Tiempo Unificada
 - dns.csv              - Vinculación Host-Usuario - Regla R3: Mass File Access SMB     - Exportación JSON / STIX
 - firewall.csv                                    - Regla R4: High Outbound Traffic
 - auth / pcap                                     - Regla R5: Descarte Legítimo (FP)
```

### 4.3. Reglas de Detección Implementadas

1. **ACE-R01 (Spear Phishing to Script Execution):**
   * Correlaciona descarga de archivo comprimido (`.zip`, `.iso`, `.rar`) por un host en `proxy.csv` con la creación de un proceso de scripting (`powershell.exe`, `cmd.exe`, `wscript.exe`) en `endpoint.csv` en una ventana temporal `<= 5 minutos`.
2. **ACE-R02 (C2 Beaconing Detection):**
   * Analiza intervalos de consulta DNS y conexiones salientes en `firewall.csv`. Si un host presenta `>= 3 conexiones` a un mismo destino externo en intervalos periódicos con desviación estándar `< 10 segundos`, dispara alerta de Comando y Control.
3. **ACE-R03 (Mass File Staging):**
   * Dispara alerta si un usuario/host genera `>= 50 eventos FILE_ACCESS` en recursos compartidos en menos de 5 minutos, seguido por ejecución de herramientas de empaquetado (`tar.exe`, `7z.exe`, `zip.exe`).
4. **ACE-R04 (Volume Anomaly with Unknown External Destination):**
   * Detecta flujos salientes donde `bytes_sent > 50 MB` hacia destinos que no figuren en la lista blanca de proveedores de confianza (ej. Office365, Google, Backup oficial).
5. **ACE-R05 (White-list & Context Awareness):**
   * Aplica contexto de infraestructura para suprimir falsos positivos conocidos (como las transferencias de respaldo de `FS01` a `backup.example.net` o tareas de administración de `IT-PC02`).

---

## 5. Criterios de Evaluación y Atributos de Ingeniería

### 5.1. Innovación
* **Correlación Temporal Multicapa:** En lugar de limitarse a alertas estáticas de EDR o Firewall, ACE une la cadena completa de muerte (*Kill Chain*), reduciendo el tiempo de investigación manual de horas a segundos.
* **Algoritmo de Detección de Balizas (Beaconing):** Identifica patrones matemáticos de periodicidad sin necesidad de descifrar tráfico TLS.

### 5.2. Viabilidad Técnica
* Construido sobre librerías estándar y tecnologías abiertas de bajo consumo de memoria.
* Compatible con formatos nativos de logs de Windows (Event Logs/Sysmon), proxies Squid/BlueCoat y firewalls perimetrales (Palo Alto, Fortinet, pfSense).

### 5.3. Seguridad de la Solución
* **Procesamiento Local Seguro:** El análisis se ejecuta 100% en infraestructura interna, sin enviar telemetría ni evidencias sensibles a nubes de terceros o modelos externos, cumpliendo estrictamente con la confidencialidad corporativa.
* **Integridad Forense:** Modo de solo lectura sobre las evidencias de entrada; no altera metadatos ni timestamps originales.

### 5.4. Escalabilidad
* Capacidad de ingesta distribuida mediante colas de mensajes (Kafka/RabbitMQ) o soporte para bases de datos documentales/series temporales (Elasticsearch / ClickHouse) en despliegues corporativos a gran escala.
