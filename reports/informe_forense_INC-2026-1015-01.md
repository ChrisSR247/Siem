# INFORME DE INVESTIGACIÓN FORENSE Y RESPUESTA A INCIDENTES
**Caso:** Operación Huella Digital: Exfiltración Dirigida de Información Financiera
**Organización Afectada:** AndesLogística S.A.
**Fecha del Incidente:** 2026-10-15 | **ID Incidente:** `INC-2026-1015-01`
**Nivel de Severidad Global:** **CRITICO** (Score: 98/100)

---

## 1. Resumen Ejecutivo del Incidente
Se confirmó un incidente crítico de ciberseguridad en AndesLogística S.A. que resultó en la exfiltración de 188.74 MB de información financiera (400 archivos de \\FS01\Finanzas). El compromiso se originó en la estación FIN-PC07 del usuario dtorres a través de Spear Phishing web a las 10:14:09, seguido de persistencia y balizamiento C2 HTTPS periódico cada 300 segundos hacia cdn-sync-services.example (203.0.113.77:443).

### 🎯 Resumen de Activos Comprometidos
- **Estación de Trabajo:** `FIN-PC07` (IP: `10.20.10.47`)
- **Usuario Comprometido:** `dtorres` (Área: Finanzas)
- **Vector de Infección Inicial:** Spear Phishing Web (factura_septiembre.zip descargado de facturas-andinas.example a las 10:14:09)
- **Infraestructura de Comando y Control (C2):** `cdn-sync-services.example (203.0.113.77:443)`
- **Frecuencia de Balizamiento (Beaconing):** 300 segundos (5 minutos exactos)
- **Datos Comprometidos:** 400 archivos confidenciales (\\FS01\Finanzas\ (Nomina, Presupuestos, Proveedores, Reportes))
- **Volumen Total Exfiltrado:** **188.74 MB** (188,743,680 bytes)

---

## 2. Reconstrucción Cronológica del Ataque (Kill Chain)

| Hora (UTC) | Fase del Ataque | Fuente | Host / Usuario | Detalle Técnico del Evento | Técnica MITRE |
|---|---|---|---|---|---|
| `2026-10-15 10:14:09` | **Fase 1: Acceso Inicial (Spear Phishing)** | `PROXY` | FIN-PC07 (dtorres) | Descarga de archivo señuelo 'https://facturas-andinas.example/download/factura_septiembre.zip' | `T1566.002` |
| `2026-10-15 10:16:22` | **Fase 2: Ejecución y Evasión de Defensas** | `ENDPOINT` | FIN-PC07 (dtorres) | Ejecución de payload oculto con bypass: powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Users\dtorres\AppData\Local\Temp\update.ps1 | `T1059.001 / T1564.003` |
| `2026-10-15 10:17:06` | **Fase 3: Comando y Control (C2)** | `FIREWALL / DNS` | FIN-PC07 (dtorres) | Inicio de balizamiento C2 HTTPS cada 5 minutos hacia 'cdn-sync-services.example' (203.0.113.77:443) | `T1071.001` |
| `2026-10-15 10:42:03` | **Fase 4: Reconocimiento Interno (Discovery)** | `ENDPOINT` | FIN-PC07 (dtorres) | Reconocimiento de usuario, dominio y carpetas compartidas (4 comandos LOLBins ejecutados) | `T1033 / T1482 / T1135` |
| `2026-10-15 11:15:04` | **Fase 5: Recolección y Staging** | `ENDPOINT` | FIN-PC07 (dtorres) | Lectura masiva de 400 archivos contables desde '\\FS01\Finanzas' hacia directorio temporal | `T1039` |
| `2026-10-15 11:41:27` | **Fase 5: Compresión Local de Datos** | `ENDPOINT` | FIN-PC07 (dtorres) | Ejecución de tar.exe para compresión en contenedor ZIP (C:\Users\dtorres\AppData\Local\Temp\docs_2026.zip) | `T1560.001` |
| `2026-10-15 11:46:13` | **Fase 6: Exfiltración de Datos** | `FIREWALL / PCAP` | FIN-PC07 (dtorres) | Exfiltración completada de 188.74 MB hacia el C2 (203.0.113.77:443) durante 481s | `T1041` |

---

## 3. Matriz Táctica MITRE ATT&CK Cubierta

| Táctica MITRE | ID Técnica | Nombre de la Técnica | Evidencia / Tecnología Involucrada |
|---|---|---|---|
| **Acceso Inicial** | `T1566.002` | Spearphishing Link | Proxy HTTP |
| **Ejecución** | `T1059.001` | PowerShell Scripting | Endpoint |
| **Evasión de Defensas** | `T1564.003` | Hidden Window & ExecutionPolicy Bypass | Endpoint |
| **Comando y Control** | `T1071.001` | Web Protocols (HTTPS Beaconing) | DNS & Firewall |
| **Descubrimiento** | `T1033` | System Owner/User Discovery | Endpoint LOLBins |
| **Descubrimiento** | `T1482` | Domain Trust Discovery | Endpoint LOLBins |
| **Descubrimiento** | `T1135` | Network Share Discovery | Endpoint LOLBins |
| **Recolección** | `T1039` | Data from Network Shared Drive | Endpoint SMB |
| **Recolección** | `T1560.001` | Archive via Utility (tar.exe) | Endpoint |
| **Exfiltración** | `T1041` | Exfiltration Over C2 Channel | Firewall & PCAP |

---

## 4. Indicadores de Compromiso (IoCs)

| Tipo de Indicador | Valor / Artefacto | Descripción y Contexto Forense | MITRE |
|---|---|---|---|
| **URL Maliciosa** | `https://facturas-andinas.example/download/factura_septiembre.zip` | URL de descarga del señuelo de Spear Phishing | `T1566.002` |
| **Dominio Malicioso** | `facturas-andinas.example` | Sitio web trampa de facturación suplantada | `T1566.002` |
| **Archivo Implante** | `C:\Users\dtorres\AppData\Local\Temp\update.ps1` | Script malicioso de PowerShell que opera como implante | `T1059.001` |
| **IP Servidor C2** | `203.0.113.77` | Infraestructura externa C2 del atacante (cdn-sync-services.example) | `T1071.001` |
| **Dominio C2** | `cdn-sync-services.example` | Nombre de dominio utilizado para balizamiento y exfiltración C2 | `T1071.001` |
| **Archivo Contenedor** | `C:\Users\dtorres\AppData\Local\Temp\docs_2026.zip` | Archivo comprimido con los 400 documentos financieros (size=191284391) | `T1560` |
| **Directorio de Staging** | `C:\Users\dtorres\AppData\Local\Temp\staging\` | Carpeta temporal de almacenamiento y preparación de datos antes de compresión | `T1074.001` |

---

## 5. Cuadro de Rigor Forense: Hechos Demostrados vs. Hipótesis vs. Distractores

### ✅ Hechos Demostrados por la Evidencia Digital
- Compromiso directo de la estación FIN-PC07 (10.20.10.47) del usuario dtorres mediante descarga web en 'facturas-andinas.example' a las 10:14:09.
- Ejecución oculta en segundo plano del script 'update.ps1' a las 10:16:22 con parámetros de evasión.
- Establecimiento de canal C2 periódico cada 300 segundos exactos hacia 'cdn-sync-services.example' (203.0.113.77:443).
- Sustracción automatizada de 400 archivos contables de \\FS01\Finanzas y empaquetado en 'docs_2026.zip' (191.28 MB) mediante tar.exe.
- Exfiltración volumétrica de 188.74 MB a través de HTTPS hacia 203.0.113.77 a las 11:46:13.

### 💡 Hipótesis Fundamentadas
- El usuario dtorres fue engañado por ingeniería social orientada al contexto fiscal/financiero y ejecutó manualmente el contenido del ZIP señuelo.
- El actor malicioso pertenece a un grupo de cibercrimen con fines de espionaje corporativo y extorsión por robo de propiedad intelectual.

### 🛡️ Distractores y Falsos Positivos Suprimidos Inteligente por el SIEM
- **Transferencia de Respaldo Legítimo** (`FS01`): Tráfico saliente de 500 MB generado por el File Server durante su ventana programada de backup. No involucra estaciones financieras ni malware.
- **Monitoreo Administrativo de Servicios TI** (`IT-PC02`): Ejecución periódica programada de PowerShell para chequear estado de servicios corporativos por el personal de TI. Sin parámetros ofuscados ni acceso a recursos confidenciales.
- **Fallos Aislados de Autenticación (Event ID 4625)** (`N/D`): Se registraron 87 fallos distribuidos aleatoriamente en varios usuarios y estaciones durante toda la jornada, consistentes con errores de digitación de contraseñas. No se evidencia ataque de fuerza bruta concentrado.

---

## 6. Evaluación de Impacto en el Negocio
CONFIDENCIALIDAD CRÍTICA: Exposición de nóminas salariales, contratos de proveedores y presupuestos estratégicos. INTEGRIDAD: Preservada (no se detectó ransomware ni alteración de registros). DISPONIBILIDAD: Sistemas operativos sin disrupción del servicio logístico. LEGAL/REGULATORIO: Riesgo alto por vulneración de normativa de protección de datos personales y secreto empresarial.

---

## 7. Plan de Respuesta y Contención Inmediata
- 1. Aislar de inmediato la estación de trabajo FIN-PC07 de la red LAN/Wi-Fi.
- 2. Bloquear en el Firewall perimetral y DNS interno la IP C2 203.0.113.77 y el dominio cdn-sync-services.example.
- 3. Forzar el restablecimiento inmediato de contraseñas de la cuenta de dominio 'dtorres'.
- 4. Revocar temporalmente accesos de red SMB a las carpetas \\FS01\Finanzas mientras se auditan las ACLs.
- 5. Eliminar en el host FIN-PC07 los artefactos: update.ps1, docs_2026.zip y la carpeta staging en %TEMP%.

### Plan de Erradicación y Recuperación
- 1. Realizar volcado forense de memoria RAM y adquisición de imagen de disco de FIN-PC07 para preservación de cadena de custodia.
- 2. Escanear toda la red corporativa en busca de actividad hacia los IoCs identificados.
- 3. Reinstalar la imagen corporativa limpia en la estación afectada antes de reincorporarla a producción.
- 4. Implementar políticas de restricción de ejecución de PowerShell (ConstrainedLanguageMode y AppLocker/WDAC).

---
*Informe generado automáticamente por AndesCorrelator Engine (ACE) SIEM el 2026-10-30 02:15:39 UTC.*
