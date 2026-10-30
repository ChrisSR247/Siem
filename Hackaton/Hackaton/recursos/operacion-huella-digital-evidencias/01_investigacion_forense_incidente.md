# Informe de Investigación Forense: Operación Huella Digital

## 1. Resumen Ejecutivo de la Investigación
El 15 de octubre de 2026, entre las 08:00 y las 14:00, se detectó una anomalía crítica de seguridad en la infraestructura de **AndesLogística S.A.** Tras la correlación integral de seis fuentes de evidencia independientes (`authentication.csv`, `dns.csv`, `endpoint.csv`, `firewall.csv`, `proxy.csv` y `suspicious-traffic.pcap`), se determinó de manera concluyente la ocurrencia de un ataque dirigido de exfiltración de información financiera.

El atacante comprometió la estación de trabajo **FIN-PC07** (`10.20.10.47`) del usuario **dtorres** mediante un vector de ingeniería social web (spear-phishing temático de facturación). Logró ejecutar un script en PowerShell que operó de forma persistente como implante C2, realizó reconocimiento de la red corporativa, recolectó 400 archivos confidenciales de finanzas desde el servidor `FS01`, los comprimió en un contenedor `.zip` y exfiltró exitosamente **188.74 MB** hacia un servidor C2 externo camuflado bajo el dominio `cdn-sync-services.example` (`203.0.113.77`).

---

## 2. Metodología y Fuentes de Evidencia Correlacionadas

| Fuente | Formato | Registros | Papel en la Investigación |
|---|---|---|---|
| `proxy.csv` | CSV | 1,452 | Identificación del punto de entrada (vector inicial de navegación). |
| `endpoint.csv` | CSV | 2,882 | Trazabilidad de procesos, comandos ejecutados y accesos a archivos locales. |
| `dns.csv` | CSV | 2,955 | Mapeo de resolución de dominios del atacante (C2) y balizamiento. |
| `firewall.csv` | CSV | 5,914 | Cuantificación volumétrica y temporal de tráfico saliente e interno. |
| `authentication.csv` | CSV | 1,455 | Validación de accesos al Dominio (`DC01`) y compartidos SMB (`FS01`). |
| `suspicious-traffic.pcap` | PCAP | 2,826 pkts | Confirmación a nivel de paquetes de sesiones TLS hacia la infraestructura C2. |

---

## 3. Reconstrucción Forense por Fases (Marco MITRE ATT&CK)

### Fase 1: Acceso Inicial (Initial Access - T1566 / T1189)
* **Fecha y Hora:** `2026-10-15T10:12:41` a `10:14:09`
* **Fuente:** `proxy.csv`
* **Detalle Técnico:**
  El usuario `dtorres` desde la estación `FIN-PC07` (`10.20.10.47`) navegó a un sitio web de facturación sospechoso:
  * `10:12:41` - `GET https://facturas-andinas.example/documentos/94831` (HTTP 200)
  * `10:14:09` - `GET https://facturas-andinas.example/download/factura_septiembre.zip` (HTTP 200)
* **Evidencia:** Registro explícito en `proxy.csv`. El señuelo fingía ser una factura del mes anterior, de alto interés para un miembro del departamento financiero.

### Fase 2: Ejecución y Evasión de Defensas (Execution & Defense Evasion - T1059.001 / T1564.003)
* **Fecha y Hora:** `2026-10-15T10:16:22`
* **Fuente:** `endpoint.csv`
* **Detalle Técnico:**
  Apenas 2 minutos y 13 segundos después de la descarga, se inició un proceso PowerShell interactivo en segundo plano:
  ```powershell
  powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Users\dtorres\AppData\Local\Temp\update.ps1
  ```
  * `Parent Process`: `explorer.exe` (indica que el usuario abrió o ejecutó el contenido extraído del archivo `.zip`).
  * `Bypass Flags`: El atacante utilizó `-ExecutionPolicy Bypass` para evadir restricciones de scripts de Windows y `-WindowStyle Hidden` para ocultar la ventana de consola a la víctima.

### Fase 3: Comando y Control (Command and Control - T1071.001 / T1095)
* **Fecha y Hora:** Inicio a las `10:17:04`, con balizas recurrentes cada 5 minutos exactos.
* **Fuentes:** `dns.csv`, `firewall.csv`, `suspicious-traffic.pcap`
* **Detalle Técnico:**
  El script `update.ps1` estableció comunicación inmediata con un servidor de Comando y Control (C2):
  1. Resolución DNS:
     * `10:17:04` -> `FIN-PC07` consulta `cdn-sync-services.example` (A) -> IP `203.0.113.77`
  2. Conexión de red de control:
     * `10:17:06` -> Conexión TCP/443 a `203.0.113.77`, enviando 1,492 bytes y recibiendo 3,868 bytes (duración 3s).
  3. Patrón de Balizamiento (Beaconing):
     * `10:22:08` (DNS) -> `10:22:10` (FW: 1,499 bytes enviados) [+300 segs]
     * `10:27:05` (DNS) -> `10:27:07` (FW: 1,473 bytes enviados) [+300 segs]
     * `10:32:11` (DNS) -> `10:32:13` (FW: 1,351 bytes enviados) [+300 segs]
     * `10:37:09` (DNS) -> `10:37:11` (FW: 1,184 bytes enviados) [+300 segs]
  4. Análisis PCAP: Paquetes TLS Application Data dirigidos a `203.0.113.77:443` confirman el canal cifrado interactivo entre el agente implantado y el atacante.

### Fase 4: Descubrimiento y Reconocimiento (Discovery - T1033 / T1087 / T1135)
* **Fecha y Hora:** `2026-10-15T10:42:03` a `10:43:31`
* **Fuente:** `endpoint.csv`
* **Detalle Técnico:**
  El operador remoto tomó control del implante y ejecutó utilidades nativas del sistema operativo (Living-off-the-Land Binaries - LOLBins):
  * `10:42:03` -> `whoami.exe` (Identificación de contexto de privilegios: `dtorres`)
  * `10:42:19` -> `nltest.exe /dclist:andes.local` (Reconocimiento del Directorio Activo y ubicación de Controladores de Dominio)
  * `10:42:51` -> `net.exe net view` (Enumeración de servidores y recursos compartidos en el dominio)
  * `10:43:31` -> `net.exe net use \\FS01\Finanzas` (Mapeo directo del recurso compartido del servidor de archivos)

### Fase 5: Recolección de Datos (Collection - T1005 / T1039 / T1560)
* **Fecha y Hora:** `2026-10-15T11:31:22` a `11:44:51`
* **Fuente:** `endpoint.csv`
* **Detalle Técnico:**
  * **Acceso Masivo Automatizado (11:31:22 a 11:35:01):**
    El implante ejecutó un bucle de lectura secuencial rápida accediendo a **400 archivos confidenciales** en `\\FS01\Finanzas\`:
    - `\\FS01\Finanzas\Proveedores\documento_XXXX.xlsx`
    - `\\FS01\Finanzas\Nomina\documento_XXXX.xlsx`
    - `\\FS01\Finanzas\Presupuestos\documento_XXXX.xlsx`
    - `\\FS01\Finanzas\Reportes\documento_XXXX.xlsx`
    Los archivos fueron copiados a una carpeta temporal local de preparación (staging):
    `C:\Users\dtorres\AppData\Local\Temp\staging\`
  * **Empaquetado y Compresión (11:41:27 a 11:44:51):**
    A las `11:41:27`, se ejecutó el utilitario nativo `tar.exe`:
    ```cmd
    tar.exe -a -c -f C:\Users\dtorres\AppData\Local\Temp\docs_2026.zip C:\Users\dtorres\AppData\Local\Temp\staging\*
    ```
    A las `11:44:51`, el sistema registra el evento `FILE_CREATE` del archivo consolidado:
    * Ruta: `C:\Users\dtorres\AppData\Local\Temp\docs_2026.zip`
    * Tamaño: **191,284,391 bytes** (~191.28 MB).

### Fase 6: Exfiltración de Información (Exfiltration - T1041 / T1048)
* **Fecha y Hora:** `2026-10-15T11:46:13` (Duración: 481 segundos = 8 minutos)
* **Fuente:** `firewall.csv`, `suspicious-traffic.pcap`
* **Detalle Técnico:**
  Inmediatamente después de completada la compresión del archivo `.zip`:
  * Conexión saliente desde `10.20.10.47` (`FIN-PC07`) hacia `203.0.113.77:443`.
  * **Volumen exfiltrado:** **188,743,680 bytes** (~188.74 MB), que se correlaciona con un margen de overhead casi idéntico al tamaño del archivo `docs_2026.zip` (191.28 MB).
  * La transferencia tardó 481 segundos a través de HTTPS para eludir inspecciones perimetrales superficiales.

---

## 4. Cuadro Comparativo: Hechos Demostrados vs. Hipótesis vs. Distractores

Para asegurar el máximo rigor científico y cumplir con las restricciones del reto, se clasifican los hallazgos:

| Categoría | Elemento / Evento | Sustento en Evidencia |
|---|---|---|
| **Hecho Demostrado** | Compromiso de `FIN-PC07` del usuario `dtorres`. | Registros en `proxy.csv` (10:14) y ejecución de `update.ps1` en `endpoint.csv` (10:16). |
| **Hecho Demostrado** | Exfiltración de 188.74 MB a `203.0.113.77`. | Registro directo en `firewall.csv` a las 11:46:13 y paquetes en `suspicious-traffic.pcap`. |
| **Hecho Demostrado** | Robo de 400 archivos de finanzas de `FS01`. | 400 eventos secuenciales de `FILE_ACCESS` en `endpoint.csv` entre 11:31 y 11:35. |
| **Hecho Demostrado** | C2 balizando cada 300 segundos a `cdn-sync-services.example`. | Consultas en `dns.csv` y sesiones de 1.4 KB en `firewall.csv` a las 10:17, 10:22, 10:27, 10:32 y 10:37. |
| **Hipótesis Fundamentada** | Extracción automatizada del payload por el usuario. | La descarga del `.zip` por Chrome (`10:14:09`) y la ejecución de `update.ps1` con padre `explorer.exe` (`10:16:22`) sugieren que el usuario abrió el ZIP descargado e hizo doble clic en el archivo que disparó el script. |
| **Distractor Descartado (Falso Positivo 1)** | Tráfico saliente de 500 MB desde `FS01` a las 11:20:00. | Corresponde a la tarea legítima de respaldo del servidor de archivos hacia `backup.example.net` (`198.51.100.44`). No es exfiltración. |
| **Distractor Descartado (Falso Positivo 2)** | Ejecuciones de `powershell.exe Get-Service` en `IT-PC02`. | Ejecutado cada 7 minutos por `jparedes` desde las 08:30. Es una tarea programada de monitoreo de servicios del administrador de TI. |
| **Distractor Descartado (Falso Positivo 3)** | Fallos dispersos de autenticación (Event ID 4625). | Distribuidos a lo largo del día en diversas máquinas sin ráfagas concentradas. Corresponden a errores normales de digitación o falta de permisos en ERP. |

---

## 5. Tabla de Indicadores de Compromiso (IoCs)

| Tipo de IoC | Valor / Indicador | Descripción / Contexto |
|---|---|---|
| **URL Maliciosa** | `https://facturas-andinas.example/documentos/94831` | Página trampa de Spear Phishing |
| **URL de Descarga** | `https://facturas-andinas.example/download/factura_septiembre.zip` | Enlace de descarga de artefacto malicioso |
| **Dominio C2** | `cdn-sync-services.example` | Dominio de infraestructura de Comando y Control |
| **IP Externa C2** | `203.0.113.77` | Servidor externo receptor del tráfico de baliza y exfiltración |
| **Archivo Local** | `C:\Users\dtorres\AppData\Local\Temp\update.ps1` | Script de PowerShell (implante malicioso) |
| **Archivo Local** | `C:\Users\dtorres\AppData\Local\Temp\docs_2026.zip` | Archivo comprimido con datos corporativos exfiltrados |
| **Directorio de Staging** | `C:\Users\dtorres\AppData\Local\Temp\staging\` | Directorio de consolidación previa a compresión |
| **Patrón de Red** | Beaconing HTTPS periódico cada 300 segundos (5 min) | Frecuencia de chequeo del implante contra el servidor C2 |
