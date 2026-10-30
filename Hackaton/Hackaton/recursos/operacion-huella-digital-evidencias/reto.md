# Reto Hackathon: Operación Huella Digital — AndesLogística S.A.

## 📌 Navegación de Documentación del Reto

Para abordar este reto de manera exhaustiva, profesional y conforme a la rúbrica de evaluación (100 puntos), se ha estructurado la solución y la investigación en los siguientes documentos especializados:

1. 📄 [01_investigacion_forense_incidente.md](file:///home/alddrinW/Documentos/Hackaton/recursos/operacion-huella-digital-evidencias/01_investigacion_forense_incidente.md)
   * Reconstrucción forense detallada basada en las 6 fuentes de evidencia (`proxy`, `endpoint`, `dns`, `firewall`, `authentication`, `suspicious-traffic.pcap`).
   * Mapeo táctico bajo el marco **MITRE ATT&CK**.
   * Identificación de Indicadores de Compromiso (IoCs).
   * **Diferenciación crítica**: Hechos demostrados vs. Hipótesis vs. Descarte de distractores (Falsos Positivos / Red Herrings).

2. ⏱️ [02_linea_de_tiempo_cronologica.md](file:///home/alddrinW/Documentos/Hackaton/recursos/operacion-huella-digital-evidencias/02_linea_de_tiempo_cronologica.md)
   * Línea de tiempo unificada y correlacionada segundo a segundo desde las 08:00 hasta las 14:00 del 15 de octubre de 2026.
   * Diagrama de secuencia y flujo de ataque en formato visual Mermaid.

3. 📋 [03_ficha_tecnica_solucion.md](file:///home/alddrinW/Documentos/Hackaton/recursos/operacion-huella-digital-evidencias/03_ficha_tecnica_solucion.md)
   * Documento formal listo para entrega en PDF (Entregable oficial).
   * Resumen ejecutivo, impacto en el negocio, arquitectura técnica del prototipo de correlación automática propuesto y justificación de viabilidad.

4. 🎤 [04_pitch_guion_3_minutos.md](file:///home/alddrinW/Documentos/Hackaton/recursos/operacion-huella-digital-evidencias/04_pitch_guion_3_minutos.md)
   * Guion cronometrado para la presentación oral ante los jueces (0:00 a 3:00 minutos).
   * Respuestas preparadas para preguntas de impacto del jurado evaluador.

5. 🧭 [05_guia_paso_a_paso_documentacion.md](file:///home/alddrinW/Documentos/Hackaton/recursos/operacion-huella-digital-evidencias/05_guia_paso_a_paso_documentacion.md)
   * Manual didáctico paso a paso para el equipo sobre qué documentar, cómo sustentar la evidencia y cómo asegurar el máximo puntaje en cada criterio de evaluación.

6. 💻 [analizador_correlacion.py](file:///home/alddrinW/Documentos/Hackaton/recursos/operacion-huella-digital-evidencias/analizador_correlacion.py)
   * Prototipo en código fuente Python para demostrar la detección y correlación automatizada de este incidente frente al jurado.

---

## 🔍 Resumen Rápido del Incidente Comprobado

* **Objetivo Comprometido:** Estación `FIN-PC07` (IP: `10.20.10.47`), perteneciente al usuario `dtorres` del área Financiera.
* **Vector de Infección Inicial:** Spear Phishing web a las **10:14:09**, descarga de archivo malicioso `factura_septiembre.zip` desde el dominio externo `facturas-andinas.example`.
* **Ejecución y Evasión:** A las **10:16:22**, ejecución en segundo plano y con evasión de directivas (`-WindowStyle Hidden -ExecutionPolicy Bypass`) del script `update.ps1` ubicado en `%TEMP%`.
* **Comando y Control (C2):** Establecimiento de balizamiento C2 HTTPS periódico (cada 5 minutos exactos) hacia `cdn-sync-services.example` (`203.0.113.77:443`).
* **Reconocimiento Interno:** A las **10:42**, ejecución de `whoami`, `nltest /dclist:andes.local` y `net view` para mapear el dominio y recursos compartidos.
* **Recolección:** Entre **11:31 y 11:35**, acceso masivo no interactivo y descarga de 400 documentos contables confidenciales (Nómina, Presupuestos, Proveedores, Reportes) desde `\\FS01\Finanzas`.
* **Empaquetado y Compresión:** A las **11:41:27**, uso de `tar.exe` para consolidar los documentos en el archivo `C:\Users\dtorres\AppData\Local\Temp\docs_2026.zip` (191.28 MB).
* **Exfiltración de Datos:** A las **11:46:13**, transmisión de **188.74 MB** de datos comprimidos hacia el servidor C2 `203.0.113.77:443` durante 481 segundos (~8 minutos).
* **Falso Positivo Descartado (Distractor):** Tráfico de 500 MB a las 11:20:00 desde `FS01` hacia `198.51.100.44` corresponde a un respaldo programado legítimo del servidor hacia `backup.example.net`.
