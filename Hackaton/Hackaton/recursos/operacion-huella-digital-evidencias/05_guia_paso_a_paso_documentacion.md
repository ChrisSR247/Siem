# Guía Paso a Paso: Qué y Cómo Documentar para Ganar el Hackathon

Esta guía te explica de forma clara, directa y estructurada **qué debes documentar exactamente**, en qué orden y cómo justificar cada punto para obtener los **100 puntos** según los criterios de evaluación del jurado.

---

## 🎯 Estructura Obligatoria de los Entregables

De acuerdo con las bases del reto (`operacion-huella-digital.md`, Sección 7), debes entregar:

1. **Ficha Técnica en PDF** (Documento formal completo).
2. **Código Fuente y Prototipo** (Herramienta técnica funcional).
3. **Evidencia de Pruebas** (Capturas, logs de ejecución del prototipo).
4. **Pitch de 3 minutos** (Defensa oral).

---

## 📑 Paso a Paso: ¿Qué Documentar Realmente en la Ficha Técnica (PDF)?

Para que tu Ficha Técnica sea impecable, organízala en las siguientes 6 secciones:

### Paso 1: Portada y Ficha de Identificación
* Nombre del Reto: *Operación Huella Digital: Investigación y Detección de un Incidente Corporativo*
* Nombre de la Empresa: *AndesLogística S.A.*
* Nombre de tu Equipo e Integrantes.
* Categoría: *Universitarios* | Enfoque: *Blue Team / Incident Response*.

### Paso 2: Resumen Ejecutivo e Impacto Empresarial (15 Pts)
* **El Problema:** Explica que AndesLogística sufría de silos de información (logs analizados manualmente y por separado).
* **El Hallazgo:** Resume en un párrafo qué pasó: compromiso de `FIN-PC07` (`dtorres`), robo de 400 archivos contables en `FS01`, y exfiltración de 188.74 MB hacia `203.0.113.77`.
* **Impacto:** Evalúa el impacto en Confidencialidad (Crítico), Integridad (Bajo) y Disponibilidad (Bajo), más el riesgo legal por filtración de nóminas y contratos.

### Paso 3: Reconstrucción Forense con Evidencia Sustentada (Comprensión: 10 Pts)
Aquí es donde demuestras dominio técnico. No digas cosas vagas, documenta con **datos duros**:
* **Vector de Entrada:** Cita el log de `proxy.csv` del `2026-10-15T10:14:09`, descarga de `factura_septiembre.zip` desde `facturas-andinas.example`.
* **Ejecución:** Cita el log de `endpoint.csv` de las `10:16:22`, comando `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Users\dtorres\AppData\Local\Temp\update.ps1`.
* **Comando y Control (C2):** Muestra el balizamiento exacto cada 300 segundos a `cdn-sync-services.example` (`203.0.113.77`) registrado en `dns.csv` y `firewall.csv`.
* **Recolección y Compresión:** Cita los 400 accesos a `\\FS01\Finanzas\...` (11:31 a 11:35) y la compresión con `tar.exe` a las 11:41 en `docs_2026.zip` (191.28 MB).
* **Exfiltración:** Cita la conexión de firewall a las `11:46:13` con **188,743,680 bytes** transferidos hacia `203.0.113.77:443`.

### Paso 4: La Clave de Oro — Diferenciar Hechos, Hipótesis y Falsos Positivos
Los jueces penalizan a quienes confunden ruidos normales con ataques. Incluye una tabla comparativa explícita:
1. **Hechos Demostrados:** Todo lo sustentado con timestamps y logs (compromiso de FIN-PC07, C2, exfiltración).
2. **Hipótesis Razonables:** Que el usuario abrió el zip y ejecutó el payload inadvertidamente (evidenciado por `parent_process: explorer.exe`).
3. **Falsos Positivos Descartados (¡MUY IMPORTANTE!):**
   * El tráfico de **500 MB** de `FS01` a las 11:20:00: Demuestra que es un respaldo legítimo hacia `backup.example.net` (`198.51.100.44`).
   * Los comandos PowerShell `Get-Service` en `IT-PC02`: Demuestra que es un monitoreo legítimo de TI cada 7 minutos por `jparedes`.
   * Los fallos de contraseña dispersos: Errores comunes de usuarios, no ataques de fuerza bruta dirigidos.

### Paso 5: Línea de Tiempo Cronológica y Diagrama Visual
* Coloca el diagrama de secuencia Mermaid (incluido en `02_linea_de_tiempo_cronologica.md`).
* Inserta una tabla ordenada cronológicamente de los eventos clave desde las 10:12 hasta las 11:54.

### Paso 6: Descripción de la Solución Técnica Propuesta (Innovación: 20 Pts, Viabilidad: 20 Pts, Seguridad: 15 Pts, Escalabilidad: 10 Pts)
* **Nombre de la Solución:** AndesCorrelator Engine (ACE).
* **Arquitectura:** Diagrama de cómo toma los CSV/Syslog/PCAP, los normaliza y aplica reglas de correlación cruzada.
* **Reglas Clave:**
  - *R1: Proxy Zip Download + Endpoint Hidden Script* en menos de 5 min.
  - *R2: Detección matemática de C2 Beaconing* (periodicidad fija sin descifrado SSL).
  - *R3: Staging masivo de archivos de red* + compresión local.
  - *R4: Exfiltración anómala de alto volumen* por puertos web.
  - *R5: Supresión de Falsos Positivos* (White-listing contextual de backups).
* **Seguridad y Privacidad:** Explica que la herramienta corre **100% On-Premise/Local**, sin exponer evidencias sensibles a servicios cloud o modelos externos (cumpliendo la Sección 12 del reto).
* **Evidencia de Pruebas:** Pega capturas de pantalla de la terminal ejecutando el prototipo `analizador_correlacion.py`.

---

## 🚫 Errores Comunes que Debes Evitar

| Error Común | Por qué resta puntos | Qué debes hacer tú |
|---|---|---|
| Acusar a FS01 de haber sido hackeado por los 500 MB | Es un falso positivo (backup). Los jueces evalúan si distingues actividad legítima. | Explicar con `dns.csv` que es `backup.example.net`. |
| Decir "hubo un virus" sin dar detalles | Falta de rigor técnico forense. | Especificar hashes/nombres: `update.ps1`, `docs_2026.zip`, comandos ejecutados. |
| Olvidar relacionar el PCAP | El reto pide correlacionar todas las evidencias entregadas. | Mencionar los paquetes TLS a `203.0.113.77` analizados en `suspicious-traffic.pcap`. |
| Proponer soluciones teóricas sin código | El criterio de Viabilidad y Entregables exige código fuente y prototipo. | Entregar y mostrar el script funcional `analizador_correlacion.py`. |
| Pasarse de los 3 minutos en el pitch | Descalificación o corte abrupto por parte del moderador. | Seguir el guion exacto de `04_pitch_guion_3_minutos.md` cronometrado en 2 min 45 seg. |

---

## 🛠️ Cómo Generar el PDF Final

Puedes compilar `03_ficha_tecnica_solucion.md` y `01_investigacion_forense_incidente.md` en PDF usando cualquiera de estas opciones:
1. Desde VS Code / Antigravity IDE: Extensión "Markdown PDF" o "Markdown Preview Enhanced" -> Export to PDF.
2. Desde la terminal en Linux:
   ```bash
   pandoc 03_ficha_tecnica_solucion.md -o Ficha_Tecnica_Operacion_Huella_Digital.pdf --pdf-engine=wkhtmltopdf
   ```
3. O abriendo el archivo Markdown en un navegador web / editor de texto y usando la función "Imprimir a PDF".
