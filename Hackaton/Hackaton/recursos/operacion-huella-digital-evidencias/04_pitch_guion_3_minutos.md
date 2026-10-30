# Guion de Pitch: Operación Huella Digital (3 Minutos)

**Objetivo:** Captar la atención del jurado desde el segundo cero, demostrar dominio técnico absoluto del caso forense, presentar la solución desarrollada y evidenciar su impacto real para AndesLogística S.A.

---

## ⏱️ Estructura y Cronograma del Pitch (180 Segundos)

### Minuto 0:00 - 0:35 | El Gancho y el Problema Empresarial
> **[Orador - Tono seguro y directo]**  
> "Buenos días, miembros del jurado.  
> Imaginen que en este preciso instante, 400 documentos financieros confidenciales con nóminas, presupuestos y costos estratégicos de su empresa están viajando hacia un servidor desconocido en el exterior.  
> Cuando el equipo de AndesLogística detectó un tráfico inusual, tenían cientos de miles de líneas de logs en seis sistemas aislados. Revisarlos manualmente toma horas; pero el atacante necesitó apenas 30 minutos para saquear el servidor de archivos.  
> Hoy les presentamos no solo la verdad exacta de lo que ocurrió, sino la solución que transforma el caos de logs aislados en detección e interrupción inmediata."

---

### Minuto 0:35 - 1:25 | La Revelación Forense (Datos Duros e Investigación)
> **[Orador - Mostrando timeline o diapositiva de la cadena de ataque]**  
> "Nuestra investigación correlacionó con rigor científico las seis fuentes de evidencia y descubrió una intrusión quirúrgica:  
> - **A las 10:14:** El usuario `dtorres`, en la máquina de Finanzas `FIN-PC07`, cayó en un correo con enlace a una supuesta factura: descargó `factura_septiembre.zip`.  
> - **A las 10:16:** Se ejecutó en segundo plano el script `update.ps1` evadiendo políticas de ejecución de Windows.  
> - **Desde las 10:17:** El implante estableció un balizamiento C2 cifrado cada 300 segundos exactos hacia el dominio `cdn-sync-services.example`, IP `203.0.113.77`.  
> - **A las 11:31:** El atacante automatizó la sustracción de 400 archivos contables desde el servidor de archivos `FS01`, los comprimió con `tar.exe` en un archivo de 191 MB, y a las 11:46 exfiltró **188.74 MB** hacia el C2 en una sola sesión de 8 minutos.  
> **Y un hallazgo clave:** Descartamos el tráfico de 500 MB de `FS01` a las 11:20: demostramos con evidencia DNS que era un respaldo programado legítimo a la nube. Separamos con precisión quirúrgica el ruido del verdadero ataque."

---

### Minuto 1:25 - 2:20 | La Solución: AndesCorrelator Engine (ACE)
> **[Orador - Presentando el prototipo / terminal con la ejecución]**  
> "Para evitar que esto vuelva a ocurrir, desarrollamos **AndesCorrelator Engine (ACE)**.  
> ACE es una plataforma ligera de correlación temporal cruzada. En lugar de alertas aisladas que abruman al analista, ACE ingesta registros de Proxy, Endpoint, DNS y Firewall, y aplica un motor de reglas multicapa:  
> 1. Detecta la correlación causal entre una descarga sospechosa y una ejecución oculta de scripts en menos de 5 minutos.  
> 2. Identifica matemáticamente patrones de balizamiento C2 periódico, sin requerir descifrado SSL.  
> 3. Detecta anomalías de staging masivo de archivos SMB combinados con picos de tráfico saliente.  
> Con ACE, el tiempo de detección de este incidente se reduce de **4 horas a menos de 3 segundos**, permitiendo aislar la estación `FIN-PC07` antes de que se consume la exfiltración."

---

### Minuto 2:20 - 3:00 | Impacto Empresarial, Seguridad y Cierre
> **[Orador - Conclusión contundente]**  
> "ACE cumple rigurosamente con los más altos estándares: es 100% procesado en local, garantizando que ninguna evidencia confidencial salga de la red corporativa. Es escalable, liviano y viable para implementarse hoy mismo en empresas medianas sin requerir licencias millonarias de SIEM.  
> Transformamos un incidente crítico en una capacidad defensiva permanente.  
> Muchas gracias. Quedamos atentos a sus preguntas."

---

## 💡 Preguntas Frecuentes y Respuestas Preparadas para el Jurado

**P1: ¿Cómo determinaron que los 500 MB de FS01 no eran parte del incidente?**  
> *Respuesta:* "Revisamos la evidencia de `dns.csv` y `firewall.csv`. A las 08:00:07 y previo a la conexión, la IP `198.51.100.44` resuelve a `backup.example.net`. El volumen de 524,288,000 bytes corresponde a exactamente 500 MB cerrados transferidos desde el servidor de archivos a su repositorio de copias de seguridad. No hubo procesos anómalos ni comandos ejecutados en FS01."

**P2: ¿Por qué el antivirus o firewall tradicional no detuvo el script?**  
> *Respuesta:* "Porque el script corrió con `-ExecutionPolicy Bypass` y `-WindowStyle Hidden`, utilizando utilitarios legítimos del sistema operativo como PowerShell y `tar.exe` (LOLBins). Además, la exfiltración se hizo a través del puerto TCP 443 simulando tráfico HTTPS hacia un dominio que parecía un CDN legítimo (`cdn-sync-services.example`). Por eso la correlación cruzada entre proxy, endpoint y firewall es la única que detecta el ataque."

**P3: ¿Qué tan difícil es implementar su prototipo en una empresa real?**  
> *Respuesta:* "Es sumamente sencillo y viable. ACE está programado en Python nativo y acepta formatos estándar Syslog, CSV y JSON generados por Windows Event Forwarding, Sysmon, proxies y firewalls comerciales. Puede correr en un contenedor Docker en el SOC sin costo de licencias."
