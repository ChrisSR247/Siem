# PLAN DE PREVENCIÓN, BLINDAJE Y HARDENING EMPRESARIAL
**Organización:** AndesLogística S.A.  
**Propósito:** Mitigar de forma estructural y permanente la cadena de ataque sufrida en *Operación Huella Digital*.  
**Marco de Referencia:** CIS Controls v8 | NIST Cybersecurity Framework | MITRE D3FEND  

---

## 1. Diagnóstico de Causa Raíz (Por qué ocurrió el incidente)
El ataque contra la estación `FIN-PC07` del usuario `dtorres` tuvo éxito debido a **5 brechas preventivas estructurales** en la empresa:

1. **Ausencia de filtrado web a nivel de contenido:** Se permitió descargar un archivo `.zip` señuelo desde un dominio no categorizado (`facturas-andinas.example`).
2. **Políticas permisivas de PowerShell:** La directiva permitía el parámetro `-ExecutionPolicy Bypass` y `-WindowStyle Hidden` sin restricción de lenguaje (*Constrained Language Mode* deshabilitado).
3. **Escritura y ejecución en `%TEMP%`:** No existían directivas de restricción de software (AppLocker/WDAC) que impidieran ejecutar scripts `.ps1` y utilitarios empaquetadores desde carpetas temporales de usuarios no privilegiados.
4. **Permisos SMB excesivos en `\\FS01\Finanzas`:** Una sola cuenta financiera comprometida pudo leer de forma no interactiva y continua 400 archivos de 4 carpetas distintas (Nómina, Proveedores, Presupuestos, Reportes) en apenas 4 minutos sin generar ninguna alerta de umbral.
5. **Falta de inspección volumétrica de salida en el Firewall:** Se autorizó la salida de **188.74 MB** de datos en una sola conexión HTTPS hacia una IP externa no confiable (`203.0.113.77`).

---

## 2. Estrategia Preventiva de Defensa en Profundidad (Defense-in-Depth)

```
[ Capa 1: Perímetro Web & Correo ]   -> Filtrado de extensiones (.zip, .iso) de dominios nuevos/desconocidos
              │
[ Capa 2: Endpoint Hardening ]       -> PowerShell ConstrainedLanguageMode + AppLocker en %TEMP% + Reglas ASR
              │
[ Capa 3: Privilegios y SMB ]        -> Principio de Mínimo Privilegio + Auditoría avanzada EID 5145 en FS01
              │
[ Capa 4: Perímetro de Red / Egress] -> Inspección TLS + Límite de cuota volumétrica de subida no autorizada
              │
[ Capa 5: SIEM & SOAR Activo ]       -> AndesCorrelator Engine (ACE) ejecutando aislamiento automático
```

---

## 3. Matriz de Controles Preventivos MITRE D3FEND

| Técnica de Ataque | Técnica de Defensa MITRE D3FEND | Control Técnico a Implementar en AndesLogística S.A. |
|---|---|---|
| **T1566.002 (Spearphishing)** | `D3-URLF (URL Filtering)` | Bloquear descargas de archivos comprimidos (`.zip`, `.iso`, `.rar`) desde dominios con antigüedad < 30 días en el Proxy. |
| **T1059.001 (PowerShell)** | `D3-SBL (Script Execution Restriction)` | Configurar `__PSLockdownPolicy = 4` y activar políticas de restricción de scripts firmados por PKI interna. |
| **T1564.003 (Hidden Window)** | `D3-PRA (Process Spawn Analysis)` | Windows Defender ASR Rule: Impedir que procesos de Office o Explorer creen ventanas ocultas de PowerShell. |
| **T1033 / T1135 (LOLBins)** | `D3-EFA (Endpoint Execution Authorization)` | Auditoría y alerta SIEM en tiempo real al detectar ejecución consecutiva de `whoami`, `nltest`, `net view`. |
| **T1039 (SMB Mass Access)** | `D3-DOA (Directory Object Access Restriction)` | Implementar listas de control de acceso granulares (ACL) en `\\FS01\Finanzas` divididas por función de rol. |
| **T1560.001 (Archive via tar)** | `D3-SCA (Software Configuration Authentication)` | Bloquear ejecución de binarios de compresión (`tar.exe`, `7z.exe`) fuera de rutas administrativas autorizadas. |
| **T1041 (Exfiltration C2)** | `D3-OTA (Outbound Traffic Analysis)` | Alerta perimetral automática cuando una estación de trabajo transmita > 50 MB hacia IPs no categorizadas. |

---

## 4. Guía de Despliegue de los Artefactos Generados

Los archivos ejecutables listos para desplegar se encuentran en la carpeta `prevention/`:

### A. Para contención inmediata de incidentes activos:
Ejecutar desde PowerShell como Administrador:
```powershell
.\prevention\01_contencion_inmediata_soar.ps1 -TargetHost "FIN-PC07" -TargetUser "dtorres"
```

### B. Para blindar todas las estaciones de trabajo de AndesLogística (GPO):
Distribuir mediante Group Policy Object (GPO) en el Controlador de Dominio `DC01`:
```powershell
.\prevention\02_hardening_gpo_empresarial.ps1
```

### C. Para desplegar monitorización granular con Sysmon:
En cada estación de trabajo:
```cmd
Sysmon64.exe -i .\prevention\03_reglas_sysmon_prevencion.xml
```

### D. Para aplicar bloqueos perimetrales:
Copiar los comandos de `prevention/04_bloqueo_firewall_perimetral.txt` en la consola CLI de los firewalls Fortinet / Palo Alto perimetrales.

---
*Plan de Prevención elaborado automáticamente por AndesCorrelator Engine (ACE) SIEM para AndesLogística S.A.*
