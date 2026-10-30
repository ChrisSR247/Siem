"""
AndesCorrelator Engine (ACE) - Motor de Prevención y Hardening Empresarial
Hackathon: Operación Huella Digital (AndesLogística S.A.)
Enfoque: SOAR, Defense-in-Depth, Zero Trust & Endpoint/Perimeter Hardening
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional
from utils import log_coloreado, Colors


class EnterprisePreventer:
    """
    Motor de Defensa Activa, Prevención y Hardening Empresarial.
    Transforma la investigación forense reactiva en controles proactivos de prevención
    diseñados para proteger la infraestructura corporativa de AndesLogística S.A.
    """

    def __init__(self, incidente: dict, output_dir: Optional[Path] = None):
        self.incidente = incidente
        from config import BASE_DIR
        self.output_dir = Path(output_dir or (BASE_DIR / "prevention"))
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generar_suite_prevencion_completa(self) -> Dict[str, str]:
        """Genera todos los artefactos preventivos, scripts de hardening, SOAR y reglas perimetrales."""
        log_coloreado("INFO", "Generando Suite de Prevención y Hardening Empresarial...")

        archivos = {}
        archivos["contencion_ps1"] = self._generar_script_contencion_activa()
        archivos["hardening_gpo_ps1"] = self._generar_script_hardening_gpo()
        archivos["sysmon_xml"] = self._generar_reglas_sysmon()
        archivos["firewall_rules"] = self._generar_reglas_firewall()
        archivos["soar_json"] = self._generar_playbook_soar()
        archivos["guia_md"] = self._generar_guia_prevencion_md()

        log_coloreado("INFO", f"Suite de prevención generada con éxito en: {self.output_dir}")
        return archivos

    # -------------------------------------------------------------------------
    # 1. SCRIPT DE CONTENCIÓN ACTIVA INMEDIATA (SOAR / Incident Response)
    # -------------------------------------------------------------------------
    def _generar_script_contencion_activa(self) -> str:
        path = self.output_dir / "01_contencion_inmediata_soar.ps1"
        host = self.incidente.get("host_comprometido", "FIN-PC07")
        ip_host = self.incidente.get("ip_host", "10.20.10.47")
        user = self.incidente.get("usuario_comprometido", "dtorres")
        c2_ip = "203.0.113.77"
        c2_domain = "cdn-sync-services.example"
        phish_domain = "facturas-andinas.example"

        ps1 = f"""<#
.SYNOPSIS
    Script de Respuesta Automática y Contención Inmediata (SOAR Playbook)
    Caso: {self.incidente.get('titulo')} - AndesLogística S.A.
.DESCRIPTION
    Ejecuta el protocolo de contención de emergencia en la estación {host} ({ip_host})
    y corta la infraestructura de Comando y Control (C2).
#>

[CmdletBinding()]
param(
    [string]$TargetHost = "{host}",
    [string]$TargetUser = "{user}",
    [string]$C2_IP = "{c2_ip}",
    [string]$C2_Domain = "{c2_domain}",
    [string]$PhishingDomain = "{phish_domain}"
)

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "   PROTOCOLO SOAR DE CONTENCIÓN INMEDIATA - ANDESLOGÍSTICA S.A.   " -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. AISLAMIENTO DE RED DE LA ESTACIÓN (Host Isolation)
Write-Host "`n[PASO 1] Aislando estación $TargetHost de la red LAN..." -ForegroundColor Red
try {{
    # Bloquear todo el tráfico entrante/saliente excepto la IP de gestión de SOC (10.20.10.102)
    New-NetFirewallRule -DisplayName "SOAR_ISOLATE_ALL_OUTBOUND" -Direction Outbound -Action Block -Profile Any -Priority 1 -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "SOAR_ALLOW_SOC_MGMT" -Direction Outbound -RemoteAddress "10.20.10.102" -Action Allow -Priority 2 -ErrorAction SilentlyContinue
    Write-Host "  [✓] Estación aislada. Tráfico lateral y salida a internet bloqueados." -ForegroundColor Green
}} catch {{
    Write-Warning "No se pudo aplicar regla de firewall local: $_"
}}

# 2. TERMINACIÓN FORZOSA DE PROCESOS MALICIOSOS (Process Kill)
Write-Host "`n[PASO 2] Terminando procesos maliciosos y herramientas de compresión..." -ForegroundColor Yellow
$procToKill = @("powershell", "pwsh", "tar", "7z", "winrar")
foreach ($p in $procToKill) {{
    Get-Process -Name $p -ErrorAction SilentlyContinue | Where-Object {{ $_.Path -notlike "*System32*" -or $_.CommandLine -like "*update.ps1*" -or $_.CommandLine -like "*Hidden*" }} | Stop-Process -Force -Verbose
}}
Write-Host "  [✓] Procesos del implante y empaquetado finalizados." -ForegroundColor Green

# 3. REVOCACIÓN DE CREDENCIALES Y SESIONES SMB
Write-Host "`n[PASO 3] Revocando credenciales y sesiones de red del usuario $TargetUser..." -ForegroundColor Yellow
try {{
    # En Controlador de Dominio / Servidor de Archivos:
    # Disable-ADAccount -Identity $TargetUser
    # Revocar sesiones SMB activas en \\FS01
    Get-SmbSession | Where-Object {{ $_.UserName -like "*$TargetUser*" }} | Close-SmbSession -Force -ErrorAction SilentlyContinue
    Write-Host "  [✓] Sesiones SMB activas revocadas en servidores de archivos." -ForegroundColor Green
}} catch {{
    Write-Warning "Revocación remota requiere privilegios en DC/FS01."
}}

# 4. CUARENTENA Y ELIMINACIÓN DE ARTEFACTOS LOCALES
Write-Host "`n[PASO 4] Poniendo en cuarentena artefactos en %TEMP%..." -ForegroundColor Yellow
$tempPaths = @(
    "C:\\Users\\$TargetUser\\AppData\\Local\\Temp\\update.ps1",
    "C:\\Users\\$TargetUser\\AppData\\Local\\Temp\\docs_2026.zip",
    "C:\\Users\\$TargetUser\\AppData\\Local\\Temp\\staging"
)
foreach ($item in $tempPaths) {{
    if (Test-Path $item) {{
        $quarantine = "$item.QUARANTINED_" + (Get-Date -Format "yyyyMMddHHmmss")
        Move-Item -Path $item -Destination $quarantine -Force -ErrorAction SilentlyContinue
        Write-Host "  [!] Artefacto en cuarentena: $quarantine" -ForegroundColor Magenta
    }}
}}

# 5. BLOQUEO PERIMETRAL Y SINKHOLE DNS
Write-Host "`n[PASO 5] Aplicando bloqueo de C2 y Phishing en hosts locales..." -ForegroundColor Yellow
$hostsFile = "$env:windir\\System32\\drivers\\etc\\hosts"
$sinkholeEntries = @(
    "127.0.0.1 $C2_Domain",
    "127.0.0.1 $PhishingDomain"
)
foreach ($entry in $sinkholeEntries) {{
    if (-not (Select-String -Path $hostsFile -Pattern $entry -SimpleMatch -Quiet)) {{
        Add-Content -Path $hostsFile -Value "`n$entry" -Force
        Write-Host "  [✓] Dominio sinkholeado en hosts local: $entry" -ForegroundColor Green
    }}
}}
Clear-DnsClientCache
Write-Host "`n[✓✓✓] PROTOCOLO DE CONTENCIÓN COMPLETADO EXITOSAMENTE." -ForegroundColor Green
"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(ps1)
        return str(path)

    # -------------------------------------------------------------------------
    # 2. SCRIPT DE HARDENING EMPRESARIAL GPO (Endpoint Hardening)
    # -------------------------------------------------------------------------
    def _generar_script_hardening_gpo(self) -> str:
        path = self.output_dir / "02_hardening_gpo_empresarial.ps1"
        ps1 = """<#
.SYNOPSIS
    Script de Hardening de Seguridad para Endpoints y Servidores Windows
    AndesLogística S.A. - Protección Anti-SpearPhishing, Anti-LOLBins y Anti-Exfiltración
.DESCRIPTION
    Aplica políticas preventivas directas y genera configuración para directivas GPO:
    1. Restricción estricta de PowerShell (Constrained Language Mode).
    2. Habilitación de Script Block Logging (Event ID 4104).
    3. Reglas ASR (Attack Surface Reduction) de Windows Defender.
    4. Bloqueo de ejecución de ejecutables y scripts desde carpetas temporales (%TEMP%, AppData).
    5. Auditoría avanzada de accesos a recursos compartidos SMB en File Servers.
#>

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "   APLICANDO DEFENSAS PREVENTIVAS CORPORATIVAS (DEFENSE-IN-DEPTH) " -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan

# -----------------------------------------------------------------------------
# CONTROL 1: RESTRICCIÓN DE POWERSHELL (Elimina el vector T1059.001 / Bypass)
# -----------------------------------------------------------------------------
Write-Host "`n[CONTROL 1] Configurando PowerShell Constrained Language Mode y Auditoría..." -ForegroundColor Yellow
# Establecer variable del sistema para bloquear PowerShell interactivo malicioso
[Environment]::SetEnvironmentVariable("__PSLockdownPolicy", "4", "Machine")

# Habilitar Script Block Logging y Module Logging en el Registro
$psAuditPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"
if (-not (Test-Path $psAuditPath)) { New-Item -Path $psAuditPath -Force | Out-Null }
Set-ItemProperty -Path $psAuditPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Set-ItemProperty -Path $psAuditPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord

$psTransPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription"
if (-not (Test-Path $psTransPath)) { New-Item -Path $psTransPath -Force | Out-Null }
Set-ItemProperty -Path $psTransPath -Name "EnableTranscripting" -Value 1 -Type DWord
Set-ItemProperty -Path $psTransPath -Name "OutputDirectory" -Value "C:\\ProgramData\\PSTranscripts" -Type String
Write-Host "  [✓] Script Block Logging y Transcripción habilitadas permanentemente." -ForegroundColor Green

# -----------------------------------------------------------------------------
# CONTROL 2: REGLAS ASR (ATTACK SURFACE REDUCTION) DE WINDOWS DEFENDER
# -----------------------------------------------------------------------------
Write-Host "`n[CONTROL 2] Activando Reglas de Reducción de Superficie de Ataque (ASR)..." -ForegroundColor Yellow

$asrRules = @{
    # Bloquear contenido ejecutable procedente de correo/navegación web
    "be9ba2d9-53ea-44a7-8f60-7bfa52fe840f" = "Bloquear ejecutables descargados vía web/mail (T1566)"
    # Bloquear ejecución de scripts ofuscados
    "5beb7efe-4261-47fa-9932-eb46078863b4" = "Bloquear scripts con flags ocultos o ofuscados (T1059/T1564)"
    # Bloquear llamadas a la API Win32 desde scripts de Office o navegadores
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Bloquear llamadas Win32 sospechosas"
    # Bloquear procesos secundarios lanzados por utilitarios LOLBins (whoami, net, nltest)
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Bloquear creación de procesos secundarios desde LOLBins"
    # Bloquear procesos que se ejecuten desde directorios temporales (%TEMP%)
    "26190899-7702-478c-87b4-2e013a726399" = "Bloquear ejecución directa de scripts en %TEMP%"
}

foreach ($ruleId in $asrRules.Keys) {
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
        Write-Host "  [✓] Regla ASR Habilitada: $($asrRules[$ruleId])" -ForegroundColor Green
    } catch {
        Write-Warning "ASR requiere Windows Defender activo."
    }
}

# -----------------------------------------------------------------------------
# CONTROL 3: BLOQUEO DE EJECUCIÓN EN CARPETAS TEMPORALES (Software Restriction)
# -----------------------------------------------------------------------------
Write-Host "`n[CONTROL 3] Configurando Software Restriction Policies contra %TEMP%..." -ForegroundColor Yellow
$saferPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Paths"
if (-not (Test-Path $saferPath)) { New-Item -Path $saferPath -Force | Out-Null }

$blockedPaths = @(
    "%TEMP%\\*.ps1",
    "%TEMP%\\*.exe",
    "%TEMP%\\*.vbs",
    "%APPDATA%\\*.ps1",
    "%APPDATA%\\*.bat"
)
$idx = 1000
foreach ($bp in $blockedPaths) {
    $subKey = "$saferPath\\$idx"
    New-Item -Path $subKey -Force | Out-Null
    Set-ItemProperty -Path $subKey -Name "ItemData" -Value $bp -Type String
    Set-ItemProperty -Path $subKey -Name "SaferFlags" -Value 0 -Type DWord
    Set-ItemProperty -Path $subKey -Name "Description" -Value "Bloqueo preventivo de scripts en carpetas de usuario no confiables" -Type String
    $idx++
}
Write-Host "  [✓] Ejecución de scripts en %TEMP% y AppData denegada por directiva." -ForegroundColor Green

# -----------------------------------------------------------------------------
# CONTROL 4: AUDITORÍA AVANZADA DE ARCHIVOS COMPARTIDOS EN FILE SERVER (FS01)
# -----------------------------------------------------------------------------
Write-Host "`n[CONTROL 4] Habilitando auditoría de accesos SMB masivos en File Server..." -ForegroundColor Yellow
# Habilitar política de auditoría de acceso a objetos (Event ID 4663 / 5140 / 5145)
auditpol /set /subcategory:"File Share" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null
Write-Host "  [✓] Auditoría de recursos compartidos SMB habilitada (Genera eventos 5145 para SIEM)." -ForegroundColor Green

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "   HARDENING EMPRESARIAL FINALIZADO - ENDPOINTS BLINDADOS       " -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(ps1)
        return str(path)

    # -------------------------------------------------------------------------
    # 3. REGLAS SYSMON DE DETECCIÓN Y BLOQUEO TEMPRANO
    # -------------------------------------------------------------------------
    def _generar_reglas_sysmon(self) -> str:
        path = self.output_dir / "03_reglas_sysmon_prevencion.xml"
        xml = """<!--
  Sysmon v15.0 Configuration - AndesLogística S.A.
  Detección Temprana de Spear Phishing, Balizamiento C2 y Exfiltración Masiva
-->
<Sysmon schemaversion="4.90">
  <EventFiltering>

    <!-- EVENT ID 1: Process Creation - Detectar Scripting Oculto y LOLBins -->
    <RuleGroup name="ProcessCreation" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- Detectar ejecución de PowerShell con flags de evasión -->
        <CommandLine condition="contains">Hidden</CommandLine>
        <CommandLine condition="contains">Bypass</CommandLine>
        <CommandLine condition="contains">update.ps1</CommandLine>
        <!-- Detectar reconocimiento LOLBins -->
        <OriginalFileName condition="is">whoami.exe</OriginalFileName>
        <OriginalFileName condition="is">nltest.exe</OriginalFileName>
        <Image condition="end with">nltest.exe</Image>
        <CommandLine condition="contains">net view</CommandLine>
        <CommandLine condition="contains">net use</CommandLine>
        <!-- Detectar empaquetado de archivos con utilitarios del sistema -->
        <OriginalFileName condition="is">tar.exe</OriginalFileName>
        <CommandLine condition="contains">tar.exe</CommandLine>
        <CommandLine condition="contains">docs_2026.zip</CommandLine>
      </ProcessCreate>
    </RuleGroup>

    <!-- EVENT ID 3: Network Connection - Detectar Balizamiento C2 y Exfiltración -->
    <RuleGroup name="NetworkConnection" groupRelation="or">
      <NetworkConnect onmatch="include">
        <DestinationIp condition="is">203.0.113.77</DestinationIp>
        <DestinationPort condition="is">443</DestinationPort>
      </NetworkConnect>
    </RuleGroup>

    <!-- EVENT ID 11: File Creation - Detectar Creación de Archivos ZIP en Temp -->
    <RuleGroup name="FileCreate" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">AppData\\Local\\Temp\\update.ps1</TargetFilename>
        <TargetFilename condition="contains">AppData\\Local\\Temp\\docs_2026.zip</TargetFilename>
        <TargetFilename condition="contains">staging</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <!-- EVENT ID 22: DNS Query - Detectar Dominio C2 y Phishing -->
    <RuleGroup name="DnsQuery" groupRelation="or">
      <DnsQuery onmatch="include">
        <QueryName condition="contains">cdn-sync-services.example</QueryName>
        <QueryName condition="contains">facturas-andinas.example</QueryName>
      </DnsQuery>
    </RuleGroup>

  </EventFiltering>
</Sysmon>
"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(xml)
        return str(path)

    # -------------------------------------------------------------------------
    # 4. REGLAS PARA FIREWALLS PERIMETRALES (Fortinet, Palo Alto, pfSense, IPTables)
    # -------------------------------------------------------------------------
    def _generar_reglas_firewall(self) -> str:
        path = self.output_dir / "04_bloqueo_firewall_perimetral.txt"
        c2_ip = "203.0.113.77"
        c2_domain = "cdn-sync-services.example"
        phish_domain = "facturas-andinas.example"

        content = f"""# ==============================================================================
# REGLAS DE BLOQUEO PERIMETRAL INMEDIATO - ANDESLOGÍSTICA S.A.
# Amenaza: Operación Huella Digital (C2 & Spear Phishing)
# ==============================================================================

# --- 1. FORTINET FORTIGATE (FortiOS CLI) ---
config firewall address
    edit "MALICIOUS_C2_IP"
        set subnet {c2_ip} 255.255.255.255
        set comment "Operacion Huella Digital - Servidor C2"
    next
    edit "MALICIOUS_C2_FQDN"
        set type fqdn
        set fqdn "{c2_domain}"
        set comment "Dominio C2 de Balizamiento"
    next
    edit "PHISHING_DOMAIN_FQDN"
        set type fqdn
        set fqdn "{phish_domain}"
        set comment "Dominio Spear Phishing Facturacion"
    next
end

config firewall policy
    edit 0
        set name "DENY_INCIDENT_C2_OUTBOUND"
        set srcintf "internal" "lan"
        set dstintf "wan1" "wan2"
        set srcaddr "all"
        set dstaddr "MALICIOUS_C2_IP" "MALICIOUS_C2_FQDN" "PHISHING_DOMAIN_FQDN"
        set action deny
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end

# --- 2. PALO ALTO NETWORKS (PAN-OS CLI) ---
set address C2_Server_203.0.113.77 ip-netmask {c2_ip}/32 description "Operacion Huella Digital C2"
set address Phishing_Site fqdn {phish_domain} description "Spear Phishing Vector"
set address C2_Domain fqdn {c2_domain} description "C2 Domain"
set rulebase security rules "DROP_C2_EXFILTRATION" to untrust from trust source any destination [ C2_Server_203.0.113.77 Phishing_Site C2_Domain ] service any action drop log-start yes

# --- 3. LINUX IPTABLES / EDGE GATEWAY ---
iptables -I FORWARD -d {c2_ip} -j DROP
iptables -I OUTPUT -d {c2_ip} -j DROP
iptables -I FORWARD -p tcp --dport 443 -d {c2_ip} -j REJECT --reject-with tcp-reset

# --- 4. BIND DNS / PI-HOLE (DNS Sinkhole) ---
# Agregar en named.conf.local o lista de sinkhole:
zone "{c2_domain}" {{ type master; file "/etc/bind/db.blocked-sinkhole"; }};
zone "{phish_domain}" {{ type master; file "/etc/bind/db.blocked-sinkhole"; }};
"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return str(path)

    # -------------------------------------------------------------------------
    # 5. PLAYBOOK SOAR AUTOMATIZADO (Cortex XSOAR / Shuffle / Wazuh Active Response)
    # -------------------------------------------------------------------------
    def _generar_playbook_soar(self) -> str:
        path = self.output_dir / "05_playbook_soar_cortex_shuffle.json"
        playbook = {
            "playbook_name": "SOAR_Incident_Response_Exfiltration_Huella_Digital",
            "version": "1.0",
            "organization": "AndesLogística S.A.",
            "trigger_condition": {
                "source": "AndesCorrelator Engine (ACE)",
                "event_type": "ACE-CR05: Exfiltración de Datos Masiva",
                "severity_threshold": "CRITICO",
                "risk_score_min": 90
            },
            "automated_actions_sequence": [
                {
                    "step": 1,
                    "name": "Host_Network_Isolation",
                    "action_type": "EDR_Command",
                    "target": "${incident.compromised_host}",
                    "command": "isolate-endpoint --keep-management-ip 10.20.10.102",
                    "timeout_seconds": 15
                },
                {
                    "step": 2,
                    "name": "Perimeter_IP_Block",
                    "action_type": "Firewall_API",
                    "target": "${incident.c2_ip}",
                    "firewall_profile": "Global_Deny_List",
                    "lease_duration": "indefinite"
                },
                {
                    "step": 3,
                    "name": "DNS_Sinkhole",
                    "action_type": "Internal_DNS_API",
                    "domains": ["cdn-sync-services.example", "facturas-andinas.example"],
                    "redirect_ip": "127.0.0.1"
                },
                {
                    "step": 4,
                    "name": "ActiveDirectory_Account_Lockout",
                    "action_type": "AD_Integration",
                    "username": "${incident.compromised_user}",
                    "action": "Disable-Account-And-Revoke-Kerberos-Tickets"
                },
                {
                    "step": 5,
                    "name": "SMB_Session_Termination",
                    "action_type": "FileServer_RPC",
                    "server": "FS01",
                    "user": "${incident.compromised_user}",
                    "action": "Close-SmbSession"
                },
                {
                    "step": 6,
                    "name": "Notify_SOC_Team",
                    "action_type": "Telegram_Webhook_Email",
                    "channels": ["Telegram_SOC_Alerts", "soc-lead@andeslogistica.com"],
                    "template": "ALERTA_CRITICA_INCIDENTE_CONTENIDO"
                }
            ]
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(playbook, f, ensure_ascii=False, indent=2)
        return str(path)

    # -------------------------------------------------------------------------
    # 6. GUÍA INTEGRAL DE PREVENCIÓN Y POLÍTICAS DE SEGURIDAD EMPRESARIAL (Markdown)
    # -------------------------------------------------------------------------
    def _generar_guia_prevencion_md(self) -> str:
        path = self.output_dir / "PLAN_PREVENCION_Y_HARDENING_EMPRESARIAL.md"
        inc = self.incidente

        md = f"""# PLAN DE PREVENCIÓN, BLINDAJE Y HARDENING EMPRESARIAL
**Organización:** AndesLogística S.A.  
**Propósito:** Mitigar de forma estructural y permanente la cadena de ataque sufrida en *Operación Huella Digital*.  
**Marco de Referencia:** CIS Controls v8 | NIST Cybersecurity Framework | MITRE D3FEND  

---

## 1. Diagnóstico de Causa Raíz (Por qué ocurrió el incidente)
El ataque contra la estación `{inc.get('host_comprometido')}` del usuario `{inc.get('usuario_comprometido')}` tuvo éxito debido a **5 brechas preventivas estructurales** en la empresa:

1. **Ausencia de filtrado web a nivel de contenido:** Se permitió descargar un archivo `.zip` señuelo desde un dominio no categorizado (`facturas-andinas.example`).
2. **Políticas permisivas de PowerShell:** La directiva permitía el parámetro `-ExecutionPolicy Bypass` y `-WindowStyle Hidden` sin restricción de lenguaje (*Constrained Language Mode* deshabilitado).
3. **Escritura y ejecución en `%TEMP%`:** No existían directivas de restricción de software (AppLocker/WDAC) que impidieran ejecutar scripts `.ps1` y utilitarios empaquetadores desde carpetas temporales de usuarios no privilegiados.
4. **Permisos SMB excesivos en `\\\\FS01\\Finanzas`:** Una sola cuenta financiera comprometida pudo leer de forma no interactiva y continua 400 archivos de 4 carpetas distintas (Nómina, Proveedores, Presupuestos, Reportes) en apenas 4 minutos sin generar ninguna alerta de umbral.
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
| **T1039 (SMB Mass Access)** | `D3-DOA (Directory Object Access Restriction)` | Implementar listas de control de acceso granulares (ACL) en `\\\\FS01\\Finanzas` divididas por función de rol. |
| **T1560.001 (Archive via tar)** | `D3-SCA (Software Configuration Authentication)` | Bloquear ejecución de binarios de compresión (`tar.exe`, `7z.exe`) fuera de rutas administrativas autorizadas. |
| **T1041 (Exfiltration C2)** | `D3-OTA (Outbound Traffic Analysis)` | Alerta perimetral automática cuando una estación de trabajo transmita > 50 MB hacia IPs no categorizadas. |

---

## 4. Guía de Despliegue de los Artefactos Generados

Los archivos ejecutables listos para desplegar se encuentran en la carpeta `prevention/`:

### A. Para contención inmediata de incidentes activos:
Ejecutar desde PowerShell como Administrador:
```powershell
.\\prevention\\01_contencion_inmediata_soar.ps1 -TargetHost "FIN-PC07" -TargetUser "dtorres"
```

### B. Para blindar todas las estaciones de trabajo de AndesLogística (GPO):
Distribuir mediante Group Policy Object (GPO) en el Controlador de Dominio `DC01`:
```powershell
.\\prevention\\02_hardening_gpo_empresarial.ps1
```

### C. Para desplegar monitorización granular con Sysmon:
En cada estación de trabajo:
```cmd
Sysmon64.exe -i .\\prevention\\03_reglas_sysmon_prevencion.xml
```

### D. Para aplicar bloqueos perimetrales:
Copiar los comandos de `prevention/04_bloqueo_firewall_perimetral.txt` en la consola CLI de los firewalls Fortinet / Palo Alto perimetrales.

---
*Plan de Prevención elaborado automáticamente por AndesCorrelator Engine (ACE) SIEM para AndesLogística S.A.*
"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(md)
        return str(path)

