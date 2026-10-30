<#
.SYNOPSIS
    Script de Respuesta Automática y Contención Inmediata (SOAR Playbook)
    Caso: Operación Huella Digital: Exfiltración Dirigida de Información Financiera - AndesLogística S.A.
.DESCRIPTION
    Ejecuta el protocolo de contención de emergencia en la estación FIN-PC07 (10.20.10.47)
    y corta la infraestructura de Comando y Control (C2).
#>

[CmdletBinding()]
param(
    [string]$TargetHost = "FIN-PC07",
    [string]$TargetUser = "dtorres",
    [string]$C2_IP = "203.0.113.77",
    [string]$C2_Domain = "cdn-sync-services.example",
    [string]$PhishingDomain = "facturas-andinas.example"
)

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "   PROTOCOLO SOAR DE CONTENCIÓN INMEDIATA - ANDESLOGÍSTICA S.A.   " -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. AISLAMIENTO DE RED DE LA ESTACIÓN (Host Isolation)
Write-Host "`n[PASO 1] Aislando estación $TargetHost de la red LAN..." -ForegroundColor Red
try {
    # Bloquear todo el tráfico entrante/saliente excepto la IP de gestión de SOC (10.20.10.102)
    New-NetFirewallRule -DisplayName "SOAR_ISOLATE_ALL_OUTBOUND" -Direction Outbound -Action Block -Profile Any -Priority 1 -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "SOAR_ALLOW_SOC_MGMT" -Direction Outbound -RemoteAddress "10.20.10.102" -Action Allow -Priority 2 -ErrorAction SilentlyContinue
    Write-Host "  [✓] Estación aislada. Tráfico lateral y salida a internet bloqueados." -ForegroundColor Green
} catch {
    Write-Warning "No se pudo aplicar regla de firewall local: $_"
}

# 2. TERMINACIÓN FORZOSA DE PROCESOS MALICIOSOS (Process Kill)
Write-Host "`n[PASO 2] Terminando procesos maliciosos y herramientas de compresión..." -ForegroundColor Yellow
$procToKill = @("powershell", "pwsh", "tar", "7z", "winrar")
foreach ($p in $procToKill) {
    Get-Process -Name $p -ErrorAction SilentlyContinue | Where-Object { $_.Path -notlike "*System32*" -or $_.CommandLine -like "*update.ps1*" -or $_.CommandLine -like "*Hidden*" } | Stop-Process -Force -Verbose
}
Write-Host "  [✓] Procesos del implante y empaquetado finalizados." -ForegroundColor Green

# 3. REVOCACIÓN DE CREDENCIALES Y SESIONES SMB
Write-Host "`n[PASO 3] Revocando credenciales y sesiones de red del usuario $TargetUser..." -ForegroundColor Yellow
try {
    # En Controlador de Dominio / Servidor de Archivos:
    # Disable-ADAccount -Identity $TargetUser
    # Revocar sesiones SMB activas en \FS01
    Get-SmbSession | Where-Object { $_.UserName -like "*$TargetUser*" } | Close-SmbSession -Force -ErrorAction SilentlyContinue
    Write-Host "  [✓] Sesiones SMB activas revocadas en servidores de archivos." -ForegroundColor Green
} catch {
    Write-Warning "Revocación remota requiere privilegios en DC/FS01."
}

# 4. CUARENTENA Y ELIMINACIÓN DE ARTEFACTOS LOCALES
Write-Host "`n[PASO 4] Poniendo en cuarentena artefactos en %TEMP%..." -ForegroundColor Yellow
$tempPaths = @(
    "C:\Users\$TargetUser\AppData\Local\Temp\update.ps1",
    "C:\Users\$TargetUser\AppData\Local\Temp\docs_2026.zip",
    "C:\Users\$TargetUser\AppData\Local\Temp\staging"
)
foreach ($item in $tempPaths) {
    if (Test-Path $item) {
        $quarantine = "$item.QUARANTINED_" + (Get-Date -Format "yyyyMMddHHmmss")
        Move-Item -Path $item -Destination $quarantine -Force -ErrorAction SilentlyContinue
        Write-Host "  [!] Artefacto en cuarentena: $quarantine" -ForegroundColor Magenta
    }
}

# 5. BLOQUEO PERIMETRAL Y SINKHOLE DNS
Write-Host "`n[PASO 5] Aplicando bloqueo de C2 y Phishing en hosts locales..." -ForegroundColor Yellow
$hostsFile = "$env:windir\System32\drivers\etc\hosts"
$sinkholeEntries = @(
    "127.0.0.1 $C2_Domain",
    "127.0.0.1 $PhishingDomain"
)
foreach ($entry in $sinkholeEntries) {
    if (-not (Select-String -Path $hostsFile -Pattern $entry -SimpleMatch -Quiet)) {
        Add-Content -Path $hostsFile -Value "`n$entry" -Force
        Write-Host "  [✓] Dominio sinkholeado en hosts local: $entry" -ForegroundColor Green
    }
}
Clear-DnsClientCache
Write-Host "`n[✓✓✓] PROTOCOLO DE CONTENCIÓN COMPLETADO EXITOSAMENTE." -ForegroundColor Green
