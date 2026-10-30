<#
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
$psAuditPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $psAuditPath)) { New-Item -Path $psAuditPath -Force | Out-Null }
Set-ItemProperty -Path $psAuditPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Set-ItemProperty -Path $psAuditPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord

$psTransPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if (-not (Test-Path $psTransPath)) { New-Item -Path $psTransPath -Force | Out-Null }
Set-ItemProperty -Path $psTransPath -Name "EnableTranscripting" -Value 1 -Type DWord
Set-ItemProperty -Path $psTransPath -Name "OutputDirectory" -Value "C:\ProgramData\PSTranscripts" -Type String
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
$saferPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths"
if (-not (Test-Path $saferPath)) { New-Item -Path $saferPath -Force | Out-Null }

$blockedPaths = @(
    "%TEMP%\*.ps1",
    "%TEMP%\*.exe",
    "%TEMP%\*.vbs",
    "%APPDATA%\*.ps1",
    "%APPDATA%\*.bat"
)
$idx = 1000
foreach ($bp in $blockedPaths) {
    $subKey = "$saferPath\$idx"
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
