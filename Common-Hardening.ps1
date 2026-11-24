## Common-Hardening.ps1
# Gemeinsame CIS-Level-1-Maßnahmen für Domain Controller und Dateiserver
# Ausführung als Administrator. Neustart nach Abschluss erforderlich.

param(
    [string]$LogDir = "C:\Logs",
    [string]$LogPath = (Join-Path $LogDir ("Hardening_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss')))
)

if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory | Out-Null
}

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Tee-Object -FilePath $LogPath -Append
}

# Audit-Unterkategorien über GUID, damit das Skript unabhängig von der Systemsprache arbeitet
$auditSubcategories = @(
    @{ Name = "Kontoanmeldung (Credential Validation)"; Guid = "{0CCE923F-69AE-11D9-BED3-505054503030}" },
    @{ Name = "Anmeldung (Logon)";                      Guid = "{0CCE9215-69AE-11D9-BED3-505054503030}" },
    @{ Name = "Abmeldung (Logoff)";                     Guid = "{0CCE9216-69AE-11D9-BED3-505054503030}" },
    @{ Name = "Benutzerkontoverwaltung";                Guid = "{0CCE9235-69AE-11D9-BED3-505054503030}" },
    @{ Name = "Prozesserstellung";                      Guid = "{0CCE922B-69AE-11D9-BED3-505054503030}" },
    @{ Name = "Überwachungsrichtlinienänderung";        Guid = "{0CCE922F-69AE-11D9-BED3-505054503030}" }
)

Write-Log "Starte Common Hardening..."

# 1. Windows-Firewall in allen Profilen aktivieren
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Write-Log "Firewall in allen Profilen aktiviert"

# 2. SMBv1 deaktivieren (wirksam nach Neustart)
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Write-Log "SMBv1 deaktiviert"

# 3. SMB-Signierung auf Server und Client erzwingen
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
Write-Log "SMB-Signierung für Server und Client erzwungen"

# 4. Audit-Richtlinien (Erfolg und Fehler) über GUID setzen
foreach ($sub in $auditSubcategories) {
    auditpol /set /subcategory:"$($sub.Guid)" /success:enable /failure:enable | Out-Null
    Write-Log "Audit aktiviert: $($sub.Name)"
}

# 5. UAC aktivieren und Administrator-Eingabeaufforderung konfigurieren
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord -Force
Write-Log "UAC aktiviert, Zustimmungsabfrage für Administratoren gesetzt"

# 6. RDP nur mit TLS (SecurityLayer 2)
$rdpPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
Set-ItemProperty -Path $rdpPath -Name "SecurityLayer" -Value 2 -Type DWord -Force
Write-Log "RDP auf TLS-Sicherheitsschicht gesetzt"

# 7. 3DES (SWEET32, CVE-2016-2183) über SCHANNEL deaktivieren
$tdesPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168"
if (-not (Test-Path $tdesPath)) { New-Item -Path $tdesPath -Force | Out-Null }
Set-ItemProperty -Path $tdesPath -Name "Enabled" -Value 0 -Type DWord -Force
Write-Log "3DES (Triple DES 168) über SCHANNEL deaktiviert"

# 8. TLS 1.0 und 1.1 für Server deaktivieren
$protoBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
foreach ($proto in @("TLS 1.0", "TLS 1.1")) {
    $p = "$protoBase\$proto\Server"
    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
    Set-ItemProperty -Path $p -Name "Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $p -Name "DisabledByDefault" -Value 1 -Type DWord -Force
    Write-Log "$proto Server deaktiviert"
}

# 9. TLS 1.2 für Server aktivieren
$p12 = "$protoBase\TLS 1.2\Server"
if (-not (Test-Path $p12)) { New-Item -Path $p12 -Force | Out-Null }
Set-ItemProperty -Path $p12 -Name "Enabled" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $p12 -Name "DisabledByDefault" -Value 0 -Type DWord -Force
Write-Log "TLS 1.2 Server aktiviert"

Write-Log "Common Hardening abgeschlossen. Neustart erforderlich, bevor der Compliance-Check läuft."
