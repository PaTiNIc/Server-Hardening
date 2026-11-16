# Harden-DomainController.ps1
# Zusätzliche CIS-Level-1-Maßnahmen für Domain Controller
# Ausführung als Administrator, nach der AD-DS-Hochstufung.

param(
    [string]$LogDir = "C:\Logs",
    [string]$LogPath = (Join-Path $LogDir ("DC-Hardening_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss')))
)

if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory | Out-Null
}

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Tee-Object -FilePath $LogPath -Append
}

# Sicherheitsprüfung: Skript nur auf einem Domain Controller ausführen (ProductType 2)
if ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 2) {
    Write-Log "Abbruch: Dieser Server ist kein Domain Controller."
    exit 1
}

Write-Log "Starte DC-spezifisches Hardening..."

# 1. LDAP-Signierung erforderlich (2)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LDAPServerIntegrity" -Value 2 -Type DWord -Force
Write-Log "LDAP-Signierung erforderlich gesetzt"

# 2. Kerberos auf AES128 und AES256 beschränken (24, ohne RC4)
#    GPO-Pfad für "Konfiguration der unterstützten Verschlüsselungstypen für Kerberos"
$kerbPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\Kerberos\Parameters"
if (-not (Test-Path $kerbPath)) { New-Item -Path $kerbPath -Force | Out-Null }
Set-ItemProperty -Path $kerbPath -Name "SupportedEncryptionTypes" -Value 24 -Type DWord -Force
Write-Log "Kerberos auf AES128 und AES256 beschränkt (Wert 24)"

# 3. DC-Firewallregeln nur anlegen, wenn sie noch nicht existieren
$dcRules = @(
    @{ Name = "AD LDAP";     Protocol = "TCP";     Port = 389 },
    @{ Name = "AD Kerberos"; Protocol = "TCP,UDP"; Port = 88 },
    @{ Name = "AD DNS";      Protocol = "TCP,UDP"; Port = 53 }
)
foreach ($rule in $dcRules) {
    if (-not (Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Action Allow `
            -Protocol $rule.Protocol -LocalPort $rule.Port | Out-Null
        Write-Log "Firewallregel angelegt: $($rule.Name)"
    } else {
        Write-Log "Firewallregel bereits vorhanden: $($rule.Name)"
    }
}

Write-Log "DC-Hardening abgeschlossen. Neustart empfohlen."
