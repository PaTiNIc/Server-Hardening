## Check-Compliance.ps1
# Prüft die CIS-Level-1-Controls aus Common-Hardening.ps1, Harden-DomainController.ps1
# und Harden-Fileserver.ps1. Ändert keine Einstellungen. Ausführung als Administrator.

param(
    [string]$LogDir = "C:\Logs"
)

if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory | Out-Null }
$LogFile = Join-Path $LogDir ("Check-Compliance_{0}_{1}.log" -f $env:COMPUTERNAME, (Get-Date -Format "yyyyMMdd-HHmm"))

$results = New-Object System.Collections.Generic.List[object]

function Add-Check {
    param([string]$Id, [string]$Name, [bool]$Pass, [string]$Detail = "")
    $script:results.Add([pscustomobject]@{ Id = $Id; Name = $Name; Pass = $Pass; Detail = $Detail })
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
}

# Rollenerkennung: ProductType 2 = Domain Controller
$isDC = (Get-CimInstance Win32_OperatingSystem).ProductType -eq 2

# --- Allgemeine Controls (Basisskript) ---

$smb = Get-SmbServerConfiguration
Add-Check "SMB-01" "SMBv1 deaktiviert" (-not $smb.EnableSMB1Protocol) "EnableSMB1Protocol=$($smb.EnableSMB1Protocol)"
Add-Check "SMB-02" "SMB-Signierung erzwungen (Server)" ($smb.RequireSecuritySignature -eq $true) "RequireSecuritySignature=$($smb.RequireSecuritySignature)"

$smbc = Get-SmbClientConfiguration
Add-Check "SMB-03" "SMB-Signierung erzwungen (Client)" ($smbc.RequireSecuritySignature -eq $true) "RequireSecuritySignature=$($smbc.RequireSecuritySignature)"

$fw = Get-NetFirewallProfile
$fwOff = @($fw | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
Add-Check "FW-01" "Windows-Firewall in allen Profilen aktiv" ($fwOff.Count -eq 0) ("Deaktiviert: " + ($fwOff -join ", "))

$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$enableLua = Get-RegValue $uacPath "EnableLUA"
Add-Check "UAC-01" "UAC aktiv" ($enableLua -eq 1) "EnableLUA=$enableLua"
$consent = Get-RegValue $uacPath "ConsentPromptBehaviorAdmin"
Add-Check "UAC-02" "Zustimmungsabfrage für Administratoren" ($consent -eq 2) "ConsentPromptBehaviorAdmin=$consent"

$rdpPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$secLayer = Get-RegValue $rdpPath "SecurityLayer"
Add-Check "RDP-01" "RDP nur mit TLS (SecurityLayer 2)" ($secLayer -eq 2) "SecurityLayer=$secLayer"

# Audit-Unterkategorien über GUID (unabhängig von der Systemsprache)
$auditRows = auditpol /get /category:* /r | ConvertFrom-Csv
$guidProp = ($auditRows[0].PSObject.Properties | Where-Object { $_.Name -match 'GUID' }).Name
$inclProp = ($auditRows[0].PSObject.Properties | Where-Object { $_.Name -match 'Aufnahme|Inclusion|Einschluss' }).Name

$auditChecks = @(
    @{ Id = "AUD-01"; Guid = "{0CCE923F-69AE-11D9-BED3-505054503030}"; Name = "Audit Kontoanmeldung (Credential Validation)" },
    @{ Id = "AUD-02"; Guid = "{0CCE9215-69AE-11D9-BED3-505054503030}"; Name = "Audit Anmeldung (Logon)" },
    @{ Id = "AUD-03"; Guid = "{0CCE9216-69AE-11D9-BED3-505054503030}"; Name = "Audit Abmeldung (Logoff)" },
    @{ Id = "AUD-04"; Guid = "{0CCE9235-69AE-11D9-BED3-505054503030}"; Name = "Audit Benutzerkontoverwaltung" },
    @{ Id = "AUD-05"; Guid = "{0CCE922B-69AE-11D9-BED3-505054503030}"; Name = "Audit Prozesserstellung" },
    @{ Id = "AUD-06"; Guid = "{0CCE922F-69AE-11D9-BED3-505054503030}"; Name = "Audit Überwachungsrichtlinienänderung" }
)
foreach ($a in $auditChecks) {
    $row = $auditRows | Where-Object { $_.$guidProp -ieq $a.Guid } | Select-Object -First 1
    if ($row) {
        $v = $row.$inclProp
        $ok = ($v -match 'Erfolg|Success') -and ($v -match 'Fehler|Failure')
        Add-Check $a.Id $a.Name $ok "Einstellung: $v"
    } else {
        Add-Check $a.Id $a.Name $false "GUID nicht gefunden: $($a.Guid)"
    }
}

# --- Rollenspezifische Controls ---

if ($isDC) {
    $ldap = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LDAPServerIntegrity"
    Add-Check "DC-01" "LDAP-Signierung erforderlich" ($ldap -eq 2) "LDAPServerIntegrity=$ldap"

    # GPO-Pfad für Kerberos-Verschlüsselungstypen; 24 = AES128 + AES256 (ohne RC4)
    $kerbPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\Kerberos\Parameters"
    $kerb = Get-RegValue $kerbPath "SupportedEncryptionTypes"
    Add-Check "DC-02" "Kerberos auf AES128/AES256 beschränkt" ($kerb -eq 24) "SupportedEncryptionTypes=$kerb"
} else {
    $cs = Get-CimInstance Win32_ComputerSystem
    Add-Check "FS-01" "Server ist Domänenmitglied" ([bool]$cs.PartOfDomain) "PartOfDomain=$($cs.PartOfDomain)"

    $rdpRules = Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayGroup -match 'Remote|Desktop' }
    $rdpOn = @($rdpRules | Where-Object { $_.Enabled -eq 'True' -or $_.Enabled -eq $true }).Count -gt 0
    Add-Check "FS-02" "RDP-Firewallregel aktiv (Standardgruppe)" $rdpOn "Regeln in Gruppe: $($rdpRules.Count)"
}

# --- Auswertung ---

$passed = @($results | Where-Object Pass).Count
$total  = $results.Count

$lines = @()
$lines += "=== CIS Compliance Check ==="
$lines += "Datum:    $(Get-Date -Format 'dd.MM.yyyy HH:mm')"
$lines += ""
foreach ($r in $results) {
    $status = if ($r.Pass) { "PASS" } else { "FAIL" }
    $lines += "{0,-8} {1,-48} {2}  ({3})" -f $r.Id, $r.Name, $status, $r.Detail
}
$lines += ""
$lines += "Ergebnis: $passed von $total Controls erfüllt"

$lines | Tee-Object -FilePath $LogFile
Write-Host "Log gespeichert unter: $LogFile" -ForegroundColor Cyan
