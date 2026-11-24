## Harden-Dateiserver.ps1
# Zusätzliche CIS-Level-1-Maßnahmen für Dateiserver
# Ausführung als Administrator, nach dem Klonen und der Rolleneinrichtung.

param(
    [string]$LogDir = "C:\Logs",
    [string]$LogPath = (Join-Path $LogDir ("Fileserver-Hardening_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss')))
)

if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory | Out-Null
}

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Tee-Object -FilePath $LogPath -Append
}

Write-Log "Starte Dateiserver-spezifisches Hardening..."

# 1. Domänenmitgliedschaft prüfen
$cs = Get-CimInstance Win32_ComputerSystem
if (-not $cs.PartOfDomain) {
    Write-Log "Abbruch: Server ist nicht in einer Domäne. Bitte zuerst der Domäne beitreten."
    exit 1
}
Write-Log "Domänenmitgliedschaft bestätigt: $($cs.Domain)"

# 2. Standardfreigabe-Regel für Remote Desktop aktivieren (nur bei Bedarf)
#    Die Regel "Remotedesktop" ist eine Windows-Standardregel und wird hier nur aktiviert, nicht neu angelegt.
Enable-NetFirewallRule -DisplayGroup "Remotedesktop" -ErrorAction SilentlyContinue
Write-Log "Standardregel Remotedesktop aktiviert (Port 3389, nur Domänenprofil empfohlen)"

# 3. Gruppenrichtlinien aktualisieren
gpupdate /force | Out-Null
Write-Log "Gruppenrichtlinien aktualisiert"

Write-Log "Dateiserver-Hardening abgeschlossen."
