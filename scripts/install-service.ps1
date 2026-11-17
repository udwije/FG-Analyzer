param([string]$SourceDir=(Split-Path -Parent $PSScriptRoot),[string]$InstallDir="$env:ProgramFiles\LogSikka")
# v6.0: installs the "LogSikka" service. An existing FortiLogCollector service is removed and its data folder
# (C:\ProgramData\FortiLogCollector) is moved to C:\ProgramData\LogSikka the first time.
$ErrorActionPreference='Stop'; $name='LogSikka'; $data="$env:ProgramData\LogSikka"; $oldData="$env:ProgramData\FortiLogCollector"
foreach($old in 'FortiLogCollector',$name){ if(Get-Service $old -ErrorAction SilentlyContinue){Stop-Service $old -Force -ErrorAction SilentlyContinue; sc.exe delete $old | Out-Null; Start-Sleep 2} }
if((Test-Path $oldData) -and -not (Test-Path $data)){ Move-Item $oldData $data; Write-Host "Moved $oldData to $data" }
New-Item -ItemType Directory -Force $InstallDir,$data,"$data\spool" | Out-Null
Copy-Item "$SourceDir\logsikka.exe" "$InstallDir\logsikka.exe" -Force
New-Service -Name $name -BinaryPathName "`"$InstallDir\logsikka.exe`" --data `"$data`"" -DisplayName 'LogSikka' -Description 'LogSikka: receives FortiGate syslog, stores it in PostgreSQL and serves the dashboard.' -StartupType Automatic
sc.exe failure $name reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
sc.exe failureflag $name 1 | Out-Null
Remove-NetFirewallRule -DisplayName 'FortiLog Syslog TCP' -ErrorAction SilentlyContinue
if(-not(Get-NetFirewallRule -DisplayName 'LogSikka Syslog TCP' -ErrorAction SilentlyContinue)){New-NetFirewallRule -DisplayName 'LogSikka Syslog TCP' -Direction Inbound -Protocol TCP -LocalPort 6514 -Action Allow -Profile Domain | Out-Null}
Start-Service $name; Get-Service $name
