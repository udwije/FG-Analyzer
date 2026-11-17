$name='LogSikka'; Stop-Service $name -Force -ErrorAction SilentlyContinue; sc.exe delete $name; Remove-NetFirewallRule -DisplayName 'LogSikka Syslog TCP' -ErrorAction SilentlyContinue
