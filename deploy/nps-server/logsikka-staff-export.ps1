<#
.SYNOPSIS
  LogSikka staff export. Runs nightly on the NPS server and writes the AD staff list (and optionally the domain
  computers) into the NPS log folder (default C:\NPSLogs), which LogSikka already reads over the share.

.DESCRIPTION
  - Writes into the same folder as the NPS logs. LogSikka's NPS reader only picks up IN*.log files, so staff.csv,
    computers.csv and staff-export.log do not interfere with NPS user mapping.
  - Uses ADSI (System.DirectoryServices): no RSAT / ActiveDirectory module needed on the NPS server.
  - Exports enabled AND disabled accounts with an Enabled column, so LogSikka can tell leavers from active staff.
  - Writes atomically (temp file, then rename), so LogSikka never reads a half-written file.
  - Safety check: if the new list has far fewer users than the last one (AD or network problem), the old file is
    kept and the run fails, instead of LogSikka marking most of the staff as leavers.

  Output (UTF-8, no BOM):
    <OutDir>\staff.csv      Username,UPN,DisplayName,Department,Title,Email,Enabled,Created,LastLogon,OU
    <OutDir>\computers.csv  Name,DNSHostName,OS,Enabled,LastLogon,OU            (only with -ComputerSearchBase)
    <OutDir>\staff-export.log

.EXAMPLE
  .\logsikka-staff-export.ps1 -SearchBase 'OU=Staff,DC=example,DC=com' `
      -ComputerSearchBase 'OU=Desktops,DC=example,DC=com'
.EXAMPLE
  # install the nightly scheduled task (run once, as an administrator)
  .\logsikka-staff-export.ps1 -SearchBase 'OU=Staff,DC=example,DC=com' `
      -ComputerSearchBase 'OU=Desktops,DC=example,DC=com' -Install -At '01:30'
#>
[CmdletBinding()]
param(
    [string] $OutDir = 'C:\NPSLogs',
    [string] $SearchBase = '',
    [string] $ComputerSearchBase = '',
    [string] $ExcludePattern = '^(svc[-_.]|sql|admin[-_.]|test|healthmailbox|krbtgt$|guest$)',
    [double] $MinRatio = 0.7,
    [switch] $Install,
    [string] $At = '01:30'
)
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)
function Write-Log([string]$msg) {
    $line = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $msg
    Write-Host $line
    try { [IO.File]::AppendAllText((Join-Path $OutDir 'staff-export.log'), $line + "`r`n", $utf8) } catch { }
}
if ($Install) {
    $script = $MyInvocation.MyCommand.Path
    $argLine = "-NoProfile -ExecutionPolicy Bypass -File `"$script`" -OutDir `"$OutDir`""
    if ($SearchBase)         { $argLine += " -SearchBase `"$SearchBase`"" }
    if ($ComputerSearchBase) { $argLine += " -ComputerSearchBase `"$ComputerSearchBase`"" }
    $action   = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argLine
    $triggers = @((New-ScheduledTaskTrigger -Daily -At $At), (New-ScheduledTaskTrigger -AtStartup))
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
                    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 10)
    Register-ScheduledTask -TaskName 'LogSikka staff export' -Action $action -Trigger $triggers `
        -Principal $principal -Settings $settings -Description 'Exports AD staff for LogSikka user mapping' -Force | Out-Null
    Write-Host "Scheduled task 'LogSikka staff export' installed (daily at $At and at startup)."
    Write-Host "Run it now with: Start-ScheduledTask -TaskName 'LogSikka staff export'"
    return
}
function New-Searcher([string]$base, [string]$filter, [string[]]$props) {
    $root = if ($base) { [ADSI]("LDAP://" + $base) } else { [ADSI]'' }
    $s = New-Object System.DirectoryServices.DirectorySearcher($root, $filter)
    $s.PageSize = 1000; $s.SearchScope = 'Subtree'
    foreach ($p in $props) { [void]$s.PropertiesToLoad.Add($p) }
    return $s
}
function P($r, [string]$name) { if ($r.Properties[$name].Count) { [string]$r.Properties[$name][0] } else { '' } }
function FileTime($r, [string]$name) {
    if (-not $r.Properties[$name].Count) { return '' }
    $v = [int64]$r.Properties[$name][0]
    if ($v -le 0) { return '' }
    return [DateTime]::FromFileTimeUtc($v).ToString('yyyy-MM-ddTHH:mm:ssZ')
}
function ParentOU([string]$dn) { ($dn -split '(?<!\\),', 2)[1] }
function Csv([object[]]$cells) {
    ($cells | ForEach-Object { '"' + ([string]$_).Replace('"', '""').Replace("`r", ' ').Replace("`n", ' ') + '"' }) -join ','
}
function Write-Atomic([string]$path, [string[]]$lines, [int]$count, [string]$what) {
    if (Test-Path $path) {
        $old = ([IO.File]::ReadAllLines($path, $utf8)).Count - 1
        if ($old -gt 20 -and $count -lt [math]::Floor($old * $MinRatio)) {
            throw "$what list has $count entries, the previous one $old (below $([int]($MinRatio*100))%). Kept the old file."
        }
    }
    $tmp = "$path.tmp"
    [IO.File]::WriteAllLines($tmp, $lines, $utf8)
    Move-Item -Path $tmp -Destination $path -Force
}
try {
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    $s = New-Searcher $SearchBase '(&(objectCategory=person)(objectClass=user))' @(
        'sAMAccountName','userPrincipalName','displayName','department','title','mail',
        'userAccountControl','whenCreated','lastLogonTimestamp','distinguishedName')
    $lines = @(Csv @('Username','UPN','DisplayName','Department','Title','Email','Enabled','Created','LastLogon','OU'))
    $n = 0; $skipped = 0
    foreach ($r in $s.FindAll()) {
        $sam = P $r 'samaccountname'
        if (-not $sam -or $sam.EndsWith('$') -or $sam -match $ExcludePattern) { $skipped++; continue }
        $uac = [int](P $r 'useraccountcontrol')
        $created = if ($r.Properties['whencreated'].Count) { ([DateTime]$r.Properties['whencreated'][0]).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' }
        $lines += Csv @($sam, (P $r 'userprincipalname'), (P $r 'displayname'), (P $r 'department'), (P $r 'title'),
                        (P $r 'mail'), ([string](-not ($uac -band 2))).ToLower(), $created,
                        (FileTime $r 'lastlogontimestamp'), (ParentOU (P $r 'distinguishedname')))
        $n++
    }
    if ($n -eq 0) { throw "No users found under '$SearchBase'. Check the OU path." }
    Write-Atomic (Join-Path $OutDir 'staff.csv') $lines $n 'Staff'
    Write-Log "staff.csv: $n accounts written ($skipped skipped by filter)"
    if ($ComputerSearchBase) {
        $c = New-Searcher $ComputerSearchBase '(objectCategory=computer)' @(
            'name','dNSHostName','operatingSystem','userAccountControl','lastLogonTimestamp','distinguishedName')
        $cl = @(Csv @('Name','DNSHostName','OS','Enabled','LastLogon','OU'))
        $m = 0
        foreach ($r in $c.FindAll()) {
            $uac = [int](P $r 'useraccountcontrol')
            $cl += Csv @((P $r 'name'), (P $r 'dnshostname'), (P $r 'operatingsystem'), ([string](-not ($uac -band 2))).ToLower(),
                         (FileTime $r 'lastlogontimestamp'), (ParentOU (P $r 'distinguishedname')))
            $m++
        }
        Write-Atomic (Join-Path $OutDir 'computers.csv') $cl $m 'Computer'
        Write-Log "computers.csv: $m computers written"
    }
    exit 0
}
catch {
    Write-Log "FAILED: $($_.Exception.Message)"
    exit 1
}
