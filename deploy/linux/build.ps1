# Build the Linux package on Windows (PowerShell, from the source folder): .\deploy\linux\build.ps1
# v6.0.12: stops on the first failure. No package is written unless tests and the build both pass.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')
function Step($what, [scriptblock]$cmd) {
    & $cmd
    if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE) - no package was created" }
}
$m = Select-String -Path main.go -Pattern 'const version = "([^"]+)"'
if (-not $m) { throw 'cannot read the version from main.go' }
$version = $m.Matches[0].Groups[1].Value
$archive = "logsikka-linux-$version.tar.gz"
if (Test-Path $archive) { Remove-Item -Force $archive }
Step 'go mod tidy' { go mod tidy }
Step 'go vet' { go vet ./... }
Step 'go test' { go test ./... }
if (Test-Path dist) { Remove-Item -Recurse -Force dist }
New-Item -ItemType Directory dist | Out-Null
$env:CGO_ENABLED = '0'; $env:GOOS = 'linux'; $env:GOARCH = 'amd64'
try { Step 'go build' { go build -trimpath -ldflags '-s -w' -o dist\logsikka . } }
finally { Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED }
if (-not (Test-Path dist\logsikka)) { throw 'dist\logsikka is missing - no package was created' }
Copy-Item deploy\linux\* dist\ -Force
Step 'tar' { tar -czf $archive -C dist . }
Write-Host "Built $archive - copy it: scp -P 22222 $archive <user>@<server>:~"
