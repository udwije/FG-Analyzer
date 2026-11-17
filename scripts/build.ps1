$ErrorActionPreference='Stop'; $env:CGO_ENABLED='0'; $env:GOOS='windows'; $env:GOARCH='amd64'; go mod tidy; go test ./...; go build -trimpath -ldflags '-s -w' -o logsikka.exe .
