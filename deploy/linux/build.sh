#!/usr/bin/env bash
# Build the Linux package from the source folder: ./deploy/linux/build.sh   (Go 1.22+, internet for the first go mod tidy)
# v6.0.12: stops on the first failure. No package is written unless tests and the build both pass.
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION=$(sed -n 's/^const version = "\([^"]*\)"/\1/p' main.go | head -1)
[ -n "$VERSION" ] || { echo "cannot read the version from main.go" >&2; exit 1; }
ARCHIVE="logsikka-linux-${VERSION}.tar.gz"
rm -f "$ARCHIVE"
go mod tidy
go vet ./...
go test ./...
rm -rf dist && mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/logsikka .
[ -x dist/logsikka ] || { echo "dist/logsikka is missing - no package was created" >&2; exit 1; }
cp deploy/linux/* dist/
tar -C dist -czf "$ARCHIVE" .
echo "Built $ARCHIVE - copy it to the server and run: sudo bash install.sh"
