#!/bin/sh
# Cross-compile the server and its OpenBSD test binaries.
#
#   scripts/build.sh VERSION GOARCH OUTDIR
#
# Produces OUTDIR/obsd-mcp and OUTDIR/tests/<pkg>.test for every package that
# has tests, so the OpenBSD VM needs no Go toolchain.
set -eu

[ $# -eq 3 ] || { echo "usage: $0 VERSION GOARCH OUTDIR" >&2; exit 2; }
version=$1 arch=$2 out=$3
module=github.com/caseyrobb/openbsd-mcp-server

export CGO_ENABLED=0 GOOS=openbsd GOARCH="$arch"
mkdir -p "$out/tests"

go build -trimpath \
	-ldflags "-s -w -X $module/internal/mcpserver.Version=$version" \
	-o "$out/obsd-mcp" ./cmd/obsd-mcp

for pkg in $(go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./...); do
	go test -c -trimpath -o "$out/tests/$(basename "$pkg").test" "$pkg"
done
