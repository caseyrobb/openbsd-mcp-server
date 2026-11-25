#!/bin/sh
# Build an OpenBSD package with pkg_create(1). Runs on OpenBSD (the CI VM),
# as an unprivileged user.
#
#   scripts/mkpkg.sh PKG_VERSION BINARY OUTDIR
#
# The package is named obsd-mcp-<version>-<arch>, with the architecture as
# the flavor, so the amd64 and arm64 files can sit side by side in one
# GitHub release (pkg_add requires the file name to match the package name).
# Install with: doas pkg_add -D unsigned ./obsd-mcp-<version>-<arch>.tgz
set -eu

[ $# -eq 3 ] || { echo "usage: $0 PKG_VERSION BINARY OUTDIR" >&2; exit 2; }
pkgver=$1 bin=$2 out=$3

if ! printf '%s\n' "$pkgver" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+((alpha|beta|pre|rc)[0-9]+)?$'; then
	echo "mkpkg.sh: bad package version '$pkgver'" >&2
	exit 1
fi

flavor=$(uname -m)   # amd64, arm64
machine=$(arch -s)   # MACHINE_ARCH recorded in @arch: amd64, aarch64
name="obsd-mcp-$pkgver-$flavor"
src=$(pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fake=$work/fake
doc=share/doc/obsd-mcp
install -d "$fake/usr/local/libexec" "$fake/usr/local/$doc"
install -m 0555 "$bin" "$fake/usr/local/libexec/obsd-mcp"
for f in README.md LICENSE docs/ARCHITECTURE.md; do
	install -m 0444 "$src/$f" "$fake/usr/local/$doc/"
done

cat >"$work/PLIST" <<EOF
@bin libexec/obsd-mcp
$doc/
$doc/ARCHITECTURE.md
$doc/LICENSE
$doc/README.md
EOF

mkdir -p "$out"
pkg_create \
	-A "$machine" \
	-B "$fake" \
	-p /usr/local \
	-D COMMENT="read-only MCP server for the OpenBSD base system" \
	-D MAINTAINER="Casey Robb" \
	-D HOMEPAGE=https://github.com/caseyrobb/openbsd-mcp-server \
	-D FULLPKGPATH=local/obsd-mcp \
	-D PERMIT_PACKAGE_CDROM=yes \
	-D PERMIT_PACKAGE_FTP=yes \
	-D REVISION_CHECK= \
	-D EPOCH_CHECK= \
	-D FLAVOR_LIST_CHECK="amd64 arm64" \
	-d "$src/pkg/DESCR" \
	-f "$work/PLIST" \
	"$out/$name.tgz"

pkg_info -f "$out/$name.tgz" | sed -n '1,/^@arch/p'
echo "built $out/$name.tgz"
