#!/bin/sh
# Run the cross-compiled test binaries on OpenBSD (used inside the CI VM).
# Each binary runs from its package directory, like "go test" does.
#
#   scripts/vmtest.sh OUTDIR
set -eu

[ $# -eq 1 ] || { echo "usage: $0 OUTDIR" >&2; exit 2; }
out=$(cd "$1" && pwd)
root=$(pwd)

if [ "$(id -u)" -eq 0 ]; then
	echo "vmtest.sh: run as an unprivileged user" >&2
	exit 1
fi

uname -a
fail=0
for t in "$out"/tests/*.test; do
	name=$(basename "$t" .test)
	dir=$(find "$root/internal" "$root/cmd" -type d -name "$name" | head -n 1)
	echo "=== $name ($dir)"
	(cd "$dir" && "$t" -test.v) || fail=1
done
exit $fail
