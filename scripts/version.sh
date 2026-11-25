#!/bin/sh
# Derive the release version from git tags (semantic versioning).
#
# Release tags are vMAJOR.MINOR.PATCH, optionally with -alpha.N, -beta.N or
# -rc.N. Output is key=value lines, suitable for $GITHUB_OUTPUT:
#
#   version      semver, embedded in the binary     0.2.0   0.2.1-dev.3+g1a2b3c4
#   pkg_version  OpenBSD package version            0.2.0   0.2.1pre3
#   release_tag  GitHub release to publish          v0.2.0  dev
#   prerelease   true for -alpha/-beta/-rc and dev builds
#
# A tag build (GITHUB_REF_TYPE=tag) uses the tag itself and fails if it is
# not valid semver. Any other build is a development build: the next patch
# version after the newest stable tag reachable from HEAD, with the number of
# commits since that tag. OpenBSD orders "pre" before the plain version, so
# 0.2.1pre3 < 0.2.1 for pkg_add -u.
set -eu

stable='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
release='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(alpha|beta|rc)\.(0|[1-9][0-9]*))?$'

emit() {
	printf 'version=%s\npkg_version=%s\nrelease_tag=%s\nprerelease=%s\n' "$1" "$2" "$3" "$4"
}

if [ "${GITHUB_REF_TYPE:-}" = tag ]; then
	tag=$GITHUB_REF_NAME
	if ! printf '%s\n' "$tag" | grep -Eq "$release"; then
		echo "version.sh: tag '$tag' is not vMAJOR.MINOR.PATCH[-(alpha|beta|rc).N]" >&2
		exit 1
	fi
	v=${tag#v}
	case $v in
	*-*)
		# 1.0.0-rc.2 -> 1.0.0rc2
		core=${v%%-*} pre=${v#*-}
		emit "$v" "$core${pre%%.*}${pre#*.}" "$tag" true
		;;
	*) emit "$v" "$v" "$tag" false ;;
	esac
	exit 0
fi

sha=$(git rev-parse --short=7 HEAD)
base=$(git tag --merged HEAD --list 'v*' | grep -E "$stable" | sort -V | tail -n 1 || true)
if [ -n "$base" ]; then
	n=$(git rev-list --count "$base..HEAD")
else
	base=v0.0.0
	n=$(git rev-list --count HEAD)
fi
v=${base#v}
if [ "$n" -eq 0 ]; then
	# HEAD is exactly a stable tag.
	emit "$v" "$v" dev true
	exit 0
fi
major=${v%%.*} rest=${v#*.}
minor=${rest%%.*} patch=${rest#*.}
next="$major.$minor.$((patch + 1))"
emit "$next-dev.$n+g$sha" "${next}pre$n" dev true
