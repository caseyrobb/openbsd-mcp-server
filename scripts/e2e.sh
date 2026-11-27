#!/bin/sh
# End-to-end test of the built package, run in the OpenBSD CI VM as an
# unprivileged user with sudo. It installs the package, sets up the
# server account exactly as the README describes (useradd, -print-doas,
# -print-sshd, a restricted authorized_keys line), then runs the e2e test
# binary, which talks MCP to the server over ssh to that account.
#
# usage: e2e.sh PACKAGE.tgz E2E_TEST_BINARY FEATURES VERSION
#
# This changes the host (package, user, doas.conf, sshd_config); it is
# meant for a throwaway VM only.
set -eu

pkg=$1 testbin=$2 feats=$3 version=$4
user=obsdmcp
bin=/usr/local/libexec/obsd-mcp
home=/home/$user

[ "$(id -u)" -ne 0 ] || { echo "run as an unprivileged user with sudo" >&2; exit 1; }

echo "== install $pkg"
sudo pkg_add -D unsigned "$pkg"
# The forced command must not be replaceable by anyone but root.
ls -l "$bin"
[ "$(stat -f '%Su %Lp' "$bin")" = "root 555" ] ||
	{ echo "unexpected owner/mode on $bin" >&2; exit 1; }
"$bin" -version

echo "== account and privileges"
sudo useradd -m -s /bin/ksh -c "read-only MCP" "$user"
"$bin" -enable "$feats" -print-doas "$user" | sudo tee -a /etc/doas.conf
sudo doas -C /etc/doas.conf

warn=$(mktemp)
"$bin" -enable "$feats" -print-sshd "$user" 2>"$warn" | sudo tee -a /etc/ssh/sshd_config
if [ -s "$warn" ]; then
	echo "-print-sshd warned about the packaged binary:" >&2
	cat "$warn" >&2
	exit 1
fi
sudo sshd -t
sudo rcctl reload sshd

key=$(mktemp -d)/e2e_ed25519
ssh-keygen -q -t ed25519 -N '' -C obsd-mcp-e2e -f "$key"
sudo install -d -o "$user" -g "$user" -m 0700 "$home/.ssh"
printf 'restrict,command="%s -enable %s" %s\n' "$bin" "$feats" "$(cat "$key.pub")" |
	sudo tee "$home/.ssh/authorized_keys" >/dev/null
sudo chown "$user:$user" "$home/.ssh/authorized_keys"
sudo chmod 0600 "$home/.ssh/authorized_keys"
sleep 1 # let the reloaded sshd settle

echo "== e2e test over ssh"
OBSDMCP_E2E_SSH="$user@127.0.0.1" OBSDMCP_E2E_KEY="$key" \
OBSDMCP_E2E_FEATURES="$feats" OBSDMCP_E2E_VERSION="$version" \
	"$testbin" -test.v -test.timeout 5m
