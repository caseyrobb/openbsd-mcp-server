// Package deploy generates host configuration snippets for the operator to
// review and install. It only returns text: nothing here writes a file.
package deploy

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
)

// PackagePath is where the pkg_add package installs the server.
const PackagePath = "/usr/local/libexec/obsd-mcp"

// safePath limits the server path to characters that need no quoting in
// sshd_config, authorized_keys command="..." or the $SHELL -c that sshd
// runs forced commands through.
var safePath = regexp.MustCompile(`^/[A-Za-z0-9._+/-]+$`)

// Command is the forced command line: the server binary plus -enable for
// the enabled features, in canonical order.
func Command(binary string, en basecmd.Enabled) (string, error) {
	if !safePath.MatchString(binary) || path.Clean(binary) != binary {
		return "", fmt.Errorf("server path %q must be absolute, clean and contain only [A-Za-z0-9._+/-]", binary)
	}
	if f := en.List(); len(f) > 0 {
		return binary + " -enable " + strings.Join(f, ","), nil
	}
	return binary, nil
}

// SSHDConfig returns an sshd_config(5) Match block that pins user to the
// server: public-key login only, no forwarding of any kind, no TTY and no
// ~/.ssh/rc. ForceCommand overrides any command the client asks for and any
// command= in authorized_keys, so the account can only ever start the
// server, with exactly the features chosen here.
func SSHDConfig(user, binary string, en basecmd.Enabled) (string, error) {
	if !basecmd.ValidUser(user) {
		return "", fmt.Errorf("invalid user name %q", user)
	}
	cmd, err := Command(binary, en)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, `# obsd-mcp: sshd_config(5) block for user %[1]s.
# Append to /etc/ssh/sshd_config, then check and reload:
#   doas sshd -t && doas rcctl reload sshd
# Also restrict each key in ~%[1]s/.ssh/authorized_keys:
#   restrict,command="%[2]s" ssh-ed25519 AAAA... comment
Match User %[1]s
	ForceCommand %[2]s
	AuthenticationMethods publickey
	DisableForwarding yes
	PermitTTY no
	PermitTunnel no
	PermitUserRC no
# End the block so lines added later stay global.
Match all
`, user, cmd)
	return b.String(), nil
}
