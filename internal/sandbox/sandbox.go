// Package sandbox computes and applies the OpenBSD unveil(2)/pledge(2) policy.
//
// The policy is computed portably (so it can be unit-tested anywhere) and
// applied only on OpenBSD; see sandbox_openbsd.go / sandbox_other.go.
package sandbox

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

// Promises is the final pledge(2) set after initialisation:
//
//	stdio - MCP JSON-RPC over stdin/stdout, pipes to children, memory, time
//	rpath - read allowlisted config files and /dev/null
//	proc  - fork(2) for os/exec, and kill(2) of our own timed-out children
//	exec  - execve(2) of the unveiled base binaries
//
// Deliberately absent: wpath cpath dpath fattr chown (no writes), inet unix
// dns (stdio transport only; the network hop is sshd's job), id settime
// unveil (unveil is locked), tty, ps/vminfo (children query those, not us).
const Promises = "stdio rpath proc exec"

// ErrUnsupported is returned by Apply on systems without pledge/unveil.
var ErrUnsupported = errors.New("sandbox: pledge/unveil not supported on this OS")

// Rule is a single unveil(2) call.
type Rule struct {
	Path  string
	Perms string // subset of "rx" only; never w or c
}

// Policy is the complete sandbox policy.
type Policy struct {
	Unveil   []Rule
	Promises string
}

// forbiddenPrefixes may never be unveiled: ports/packages and secret stores.
var forbiddenPrefixes = []string{
	"/usr/local", "/etc/pkg", "/var/db/pkg", "/usr/ports", "/usr/X11R6",
	"/etc/master.passwd", "/etc/spwd.db", "/etc/doas.conf", "/etc/iked.conf", "/etc/ipsec.conf", "/etc/ssl/private", "/etc/ssh/ssh_host_",
	"/etc/isakmpd/private", "/etc/iked/private", "/root", "/home",
}

// NewPolicy builds the policy from executable paths (unveiled "x") and
// readable file paths (unveiled "r"). Individual files are unveiled, never
// whole directories, so even a bug in later path validation cannot reach a
// sibling such as /etc/master.passwd.
func NewPolicy(binaries, readFiles []string) (Policy, error) {
	p := Policy{Promises: Promises}
	// os/exec opens /dev/null for a child's stdin.
	reads := append([]string{"/dev/null"}, readFiles...)
	for _, b := range binaries {
		if err := checkPath(b); err != nil {
			return Policy{}, err
		}
		p.Unveil = append(p.Unveil, Rule{Path: b, Perms: "x"})
	}
	for _, r := range reads {
		if err := checkPath(r); err != nil {
			return Policy{}, err
		}
		p.Unveil = append(p.Unveil, Rule{Path: r, Perms: "r"})
	}
	sort.Slice(p.Unveil, func(i, j int) bool { return p.Unveil[i].Path < p.Unveil[j].Path })
	return p, nil
}

func checkPath(p string) error {
	if !path.IsAbs(p) || path.Clean(p) != p {
		return fmt.Errorf("sandbox: path %q must be absolute and clean", p)
	}
	if p == "/" || strings.HasSuffix(p, "/") {
		return fmt.Errorf("sandbox: refusing to unveil directory-like path %q", p)
	}
	for _, f := range forbiddenPrefixes {
		if p == f || strings.HasPrefix(p, f+"/") || (strings.HasSuffix(f, "_") && strings.HasPrefix(p, f)) {
			return fmt.Errorf("sandbox: path %q is forbidden", p)
		}
	}
	return nil
}

// String renders the policy as the equivalent C calls, for -print-policy.
func (p Policy) String() string {
	var b strings.Builder
	for _, r := range p.Unveil {
		fmt.Fprintf(&b, "unveil(%q, %q);\n", r.Path, r.Perms)
	}
	b.WriteString("unveil(NULL, NULL);\n")
	fmt.Fprintf(&b, "pledge(%q, NULL);\n", p.Promises)
	return b.String()
}
