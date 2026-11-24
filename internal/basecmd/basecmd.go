// Package basecmd is the single source of truth for every external program
// this server may execute. Each entry is a fixed absolute path plus a fixed
// argument vector. Callers select a command by ID only; they can never supply
// argv. The sandbox derives its unveil(2) "x" list from this same table, so a
// binary that is not registered here cannot be executed at all on OpenBSD.
//
// Scope rule: OpenBSD base system only. Nothing under /usr/local, no ports.
package basecmd

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// ID names an allowlisted command invocation.
type ID string

// Registered command IDs.
const (
	Uname  ID = "uname"
	Uptime ID = "uptime"
	Sysctl ID = "sysctl"
	Df     ID = "df"
	Vmstat ID = "vmstat"

	Ifconfig ID = "ifconfig"
	Routes   ID = "routes"
	// PfInfo requires root (/dev/pf is 0600). It runs through doas with an
	// exact-args rule and only when the operator opts in (-pf-doas).
	PfInfo ID = "pf_info"
)

// Spec is an immutable command invocation: absolute binary path and fixed args.
type Spec struct {
	Path string
	Args []string
	// OptIn commands are not unveiled or runnable unless explicitly enabled.
	OptIn bool
}

// SysctlNames is the fixed set of MIBs queried by the system overview.
// Every name here is readable by an unprivileged user on OpenBSD.
var SysctlNames = []string{
	"kern.ostype",
	"kern.osrelease",
	"kern.version",
	"kern.boottime",
	"kern.securelevel",
	"hw.machine",
	"hw.model",
	"hw.ncpu",
	"hw.ncpuonline",
	"hw.physmem",
	"hw.usermem",
	"vm.loadavg",
}

var registry = map[ID]Spec{
	Uname:  {Path: "/usr/bin/uname", Args: []string{"-a"}},
	Uptime: {Path: "/usr/bin/uptime"},
	Sysctl: {Path: "/sbin/sysctl", Args: SysctlNames},
	Df:     {Path: "/bin/df", Args: []string{"-h"}},
	Vmstat: {Path: "/usr/bin/vmstat"},

	Ifconfig: {Path: "/sbin/ifconfig"},
	Routes:   {Path: "/usr/bin/netstat", Args: []string{"-rn"}},
	PfInfo:   {Path: "/usr/bin/doas", Args: []string{"-n", "/sbin/pfctl", "-s", "info"}, OptIn: true},
}

// BaseDirs are the only directories registered binaries may live in.
var BaseDirs = []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin"}

// Enabled is the set of opt-in command IDs the operator has turned on.
// The zero value enables none.
type Enabled map[ID]bool

// Lookup returns a defensive copy of the spec for id. Opt-in commands are
// rejected unless present in en.
func Lookup(id ID, en Enabled) (Spec, error) {
	s, ok := registry[id]
	if !ok {
		return Spec{}, fmt.Errorf("basecmd: command %q is not allowlisted", id)
	}
	if s.OptIn && !en[id] {
		return Spec{}, fmt.Errorf("basecmd: command %q is opt-in and not enabled", id)
	}
	return Spec{Path: s.Path, Args: append([]string(nil), s.Args...), OptIn: s.OptIn}, nil
}

// IsOptIn reports whether id is a registered opt-in command.
func IsOptIn(id ID) bool { return registry[id].OptIn }

// Binaries returns the sorted, de-duplicated set of binary paths for every
// non-opt-in command plus the enabled opt-in ones. The sandbox unveils
// exactly these with "x".
func Binaries(en Enabled) []string {
	seen := map[string]bool{}
	var out []string
	for id, s := range registry {
		if s.OptIn && !en[id] {
			continue
		}
		if !seen[s.Path] {
			seen[s.Path] = true
			out = append(out, s.Path)
		}
	}
	sort.Strings(out)
	return out
}

// Validate checks registry invariants. It is called at startup and in tests.
func Validate() error {
	for id, s := range registry {
		if err := validateSpec(s); err != nil {
			return fmt.Errorf("basecmd: %s: %w", id, err)
		}
	}
	return nil
}

func validateSpec(s Spec) error {
	if !path.IsAbs(s.Path) || path.Clean(s.Path) != s.Path {
		return fmt.Errorf("path %q must be absolute and clean", s.Path)
	}
	if !inBaseDir(s.Path) {
		return fmt.Errorf("path %q is outside base system dirs %v", s.Path, BaseDirs)
	}
	for _, a := range s.Args {
		if strings.ContainsAny(a, "\x00\n") {
			return fmt.Errorf("arg %q contains forbidden characters", a)
		}
		// An absolute-path argument is a program run by a wrapper (doas);
		// it must obey the same base-only rule.
		if strings.HasPrefix(a, "/") && (path.Clean(a) != a || !inBaseDir(a)) {
			return fmt.Errorf("arg %q is a path outside base system dirs", a)
		}
	}
	return nil
}

func inBaseDir(p string) bool {
	dir := path.Dir(p)
	for _, d := range BaseDirs {
		if dir == d {
			return true
		}
	}
	return false
}
