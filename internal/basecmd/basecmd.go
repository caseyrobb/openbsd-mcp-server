// Package basecmd is the single source of truth for every external program
// this server may execute. Each entry is a fixed absolute path plus a fixed
// argument vector. Callers select a command by ID only; they can never supply
// argv. The sandbox derives its unveil(2) "x" list from this same table, and
// -print-doas derives the doas.conf(5) rules from it, so a binary or argument
// list that is not registered here cannot be executed at all on OpenBSD.
//
// Scope rule: OpenBSD base system only. Nothing under /usr/local, no ports.
package basecmd

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// ID names an allowlisted command invocation.
type ID string

// Feature groups opt-in commands. The empty Feature is always enabled.
type Feature string

// Opt-in features, enabled with -enable.
const (
	FeaturePF      Feature = "pf"      // pfctl via doas (/dev/pf is 0600 root)
	FeatureUnbound Feature = "unbound" // unbound-control via doas (socket is full-control)
	FeatureBGP     Feature = "bgp"     // bgpctl via bgpd's restricted (show-only) socket
)

// Features lists every opt-in feature in display order.
var Features = []Feature{FeaturePF, FeatureUnbound, FeatureBGP}

// DoasPath is the only privilege wrapper the server may run.
const DoasPath = "/usr/bin/doas"

// BGPRestrictedSocket is the bgpd restricted control socket bgpctl talks to.
// bgpd creates it mode 0666 and accepts only show requests on it; the
// operator enables it with: socket "/var/run/bgpd.rsock" restricted
const BGPRestrictedSocket = "/var/run/bgpd.rsock"

// Registered command IDs.
const (
	Uname  ID = "uname"
	Uptime ID = "uptime"
	Sysctl ID = "sysctl"
	Df     ID = "df"
	Vmstat ID = "vmstat"

	Ifconfig ID = "ifconfig"
	Routes   ID = "routes"

	PfInfo       ID = "pf_info"
	PfRules      ID = "pf_rules"
	PfTables     ID = "pf_tables"
	PfMemory     ID = "pf_memory"
	PfTimeouts   ID = "pf_timeouts"
	PfInterfaces ID = "pf_interfaces"
	PfQueues     ID = "pf_queues"

	UnboundStatus     ID = "unbound_status"
	UnboundStats      ID = "unbound_stats"
	UnboundForwards   ID = "unbound_forwards"
	UnboundStubs      ID = "unbound_stubs"
	UnboundLocalZones ID = "unbound_local_zones"
	UnboundAuthZones  ID = "unbound_auth_zones"
	UnboundInsecure   ID = "unbound_insecure"

	BGPSummary    ID = "bgp_summary"
	BGPNeighbors  ID = "bgp_neighbors"
	BGPNexthops   ID = "bgp_nexthops"
	BGPInterfaces ID = "bgp_interfaces"
	BGPRIBMemory  ID = "bgp_rib_memory"
)

// Spec is an immutable command invocation.
type Spec struct {
	// Path is the program that does the work (e.g. /sbin/pfctl), even when
	// it runs through doas.
	Path string
	Args []string
	// Feature gates the command; empty means always available.
	Feature Feature
	// Doas runs the command as root via "doas -n Path Args...", which needs
	// a matching exact-args rule (see DoasRules).
	Doas bool
}

// Argv returns the program to execve and its arguments.
func (s Spec) Argv() (string, []string) {
	if s.Doas {
		return DoasPath, append([]string{"-n", s.Path}, s.Args...)
	}
	return s.Path, append([]string(nil), s.Args...)
}

// String renders the command line for display.
func (s Spec) String() string {
	p, a := s.Argv()
	return strings.Join(append([]string{p}, a...), " ")
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

func pfctl(modifier string) Spec {
	return Spec{Path: "/sbin/pfctl", Args: []string{"-s", modifier}, Feature: FeaturePF, Doas: true}
}

func unboundControl(verb string) Spec {
	return Spec{Path: "/usr/sbin/unbound-control", Args: []string{verb}, Feature: FeatureUnbound, Doas: true}
}

func bgpctl(show ...string) Spec {
	args := append([]string{"-s", BGPRestrictedSocket, "show"}, show...)
	return Spec{Path: "/usr/sbin/bgpctl", Args: args, Feature: FeatureBGP}
}

var registry = map[ID]Spec{
	Uname:  {Path: "/usr/bin/uname", Args: []string{"-a"}},
	Uptime: {Path: "/usr/bin/uptime"},
	Sysctl: {Path: "/sbin/sysctl", Args: SysctlNames},
	Df:     {Path: "/bin/df", Args: []string{"-h"}},
	Vmstat: {Path: "/usr/bin/vmstat"},

	Ifconfig: {Path: "/sbin/ifconfig"},
	Routes:   {Path: "/usr/bin/netstat", Args: []string{"-rn"}},

	// pfctl -s only; never -f -F -e -d -k -K -T -x or anchors with -a.
	PfInfo:       pfctl("info"),
	PfRules:      pfctl("rules"),
	PfTables:     pfctl("Tables"),
	PfMemory:     pfctl("memory"),
	PfTimeouts:   pfctl("timeouts"),
	PfInterfaces: pfctl("Interfaces"),
	PfQueues:     pfctl("queue"),

	// Read-only verbs only. Note "stats" RESETS counters; stats_noreset does not.
	UnboundStatus:     unboundControl("status"),
	UnboundStats:      unboundControl("stats_noreset"),
	UnboundForwards:   unboundControl("list_forwards"),
	UnboundStubs:      unboundControl("list_stubs"),
	UnboundLocalZones: unboundControl("list_local_zones"),
	UnboundAuthZones:  unboundControl("list_auth_zones"),
	UnboundInsecure:   unboundControl("list_insecure"),

	// The restricted socket rejects anything but show in bgpd itself.
	BGPSummary:    bgpctl("summary"),
	BGPNeighbors:  bgpctl("neighbor"),
	BGPNexthops:   bgpctl("nexthop"),
	BGPInterfaces: bgpctl("interfaces"),
	BGPRIBMemory:  bgpctl("rib", "memory"),
}

// BaseDirs are the only directories registered binaries may live in.
var BaseDirs = []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin"}

// socketDirs are where an absolute non-program argument (a control socket)
// may point.
var socketDirs = []string{"/var/run"}

// Enabled is the set of opt-in features the operator turned on.
// The zero value enables none.
type Enabled map[Feature]bool

// ParseFeatures parses the -enable flag value, e.g. "pf,unbound,bgp".
func ParseFeatures(s string) (Enabled, error) {
	en := Enabled{}
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		known := false
		for _, k := range Features {
			known = known || Feature(f) == k
		}
		if !known {
			return nil, fmt.Errorf("unknown feature %q (valid: %s)", f, featureList())
		}
		en[Feature(f)] = true
	}
	return en, nil
}

func featureList() string {
	var s []string
	for _, f := range Features {
		s = append(s, string(f))
	}
	return strings.Join(s, ", ")
}

func (en Enabled) allows(f Feature) bool { return f == "" || en[f] }

// Lookup returns a defensive copy of the spec for id. Commands whose feature
// is not enabled are rejected.
func Lookup(id ID, en Enabled) (Spec, error) {
	s, ok := registry[id]
	if !ok {
		return Spec{}, fmt.Errorf("basecmd: command %q is not allowlisted", id)
	}
	if !en.allows(s.Feature) {
		return Spec{}, fmt.Errorf("basecmd: command %q needs feature %q, which is not enabled", id, s.Feature)
	}
	s.Args = append([]string(nil), s.Args...)
	return s, nil
}

// Describe returns the display command line for id regardless of features,
// or "" if id is unknown.
func Describe(id ID) string {
	if s, ok := registry[id]; ok {
		return s.String()
	}
	return ""
}

// Binaries returns the sorted, de-duplicated set of programs the server
// itself execs for the enabled features. Doas commands contribute
// /usr/bin/doas, not the target: the target is executed by doas, not by us.
// The sandbox unveils exactly these with "x".
func Binaries(en Enabled) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range registry {
		if !en.allows(s.Feature) {
			continue
		}
		p, _ := s.Argv()
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// validUser matches a conservative OpenBSD login name, so a generated
// doas.conf line cannot be malformed or carry extra tokens.
var validUser = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// DoasRules returns the exact doas.conf(5) lines that the enabled features
// need for user, sorted. Each rule pins the full argument list, so doas
// refuses any other arguments.
func DoasRules(user string, en Enabled) ([]string, error) {
	if !validUser.MatchString(user) {
		return nil, fmt.Errorf("invalid user name %q", user)
	}
	var out []string
	for _, s := range registry {
		if !s.Doas || !en.allows(s.Feature) {
			continue
		}
		out = append(out, fmt.Sprintf("permit nopass %s as root cmd %s args %s",
			user, s.Path, strings.Join(s.Args, " ")))
	}
	sort.Strings(out)
	return out, nil
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
	if !inDirs(s.Path, BaseDirs) {
		return fmt.Errorf("path %q is outside base system dirs %v", s.Path, BaseDirs)
	}
	if s.Path == DoasPath {
		return fmt.Errorf("use Doas: true instead of running %s directly", DoasPath)
	}
	if s.Feature != "" {
		known := false
		for _, k := range Features {
			known = known || s.Feature == k
		}
		if !known {
			return fmt.Errorf("unknown feature %q", s.Feature)
		}
	}
	for _, a := range s.Args {
		if a == "" || strings.ContainsAny(a, "\x00\n\t ") {
			return fmt.Errorf("arg %q is empty or contains whitespace/control characters", a)
		}
		// Absolute-path arguments may only name a base program or a control
		// socket under /var/run.
		if strings.HasPrefix(a, "/") &&
			(path.Clean(a) != a || !(inDirs(a, BaseDirs) || inDirs(a, socketDirs))) {
			return fmt.Errorf("arg %q is a path outside base program or socket dirs", a)
		}
	}
	return nil
}

func inDirs(p string, dirs []string) bool {
	dir := path.Dir(p)
	for _, d := range dirs {
		if dir == d {
			return true
		}
	}
	return false
}
