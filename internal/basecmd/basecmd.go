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
	"time"
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
	FeatureNTP     Feature = "ntp"     // ntpctl via doas (ntpd's socket is 0660 root)
	// FeatureServices runs rcctl(8) via doas. rcctl is a ksh script, so
	// running it directly would need /bin/ksh unveiled "x"; through doas,
	// doas execs it after our unveil is gone. "ls started|failed" also
	// need root.
	FeatureServices Feature = "services"
	// FeatureConfCheck runs each daemon's configtest mode (-n, sshd -t)
	// via doas, because the configs are mostly 0600 root.
	FeatureConfCheck Feature = "confcheck"
)

// Features lists every opt-in feature in display order.
var Features = []Feature{FeaturePF, FeatureUnbound, FeatureBGP, FeatureNTP, FeatureServices, FeatureConfCheck}

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

	Sensors   ID = "sensors"
	Mounts    ID = "mounts"
	Swap      ID = "swap"
	ProcsCPU  ID = "procs_cpu"
	ProcsMem  ID = "procs_mem"
	NetProto  ID = "net_protocols"
	NetIfaces ID = "net_interfaces"
	NetMbufs  ID = "net_mbufs"
	NetSock4  ID = "net_sockets_inet"
	NetSock6  ID = "net_sockets_inet6"
	NetARP    ID = "net_arp"
	NetNDP    ID = "net_ndp"

	NTPStatus  ID = "ntp_status"
	NTPPeers   ID = "ntp_peers"
	NTPSensors ID = "ntp_sensors"
	NTPAll     ID = "ntp_all"

	SvcEnabled ID = "svc_enabled"
	SvcStarted ID = "svc_started"
	SvcFailed  ID = "svc_failed"

	CheckPF      ID = "check_pf"
	CheckBGPD    ID = "check_bgpd"
	CheckHTTPD   ID = "check_httpd"
	CheckRelayd  ID = "check_relayd"
	CheckSMTPD   ID = "check_smtpd"
	CheckIKED    ID = "check_iked"
	CheckNTPD    ID = "check_ntpd"
	CheckOSPFD   ID = "check_ospfd"
	CheckOSPF6D  ID = "check_ospf6d"
	CheckDHCPD   ID = "check_dhcpd"
	CheckUnwind  ID = "check_unwind"
	CheckVMD     ID = "check_vmd"
	CheckSNMPD   ID = "check_snmpd"
	CheckSSHD    ID = "check_sshd"
	CheckUnbound ID = "check_unbound"
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
	// Timeout, when longer than the runner's default, is this command's
	// limit. rcctl runs a shell per service and needs it on slow hosts.
	Timeout time.Duration
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

// PsFields is the ps(1) -o column list. It uses "comm" (the program name)
// and never "args"/"command": other users' full command lines can carry
// passwords or tokens.
const PsFields = "pid,ppid,user,stat,pcpu,pmem,rss,start,time,comm"

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

func ntpctl(modifier string) Spec {
	return Spec{Path: "/usr/sbin/ntpctl", Args: []string{"-s", modifier}, Feature: FeatureNTP, Doas: true}
}

// RcctlTimeout bounds rcctl ls, which runs an rc.d script check per service.
// 5s was too short on an emulated arm64 VM even for "ls on".
const RcctlTimeout = 30 * time.Second

func rcctlLs(what string) Spec {
	return Spec{Path: "/usr/sbin/rcctl", Args: []string{"ls", what}, Feature: FeatureServices, Doas: true,
		Timeout: RcctlTimeout}
}

// configtest runs a daemon's check-only mode as root. Every argument list
// here must be a documented "only check the configuration" mode; the
// registry tests pin the allowed shapes.
func configtest(path string, args ...string) Spec {
	return Spec{Path: path, Args: args, Feature: FeatureConfCheck, Doas: true}
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

	// Always available and unprivileged. These must be ELF binaries, not
	// scripts: exec'ing a script needs its interpreter unveiled "x" too.
	Sensors:   {Path: "/sbin/sysctl", Args: []string{"hw.sensors"}},
	Mounts:    {Path: "/sbin/mount"},
	Swap:      {Path: "/sbin/swapctl", Args: []string{"-l"}},
	ProcsCPU:  {Path: "/bin/ps", Args: []string{"-axr", "-o", PsFields}},
	ProcsMem:  {Path: "/bin/ps", Args: []string{"-axm", "-o", PsFields}},
	NetProto:  {Path: "/usr/bin/netstat", Args: []string{"-s"}},
	NetIfaces: {Path: "/usr/bin/netstat", Args: []string{"-in"}},
	NetMbufs:  {Path: "/usr/bin/netstat", Args: []string{"-m"}},
	NetSock4:  {Path: "/usr/bin/netstat", Args: []string{"-an", "-f", "inet"}},
	NetSock6:  {Path: "/usr/bin/netstat", Args: []string{"-an", "-f", "inet6"}},
	NetARP:    {Path: "/usr/sbin/arp", Args: []string{"-an"}},
	NetNDP:    {Path: "/usr/sbin/ndp", Args: []string{"-an"}},

	// ntpd's control socket only implements show requests.
	NTPStatus:  ntpctl("status"),
	NTPPeers:   ntpctl("peers"),
	NTPSensors: ntpctl("Sensors"),
	NTPAll:     ntpctl("all"),

	// rcctl ls only; never enable/disable/start/stop/set/order.
	SvcEnabled: rcctlLs("on"),
	SvcStarted: rcctlLs("started"),
	SvcFailed:  rcctlLs("failed"),

	// "Configtest mode. Only check the configuration file for validity."
	CheckPF:      configtest("/sbin/pfctl", "-n", "-f", "/etc/pf.conf"),
	CheckBGPD:    configtest("/usr/sbin/bgpd", "-n"),
	CheckHTTPD:   configtest("/usr/sbin/httpd", "-n"),
	CheckRelayd:  configtest("/usr/sbin/relayd", "-n"),
	CheckSMTPD:   configtest("/usr/sbin/smtpd", "-n"),
	CheckIKED:    configtest("/sbin/iked", "-n"),
	CheckNTPD:    configtest("/usr/sbin/ntpd", "-n"),
	CheckOSPFD:   configtest("/usr/sbin/ospfd", "-n"),
	CheckOSPF6D:  configtest("/usr/sbin/ospf6d", "-n"),
	CheckDHCPD:   configtest("/usr/sbin/dhcpd", "-n"),
	CheckUnwind:  configtest("/sbin/unwind", "-n"),
	CheckVMD:     configtest("/usr/sbin/vmd", "-n"),
	CheckSNMPD:   configtest("/usr/sbin/snmpd", "-n"),
	CheckSSHD:    configtest("/usr/sbin/sshd", "-t"),
	CheckUnbound: configtest("/usr/sbin/unbound-checkconf"),
}

// BaseDirs are the only directories registered binaries may live in.
var BaseDirs = []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin"}

// socketDirs are where an absolute non-program argument (a control socket)
// may point.
var socketDirs = []string{"/var/run"}

// configArgs are the only config files that may be named as an argument.
var configArgs = map[string]bool{"/etc/pf.conf": true}

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

// List returns the enabled features in canonical (Features) order.
func (en Enabled) List() []string {
	var out []string
	for _, f := range Features {
		if en[f] {
			out = append(out, string(f))
		}
	}
	return out
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

// FeatureOf returns the feature that gates id ("" for always available).
func FeatureOf(id ID) Feature { return registry[id].Feature }

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

// ValidUser reports whether name is a conservative OpenBSD login name, safe
// to place in generated doas.conf and sshd_config lines.
func ValidUser(name string) bool { return validUser.MatchString(name) }

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
		// A bare "args" permits no arguments at all.
		out = append(out, strings.TrimSpace(fmt.Sprintf("permit nopass %s as root cmd %s args %s",
			user, s.Path, strings.Join(s.Args, " "))))
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
		// Absolute-path arguments may only name a base program, a control
		// socket under /var/run or an allowlisted config file.
		if strings.HasPrefix(a, "/") &&
			(path.Clean(a) != a || !(inDirs(a, BaseDirs) || inDirs(a, socketDirs) || configArgs[a])) {
			return fmt.Errorf("arg %q is a path outside base program, socket or config allowlists", a)
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
