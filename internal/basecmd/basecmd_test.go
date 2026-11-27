package basecmd

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRegistryValid(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
}

var all = func() Enabled {
	en := Enabled{}
	for _, f := range Features {
		en[f] = true
	}
	return en
}()

func TestRegistryHasNoPortsPaths(t *testing.T) {
	for _, b := range Binaries(all) {
		if strings.HasPrefix(b, "/usr/local") || strings.HasPrefix(b, "/usr/X11R6") {
			t.Errorf("binary %q is outside base system", b)
		}
	}
}

func TestLookupUnknownRejected(t *testing.T) {
	for _, id := range []ID{"", "sh", "/bin/sh", "pfctl -F all", "../sysctl"} {
		if _, err := Lookup(id, nil); err == nil {
			t.Errorf("Lookup(%q) succeeded, want error", id)
		}
	}
}

func TestLookupReturnsCopy(t *testing.T) {
	s, err := Lookup(Sysctl, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Args[0] = "kern.securelevel=-1"
	s2, _ := Lookup(Sysctl, nil)
	if s2.Args[0] == "kern.securelevel=-1" {
		t.Fatal("Lookup leaked mutable registry slice")
	}
}

func TestValidateSpecRejects(t *testing.T) {
	bad := []Spec{
		{Path: "sysctl"},
		{Path: "/usr/local/bin/foo"},
		{Path: "/sbin/../usr/local/bin/foo"},
		{Path: "/etc/rc"},
		{Path: "/bin/sh/"},
		{Path: "/sbin/sysctl", Args: []string{"a\x00b"}},
		{Path: "/sbin/pfctl", Args: []string{"/usr/local/bin/pftop"}},
		{Path: "/sbin/pfctl", Args: []string{"/sbin/../usr/local/bin/x"}},
		{Path: "/usr/sbin/bgpctl", Args: []string{"-s", "/tmp/bgpd.sock"}},
		{Path: "/usr/sbin/bgpctl", Args: []string{"-s", "/var/run/../tmp/x"}},
		{Path: "/sbin/pfctl", Args: []string{"-s rules"}}, // would split in doas.conf
		{Path: "/sbin/pfctl", Args: []string{""}},
		{Path: "/usr/bin/doas", Args: []string{"-n", "/sbin/pfctl"}},
		{Path: "/sbin/pfctl", Feature: "carp"},
	}
	for _, s := range bad {
		if err := validateSpec(s); err == nil {
			t.Errorf("validateSpec(%+v) = nil, want error", s)
		}
	}
}

func TestSysctlArgsAreReadOnly(t *testing.T) {
	// sysctl writes when given name=value; the fixed arg list must never do that.
	for _, n := range append(append([]string(nil), SysctlNames...), SecuritySysctlNames...) {
		if strings.ContainsAny(n, "= ") || strings.HasPrefix(n, "-") {
			t.Errorf("sysctl arg %q could mutate or alter behaviour", n)
		}
	}
}

func TestFeatureGating(t *testing.T) {
	for id, s := range registry {
		if s.Feature == "" {
			continue
		}
		if _, err := Lookup(id, nil); err == nil {
			t.Errorf("%s ran without feature %s enabled", id, s.Feature)
		}
		if _, err := Lookup(id, Enabled{s.Feature: true}); err != nil {
			t.Errorf("%s: %v", id, err)
		}
		// Enabling a different feature must not unlock it.
		for _, f := range Features {
			if f != s.Feature {
				if _, err := Lookup(id, Enabled{f: true}); err == nil {
					t.Errorf("%s unlocked by unrelated feature %s", id, f)
				}
			}
		}
	}
}

func TestBinariesPerFeature(t *testing.T) {
	cases := []struct {
		en         Enabled
		want, deny []string
	}{
		{nil, nil, []string{DoasPath, "/sbin/pfctl", "/usr/sbin/unbound-control", "/usr/sbin/bgpctl",
			"/usr/sbin/ntpctl", "/usr/sbin/rcctl", "/bin/ksh", "/bin/sh"}},
		{all, []string{DoasPath, "/usr/sbin/bgpctl", "/bin/ps", "/usr/bin/netstat"},
			append([]string{"/usr/sbin/ntpctl", "/usr/sbin/rcctl", "/usr/sbin/bgpd", "/usr/sbin/sshd", "/bin/ksh", "/bin/sh",
				"/usr/bin/tail", "/bin/ls", "/usr/bin/last"}, ctlPrograms...)},
		{Enabled{FeaturePF: true}, []string{DoasPath}, []string{"/sbin/pfctl", "/usr/sbin/bgpctl"}},
		{Enabled{FeatureUnbound: true}, []string{DoasPath}, []string{"/usr/sbin/unbound-control", "/usr/sbin/bgpctl"}},
		{Enabled{FeatureBGP: true}, []string{"/usr/sbin/bgpctl"}, []string{DoasPath}},
	}
	for _, c := range cases {
		got := Binaries(c.en)
		for _, w := range c.want {
			if !slices.Contains(got, w) {
				t.Errorf("Binaries(%v) missing %s: %v", c.en, w, got)
			}
		}
		for _, d := range c.deny {
			if slices.Contains(got, d) {
				t.Errorf("Binaries(%v) must not contain %s: %v", c.en, d, got)
			}
		}
	}
}

func TestPfctlOnlyShows(t *testing.T) {
	safe := map[string]bool{"info": true, "rules": true, "Tables": true, "memory": true,
		"timeouts": true, "Interfaces": true, "queue": true}
	for id, s := range registry {
		if s.Path != "/sbin/pfctl" {
			continue
		}
		if id == CheckPF {
			continue // TestConfigtestShapes
		}
		if !s.Doas || s.Feature != FeaturePF {
			t.Errorf("%s: pfctl must be doas + feature pf", id)
		}
		if len(s.Args) != 2 || s.Args[0] != "-s" || !safe[s.Args[1]] {
			t.Errorf("%s: pfctl args %v are not a single safe -s modifier", id, s.Args)
		}
	}
}

func TestUnboundControlOnlyReadOnlyVerbs(t *testing.T) {
	for id, s := range registry {
		if s.Path != "/usr/sbin/unbound-control" {
			continue
		}
		if !s.Doas || s.Feature != FeatureUnbound {
			t.Errorf("%s: unbound-control must be doas + feature unbound", id)
		}
		if len(s.Args) != 1 {
			t.Errorf("%s: want exactly one verb, got %v", id, s.Args)
			continue
		}
		v := s.Args[0]
		// "stats" resets counters; only stats_noreset is read-only.
		if !(v == "status" || v == "stats_noreset" || strings.HasPrefix(v, "list_")) {
			t.Errorf("%s: verb %q is not on the read-only allowlist", id, v)
		}
	}
}

func TestBgpctlOnlyShowOnRestrictedSocket(t *testing.T) {
	for id, s := range registry {
		if s.Path != "/usr/sbin/bgpctl" {
			continue
		}
		if s.Doas || s.Feature != FeatureBGP {
			t.Errorf("%s: bgpctl must run unprivileged under feature bgp", id)
		}
		if len(s.Args) < 4 || s.Args[0] != "-s" || s.Args[1] != BGPRestrictedSocket || s.Args[2] != "show" {
			t.Errorf("%s: args %v must be -s %s show ...", id, s.Args, BGPRestrictedSocket)
		}
	}
}

func TestNtpctlOnlyShows(t *testing.T) {
	safe := map[string]bool{"status": true, "peers": true, "Sensors": true, "all": true}
	for id, s := range registry {
		if s.Path != "/usr/sbin/ntpctl" {
			continue
		}
		if !s.Doas || s.Feature != FeatureNTP || len(s.Args) != 2 || s.Args[0] != "-s" || !safe[s.Args[1]] {
			t.Errorf("%s: ntpctl spec %+v is not doas + ntp + one -s modifier", id, s)
		}
	}
}

func TestRcctlOnlyLists(t *testing.T) {
	safe := map[string]bool{"on": true, "started": true, "failed": true}
	for id, s := range registry {
		if s.Path != "/usr/sbin/rcctl" {
			continue
		}
		// Through doas: rcctl is a ksh script and must never be exec'd by us.
		if !s.Doas || s.Feature != FeatureServices || len(s.Args) != 2 || s.Args[0] != "ls" || !safe[s.Args[1]] {
			t.Errorf("%s: rcctl spec %+v is not doas + services + ls <on|started|failed>", id, s)
		}
	}
}

// TestConfigtestShapes pins every confcheck command to a documented
// check-only mode, so no entry can drift into loading a config.
func TestConfigtestShapes(t *testing.T) {
	n := 0
	for id, s := range registry {
		if s.Feature != FeatureConfCheck {
			continue
		}
		n++
		if !s.Doas {
			t.Errorf("%s: configtest must run via doas", id)
		}
		args := strings.Join(s.Args, " ")
		ok := false
		switch s.Path {
		case "/sbin/pfctl":
			ok = args == "-n -f /etc/pf.conf"
		case "/usr/sbin/sshd":
			ok = args == "-t"
		case "/usr/sbin/unbound-checkconf":
			ok = args == ""
		default:
			ok = args == "-n"
		}
		if !ok {
			t.Errorf("%s: %s %q is not a check-only invocation", id, s.Path, args)
		}
	}
	if n == 0 {
		t.Fatal("no confcheck commands")
	}
}

func TestAlwaysOnCommandsAreUnprivileged(t *testing.T) {
	for id, s := range registry {
		if s.Feature == "" && s.Doas {
			t.Errorf("%s: always-available commands must not use doas", id)
		}
	}
}

func TestPsNeverShowsArguments(t *testing.T) {
	for _, f := range strings.Split(PsFields, ",") {
		if f == "args" || f == "command" {
			t.Errorf("ps field %q exposes full command lines", f)
		}
	}
	for id, s := range registry {
		if s.Path == "/bin/ps" && (len(s.Args) != 3 || s.Args[1] != "-o" || s.Args[2] != PsFields ||
			strings.ContainsAny(s.Args[0], "ewE")) {
			t.Errorf("%s: ps args %v", id, s.Args)
		}
	}
}

func TestArgvAddsDoasWrapper(t *testing.T) {
	s, _ := Lookup(PfInfo, Enabled{FeaturePF: true})
	p, a := s.Argv()
	if got := strings.Join(append([]string{p}, a...), " "); got != "/usr/bin/doas -n /sbin/pfctl -s info" {
		t.Fatalf("argv = %q", got)
	}
	s, _ = Lookup(BGPSummary, Enabled{FeatureBGP: true})
	if got := s.String(); got != "/usr/sbin/bgpctl -s /var/run/bgpd.rsock show summary" {
		t.Fatalf("argv = %q", got)
	}
}

func rules(t *testing.T, user string, en Enabled) []string {
	t.Helper()
	r, err := DoasRules(user, en)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDoasRules(t *testing.T) {
	pf := rules(t, "obsdmcp", Enabled{FeaturePF: true})
	if !slices.Contains(pf, "permit nopass obsdmcp as root cmd /sbin/pfctl args -s info") {
		t.Errorf("missing pf info rule: %v", pf)
	}
	for _, r := range pf {
		if strings.Contains(r, "unbound") || strings.Contains(r, "bgpctl") {
			t.Errorf("rule for a disabled feature: %s", r)
		}
	}
	// Every doas command in the registry yields exactly one rule, and the
	// rule's args equal the command's args (what doas will match).
	everything := rules(t, "u", all)
	n := 0
	for _, s := range registry {
		if s.Doas {
			n++
			want := strings.TrimSpace("permit nopass u as root cmd " + s.Path + " args " + strings.Join(s.Args, " "))
			if !slices.Contains(everything, want) {
				t.Errorf("no rule %q", want)
			}
		}
	}
	if len(everything) != n {
		t.Errorf("%d rules for %d doas commands", len(everything), n)
	}
	if len(rules(t, "u", Enabled{FeatureBGP: true})) != 0 {
		t.Error("bgp must not need doas")
	}
	// A command without arguments gets a bare "args": doas then permits
	// no arguments at all.
	if !slices.Contains(everything, "permit nopass u as root cmd /usr/sbin/unbound-checkconf args") {
		t.Error("missing bare-args unbound-checkconf rule")
	}
}

func TestDoasRulesRejectsBadUser(t *testing.T) {
	for _, u := range []string{"", "root keepenv", "a\npermit nopass x", ":wheel", "Obsd", "-x", strings.Repeat("a", 40)} {
		if _, err := DoasRules(u, all); err == nil {
			t.Errorf("DoasRules(%q) accepted", u)
		}
	}
}

func TestParseFeatures(t *testing.T) {
	en, err := ParseFeatures("pf, bgp,,")
	if err != nil || !en[FeaturePF] || !en[FeatureBGP] || en[FeatureUnbound] {
		t.Fatalf("got %v, %v", en, err)
	}
	if en, err := ParseFeatures(""); err != nil || len(en) != 0 {
		t.Fatalf("empty: %v, %v", en, err)
	}
	for _, bad := range []string{"pf,isakmpd", "PF", "all", "pf;unbound"} {
		if _, err := ParseFeatures(bad); err == nil {
			t.Errorf("ParseFeatures(%q) accepted", bad)
		}
	}
}

// Only commands known to be slow get a longer limit, and it stays bounded.
func TestSpecTimeouts(t *testing.T) {
	for _, id := range []ID{SvcEnabled, SvcStarted, SvcFailed} {
		if registry[id].Timeout != RcctlTimeout {
			t.Errorf("%s: timeout %s, want %s", id, registry[id].Timeout, RcctlTimeout)
		}
	}
	for id, s := range registry {
		if s.Timeout < 0 || s.Timeout > time.Minute {
			t.Errorf("%s: timeout %s out of range", id, s.Timeout)
		}
		if s.Timeout != 0 && s.Path != "/usr/sbin/rcctl" {
			t.Errorf("%s: unexpected custom timeout %s", id, s.Timeout)
		}
	}
}

// ctlPrograms are daemon control programs that also accept reload, stop or
// flush commands. They only ever run through doas with pinned arguments.
var ctlPrograms = []string{
	"/usr/sbin/ospfctl", "/usr/sbin/ospf6ctl", "/usr/sbin/relayctl", "/usr/sbin/smtpctl",
	"/usr/sbin/vmctl", "/usr/sbin/unwindctl", "/sbin/ipsecctl", "/usr/sbin/ikectl",
}

// TestDaemonCtlOnlyShows pins every daemon control command to a documented
// read-only verb, through doas, under its own feature.
func TestDaemonCtlOnlyShows(t *testing.T) {
	allowed := map[string]struct {
		f    Feature
		args map[string]bool
	}{
		"/usr/sbin/ospfctl": {FeatureOSPF, map[string]bool{"show summary": true, "show neighbor": true,
			"show interfaces": true, "show rib": true, "show fib": true}},
		"/usr/sbin/ospf6ctl": {FeatureOSPF6, map[string]bool{"show summary": true, "show neighbor": true,
			"show interfaces": true, "show rib": true, "show fib": true}},
		"/usr/sbin/relayctl": {FeatureRelayd, map[string]bool{"show summary": true, "show hosts": true,
			"show redirects": true, "show relays": true, "show routers": true}},
		"/usr/sbin/smtpctl":   {FeatureSMTPD, map[string]bool{"show status": true, "show stats": true}},
		"/usr/sbin/vmctl":     {FeatureVMD, map[string]bool{"status": true}},
		"/usr/sbin/unwindctl": {FeatureUnwind, map[string]bool{"status": true, "status autoconf": true}},
		"/sbin/ipsecctl":      {FeatureIPsec, map[string]bool{"-s flow": true, "-s sa": true}},
		"/usr/sbin/ikectl":    {FeatureIPsec, map[string]bool{"show sa": true}},
	}
	seen := map[string]int{}
	for id, s := range registry {
		a, ok := allowed[s.Path]
		if !ok {
			continue
		}
		seen[s.Path]++
		args := strings.Join(s.Args, " ")
		if !s.Doas || s.Feature != a.f || !a.args[args] {
			t.Errorf("%s: %s %q (doas=%v feature=%s) is not an allowed read-only invocation", id, s.Path, args, s.Doas, s.Feature)
		}
		for _, x := range s.Args {
			if x == "-k" || strings.HasPrefix(x, "-") && strings.Contains(x, "k") {
				t.Errorf("%s: %s must never get -k (prints keys)", id, s.Path)
			}
		}
	}
	for _, p := range ctlPrograms {
		if seen[p] == 0 {
			t.Errorf("no registered commands for %s", p)
		}
	}
}

// TestLogTailShapes pins log reads to tail -n LogTailLines <allowlisted file>.
func TestLogTailShapes(t *testing.T) {
	files := map[string]bool{}
	for id, s := range registry {
		if s.Path != "/usr/bin/tail" && s.Feature != FeatureLogs {
			continue
		}
		if s.Path != "/usr/bin/tail" || s.Feature != FeatureLogs || !s.Doas || len(s.Args) != 3 ||
			s.Args[0] != "-n" || s.Args[1] != LogTailLines || !logArgs[s.Args[2]] {
			t.Errorf("%s: %+v is not doas tail -n %s <log file>", id, s, LogTailLines)
			continue
		}
		if files[s.Args[2]] {
			t.Errorf("%s: %s registered twice", id, s.Args[2])
		}
		files[s.Args[2]] = true
	}
	if len(files) != len(logArgs) {
		t.Errorf("log files registered %d, allowlisted %d", len(files), len(logArgs))
	}
	for f := range logArgs {
		for _, bad := range []string{"master.passwd", "spwd", ".ssh", "ssl/private", ".key"} {
			if strings.Contains(f, bad) {
				t.Errorf("log allowlist contains %s", f)
			}
		}
	}
}

func TestValidateRejectsOtherLogPaths(t *testing.T) {
	for _, f := range []string{"/var/log/../../etc/master.passwd", "/etc/master.passwd", "/var/log/pflog",
		"/var/log/wtmp", "/var/www/logs/../../etc/spwd.db"} {
		if err := validateSpec(Spec{Path: "/usr/bin/tail", Args: []string{"-n", "10", f}}); err == nil {
			t.Errorf("tail %s accepted", f)
		}
	}
}

func TestMaxOutputOnlyForLogs(t *testing.T) {
	for id, s := range registry {
		if s.MaxOutput != 0 && s.Feature != FeatureLogs {
			t.Errorf("%s: unexpected MaxOutput %d", id, s.MaxOutput)
		}
	}
	if validateSpec(Spec{Path: "/bin/df", MaxOutput: 64 << 20}) == nil {
		t.Error("huge MaxOutput accepted")
	}
}

// TestSecurityShapes pins the security posture commands.
func TestSecurityShapes(t *testing.T) {
	want := map[ID]string{
		SecPatches: "doas /bin/ls -1 /var/syspatch",
		SecSSHD:    "doas /usr/sbin/sshd -T",
		SecSysctl:  "/sbin/sysctl " + strings.Join(SecuritySysctlNames, " "),
		SecLogins:  "doas /usr/bin/last -n 50",
	}
	n := 0
	for id, s := range registry {
		if s.Feature != FeatureSecurity {
			continue
		}
		n++
		got := s.Path + " " + strings.Join(s.Args, " ")
		if s.Doas {
			got = "doas " + got
		}
		if want[id] != got {
			t.Errorf("%s: %q, want %q", id, got, want[id])
		}
	}
	if n != len(want) {
		t.Errorf("%d security commands, want %d", n, len(want))
	}
	// syspatch is never run: even -l creates a directory under /tmp.
	for id, s := range registry {
		if strings.HasSuffix(s.Path, "/syspatch") {
			t.Errorf("%s runs syspatch", id)
		}
	}
}
