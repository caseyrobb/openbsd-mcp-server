package basecmd

import (
	"strings"
	"testing"
)

func TestRegistryValid(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryHasNoPortsPaths(t *testing.T) {
	for _, b := range Binaries(Enabled{PfInfo: true}) {
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
		{Path: "/usr/bin/doas", Args: []string{"-n", "/usr/local/bin/pftop"}},
		{Path: "/usr/bin/doas", Args: []string{"-n", "/sbin/../usr/local/bin/x"}},
	}
	for _, s := range bad {
		if err := validateSpec(s); err == nil {
			t.Errorf("validateSpec(%+v) = nil, want error", s)
		}
	}
}

func TestSysctlArgsAreReadOnly(t *testing.T) {
	// sysctl writes when given name=value; the fixed arg list must never do that.
	for _, n := range SysctlNames {
		if strings.ContainsAny(n, "= ") || strings.HasPrefix(n, "-") {
			t.Errorf("sysctl arg %q could mutate or alter behaviour", n)
		}
	}
}

func TestOptInRequiresEnable(t *testing.T) {
	if _, err := Lookup(PfInfo, nil); err == nil {
		t.Fatal("opt-in command ran without being enabled")
	}
	if _, err := Lookup(PfInfo, Enabled{PfInfo: true}); err != nil {
		t.Fatal(err)
	}
	for _, b := range Binaries(nil) {
		if b == "/usr/bin/doas" {
			t.Fatal("doas unveiled without opt-in")
		}
	}
	found := false
	for _, b := range Binaries(Enabled{PfInfo: true}) {
		found = found || b == "/usr/bin/doas"
	}
	if !found {
		t.Fatal("doas missing when pf_info enabled")
	}
}

func TestPfInfoArgsExact(t *testing.T) {
	// Must match the documented doas.conf rule exactly:
	//   permit nopass obsdmcp as root cmd /sbin/pfctl args -s info
	s, _ := Lookup(PfInfo, Enabled{PfInfo: true})
	got := strings.Join(append([]string{s.Path}, s.Args...), " ")
	if got != "/usr/bin/doas -n /sbin/pfctl -s info" {
		t.Fatalf("pf_info argv = %q", got)
	}
}
