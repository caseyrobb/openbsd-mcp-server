package sandbox

import (
	"strings"
	"testing"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
)

func TestPolicyFromRegistry(t *testing.T) {
	p, err := NewPolicy(basecmd.Binaries(nil), []string{"/etc/rc.conf.local"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Promises != "stdio rpath proc exec" {
		t.Errorf("promises = %q", p.Promises)
	}
	for _, r := range p.Unveil {
		if strings.ContainsAny(r.Perms, "wc") {
			t.Errorf("rule %+v grants write/create", r)
		}
	}
	s := p.String()
	for _, want := range []string{
		`unveil("/sbin/sysctl", "x");`,
		`unveil("/dev/null", "r");`,
		`unveil(NULL, NULL);`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("policy missing %s\n%s", want, s)
		}
	}
}

func TestPromisesExcludeDangerousGroups(t *testing.T) {
	for _, bad := range []string{"wpath", "cpath", "dpath", "fattr", "inet", "unix", "dns", "unveil", "id", "settime"} {
		for _, p := range strings.Fields(Promises) {
			if p == bad {
				t.Errorf("promise %q must not be granted", bad)
			}
		}
	}
}

func TestNewPolicyRejectsForbiddenPaths(t *testing.T) {
	bad := []string{
		"/usr/local/bin/python3",
		"/usr/local",
		"/etc/pkg/x",
		"/var/db/pkg/foo/+CONTENTS",
		"/etc/master.passwd",
		"/etc/spwd.db",
		"/etc/doas.conf",
		"/etc/iked.conf",
		"/etc/ssl/private/server.key",
		"/etc/ssh/ssh_host_ed25519_key",
		"/root/.profile",
		"/etc/../usr/local/bin/x",
		"etc/pf.conf",
		"/",
		"/etc/",
	}
	for _, b := range bad {
		if _, err := NewPolicy(nil, []string{b}); err == nil {
			t.Errorf("NewPolicy accepted read path %q", b)
		}
		if _, err := NewPolicy([]string{b}, nil); err == nil {
			t.Errorf("NewPolicy accepted exec path %q", b)
		}
	}
}
