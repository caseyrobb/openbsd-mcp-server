//go:build openbsd

package sandbox

// Integration tests for the real pledge(2)/unveil(2) policy. They run only on
// OpenBSD. Each scenario re-executes the test binary as a child, because
// sandboxing is irreversible and a pledge violation kills the process with
// SIGABRT. The child applies the production policy, then probes it.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/caseyrobb/openbsd-mcp-server/internal/audit"
	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
	"github.com/caseyrobb/openbsd-mcp-server/internal/collect"
	"github.com/caseyrobb/openbsd-mcp-server/internal/confread"
	"github.com/caseyrobb/openbsd-mcp-server/internal/execx"
)

const (
	childEnv = "OBSDMCP_SANDBOX_CHILD"
	// featuresEnv opts in to TestSandboxFeatures, e.g. "pf,unbound,bgp".
	// The host must be set up first: doas rules from -print-doas, unbound
	// running, bgpd running with the restricted socket.
	featuresEnv = "OBSDMCP_TEST_FEATURES"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(childEnv); mode != "" {
		os.Exit(child(mode))
	}
	os.Exit(m.Run())
}

// child applies the production policy and runs one scenario. Exit 0 = pass,
// 1 = a probe misbehaved (details on stdout), 2 = setup failed.
func child(mode string) int {
	conf, err := confread.New()
	if err != nil {
		fmt.Println("setup: confread:", err)
		return 2
	}
	en := basecmd.Enabled{}
	if mode == "features" {
		if en, err = basecmd.ParseFeatures(os.Getenv(featuresEnv)); err != nil {
			fmt.Println("setup:", err)
			return 2
		}
	}
	p, err := NewPolicy(basecmd.Binaries(en), conf.Paths())
	if err != nil {
		fmt.Println("setup: policy:", err)
		return 2
	}
	if _, err := Apply(p); err != nil {
		fmt.Println("setup: apply:", err)
		return 2
	}

	switch mode {
	case "allowed":
		return probeAllowed(conf)
	case "features":
		return probeFeatures(en)
	case "write":
		err := os.WriteFile("/tmp/obsdmcp-sandbox-probe", []byte("x"), 0o600)
		fmt.Println("write returned:", err) // reached only if not killed
		if err == nil {
			return 1
		}
	case "socket":
		c, err := net.Dial("tcp", "127.0.0.1:22")
		fmt.Println("dial returned:", err)
		if err == nil {
			c.Close()
			return 1
		}
	case "devnull-write":
		// Documents why execx must never leave Stdout/Stderr nil: Go opens
		// /dev/null with plain open(2), which gets no __pledge_open exemption.
		f, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
		fmt.Println("devnull write open returned:", err)
		if err == nil {
			f.Close()
			return 1
		}
	case "unveil":
		err := unix.Unveil("/", "r")
		fmt.Println("unveil returned:", err)
		if err == nil {
			return 1
		}
	default:
		fmt.Println("unknown mode", mode)
		return 2
	}
	return 0
}

// step announces the next probe on stdout (unbuffered), so if pledge kills
// the child, the parent's output shows exactly which probe did it.
func step(format string, a ...any) { fmt.Printf("step: "+format+"\n", a...) }

func probeAllowed(conf *confread.Reader) int {
	var fails []string
	fail := func(f string, a ...any) { fails = append(fails, fmt.Sprintf(f, a...)) }

	// Allowed: an allowlisted 0644 config through the full confread pipeline
	// (this also proves EvalSymlinks/lstat on unveiled ancestors works).
	step("confread /etc/hosts")
	if f, err := conf.Read("/etc/hosts"); err != nil {
		fail("confread /etc/hosts: %v", err)
	} else if !strings.Contains(f.Content, "localhost") {
		fail("confread /etc/hosts: unexpected content")
	}
	// Allowed: an allowlisted base binary via the real runner.
	// A file below an ancestor that is not itself unveiled (/etc/ssh).
	step("confread /etc/ssh/sshd_config")
	if _, err := conf.Read("/etc/ssh/sshd_config"); err != nil && !errors.Is(err, confread.ErrNotPresent) {
		fail("confread /etc/ssh/sshd_config: %v", err)
	}

	// Allowed: every non-opt-in production command via the real runner.
	step("execx sysctl")
	if res, err := (execx.Exec{}).Run(context.Background(), basecmd.Sysctl); err != nil {
		fail("exec sysctl: %v", err)
	} else if !strings.Contains(res.Stdout, "kern.ostype=OpenBSD") {
		fail("exec sysctl: unexpected output %q", res.Stdout)
	}
	for _, id := range []basecmd.ID{basecmd.Uname, basecmd.Uptime, basecmd.Df, basecmd.Vmstat, basecmd.Ifconfig, basecmd.Routes} {
		step("execx %s", id)
		if res, err := (execx.Exec{}).Run(context.Background(), id); err != nil {
			fail("exec %s: %v (stderr %q)", id, err, res.Stderr)
		} else if strings.TrimSpace(res.Stdout) == "" {
			fail("exec %s: empty output", id)
		}
	}
	// Every always-available *_status view. A non-zero exit still proves
	// the sandbox let the command run (e.g. swapctl with no swap, ndp with
	// IPv6 off); only exec/sandbox failures count.
	for _, sub := range collect.Subsystems {
		if sub.Feature != "" {
			continue
		}
		for _, v := range sub.Views {
			step("%s_status %s", sub.Name, v.Name)
			res, err := (execx.Exec{}).Run(context.Background(), v.ID)
			if err != nil && !errors.Is(err, execx.ErrNonZeroExit) {
				fail("%s_status %s: %v", sub.Name, v.Name, err)
			} else if err != nil {
				fmt.Printf("note: %s_status %s exited non-zero: %s\n", sub.Name, v.Name,
					strings.TrimSpace(res.Stderr))
			}
		}
	}

	// Audit: sendsyslog(2) works under the final pledge with nothing unveiled.
	step("audit sendsyslog")
	if l, err := audit.NewSyslog("obsd-mcp-test"); err != nil {
		fail("audit.NewSyslog: %v", err)
	} else if err := l.(interface {
		Send(audit.Priority, string) error
	}).Send(audit.Info, "event=sandbox_self_test"); err != nil {
		fail("audit sendsyslog under pledge: %v", err)
	}

	// Opt-in commands stay refused when their feature is not enabled.
	for _, id := range []basecmd.ID{basecmd.PfInfo, basecmd.UnboundStatus, basecmd.BGPSummary,
		basecmd.NTPStatus, basecmd.SvcEnabled, basecmd.CheckPF, basecmd.CheckSSHD} {
		step("execx %s (not enabled)", id)
		if _, err := (execx.Exec{}).Run(context.Background(), id); err == nil {
			fail("%s ran without its feature enabled", id)
		}
	}

	// Denied reads: not unveiled, so ENOENT/EACCES regardless of file mode.
	for _, path := range []string{
		"/etc/master.passwd", "/etc/spwd.db", "/etc/passwd", "/etc/doas.conf",
		"/etc/ssh/ssh_host_ed25519_key", "/usr/local", "/etc/rc", "/var/log/messages",
	} {
		step("open %s", path)
		if f, err := os.Open(path); err == nil {
			f.Close()
			fail("open %s succeeded", path)
		} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
			fail("open %s: unexpected error %v", path, err)
		}
	}
	step("readdir /etc")
	if _, err := os.ReadDir("/etc"); err == nil {
		fail("listing /etc succeeded")
	}

	// Denied exec: anything not in the registry, including doas when
	// pf_info is not opted in. Stdout/Stderr must be set, as in execx: a nil
	// writer makes os/exec open /dev/null O_WRONLY, which needs "wpath".
	for _, bin := range []string{"/bin/sh", "/bin/ksh", "/usr/bin/doas", "/sbin/pfctl", "/bin/cat",
		"/usr/sbin/unbound-control", "/usr/sbin/bgpctl", "/usr/sbin/ntpctl", "/usr/sbin/rcctl",
		"/usr/sbin/sshd", "/usr/sbin/bgpd"} {
		step("exec %s", bin)
		var out bytes.Buffer
		cmd := exec.Command(bin)
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err == nil {
			fail("exec %s succeeded", bin)
		}
	}
	step("done")

	if len(fails) > 0 {
		fmt.Println(strings.Join(fails, "\n"))
		return 1
	}
	return 0
}

// probeFeatures runs every view of every enabled subsystem through the real
// runner and collector, inside the sandbox built for those features. The
// targets (pfctl, unbound-control) must NOT be directly executable: only
// doas is unveiled for them.
func probeFeatures(en basecmd.Enabled) int {
	var fails []string
	r := execx.Exec{Enabled: en}
	for _, sub := range collect.Subsystems {
		if sub.Feature == "" || !en[sub.Feature] {
			continue // always-available views run in the "allowed" scenario
		}
		for _, v := range sub.Views {
			step("%s_status %s", sub.Name, v.Name)
			// Empty output is valid (no queues, no tables, no forwards);
			// only a failed command counts.
			if _, err := collect.Status(context.Background(), r, sub, v.Name); err != nil {
				fails = append(fails, fmt.Sprintf("%s/%s: %v", sub.Name, v.Name, err))
			}
		}
	}
	// Config checks: an invalid or absent config is a normal result; only
	// a check that could not run (doas refused, exec failed) counts.
	if en[basecmd.FeatureConfCheck] {
		for _, v := range collect.ConfigChecks.Views {
			step("config_check %s", v.Name)
			res, err := collect.ConfigCheck(context.Background(), r, v.Name)
			if err != nil {
				fails = append(fails, fmt.Sprintf("config_check/%s: %v", v.Name, err))
			} else {
				fmt.Printf("note: config_check %s valid=%t\n", v.Name, res.Valid)
			}
		}
	}
	// Logs: a log that was never written (no ftpd, no httpd) is absent;
	// any other failure, including a doas refusal, counts.
	if en[basecmd.FeatureLogs] {
		for _, l := range collect.Logs {
			step("log_tail %s", l.Name)
			res, err := collect.LogTail(context.Background(), r, l.Name, collect.MaxLogLines, "")
			switch {
			case err != nil && strings.Contains(err.Error(), "No such file or directory"):
				fmt.Printf("note: log_tail %s: absent\n", l.Name)
			case err != nil:
				fails = append(fails, fmt.Sprintf("log_tail/%s: %v", l.Name, err))
			default:
				fmt.Printf("note: log_tail %s: scanned=%d redactions=%d\n", l.Name, res.Scanned, res.Redactions)
			}
		}
	}
	// The doas targets are never directly executable: only doas is unveiled.
	for _, bin := range []string{"/sbin/pfctl", "/usr/sbin/unbound-control", "/usr/sbin/ntpctl",
		"/usr/sbin/rcctl", "/bin/ksh", "/usr/sbin/sshd", "/usr/sbin/bgpd", "/usr/bin/tail",
		"/usr/sbin/ospfctl", "/usr/sbin/ospf6ctl", "/usr/sbin/relayctl", "/usr/sbin/smtpctl",
		"/usr/sbin/vmctl", "/usr/sbin/unwindctl", "/sbin/ipsecctl", "/usr/sbin/ikectl",
		"/bin/ls", "/usr/bin/last"} {
		step("direct exec %s", bin)
		var out bytes.Buffer
		cmd := exec.Command(bin)
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err == nil {
			fails = append(fails, "direct exec of "+bin+" succeeded")
		}
	}
	step("done")
	if len(fails) > 0 {
		fmt.Println(strings.Join(fails, "\n"))
		return 1
	}
	return 0
}

func runChild(t *testing.T, mode string) (out string, ws syscall.WaitStatus) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), childEnv+"="+mode)
	b, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Fatalf("starting child: %v", err)
	}
	return string(b), cmd.ProcessState.Sys().(syscall.WaitStatus)
}

// TestSandboxFeatures runs only when OBSDMCP_TEST_FEATURES is set, because it
// needs host setup (doas rules, running daemons).
func TestSandboxFeatures(t *testing.T) {
	if os.Getenv(featuresEnv) == "" {
		t.Skip("set " + featuresEnv + "=pf,unbound,bgp (after host setup) to run")
	}
	out, ws := runChild(t, "features")
	if ws.Signaled() {
		t.Fatalf("child killed by %v\n%s", ws.Signal(), out)
	}
	if ws.ExitStatus() != 0 {
		t.Fatalf("exit %d:\n%s", ws.ExitStatus(), out)
	}
	t.Logf("\n%s", out)
}

func TestSandboxAllowsOnlyPolicy(t *testing.T) {
	out, ws := runChild(t, "allowed")
	if ws.Signaled() {
		t.Fatalf("child killed by %v (pledge too narrow?)\n%s", ws.Signal(), out)
	}
	if ws.ExitStatus() != 0 {
		t.Fatalf("exit %d:\n%s", ws.ExitStatus(), out)
	}
}

// Each of these is outside the promises; OpenBSD should kill the child with
// SIGABRT. A clean error return is also acceptable (still no effect), but a
// success is a failure.
func TestSandboxForbiddenOperations(t *testing.T) {
	for _, mode := range []string{"write", "devnull-write", "socket", "unveil"} {
		t.Run(mode, func(t *testing.T) {
			out, ws := runChild(t, mode)
			switch {
			case ws.Signaled() && ws.Signal() == syscall.SIGABRT:
				// pledge violation: expected
			case ws.Signaled():
				t.Fatalf("killed by unexpected signal %v\n%s", ws.Signal(), out)
			case ws.ExitStatus() == 0:
				t.Logf("not killed, but operation failed cleanly:\n%s", out)
			default:
				t.Fatalf("exit %d:\n%s", ws.ExitStatus(), out)
			}
			if _, err := os.Stat("/tmp/obsdmcp-sandbox-probe"); err == nil {
				os.Remove("/tmp/obsdmcp-sandbox-probe")
				t.Fatal("sandboxed child created a file")
			}
		})
	}
}
