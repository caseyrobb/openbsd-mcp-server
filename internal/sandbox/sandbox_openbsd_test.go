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

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
	"github.com/caseyrobb/openbsd-mcp-server/internal/confread"
	"github.com/caseyrobb/openbsd-mcp-server/internal/execx"
)

const childEnv = "OBSDMCP_SANDBOX_CHILD"

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
	p, err := NewPolicy(basecmd.Binaries(nil), conf.Paths())
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
	step("execx sysctl")
	if res, err := (execx.Exec{}).Run(context.Background(), basecmd.Sysctl); err != nil {
		fail("exec sysctl: %v", err)
	} else if !strings.Contains(res.Stdout, "kern.ostype=OpenBSD") {
		fail("exec sysctl: unexpected output %q", res.Stdout)
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
	for _, bin := range []string{"/bin/sh", "/bin/ksh", "/usr/bin/doas", "/sbin/pfctl", "/bin/cat"} {
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
