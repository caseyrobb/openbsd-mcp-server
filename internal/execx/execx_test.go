package execx

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
)

func TestBoundedBuffer(t *testing.T) {
	cases := []struct {
		max    int
		writes []string
		want   string
		trunc  bool
	}{
		{max: 5, writes: []string{"abc"}, want: "abc"},
		{max: 5, writes: []string{"abcde"}, want: "abcde"},
		{max: 5, writes: []string{"abcdef"}, want: "abcde", trunc: true},
		{max: 5, writes: []string{"abc", "def", "ghi"}, want: "abcde", trunc: true},
		{max: 0, writes: []string{"x"}, want: "", trunc: true},
		{max: 3, writes: []string{"abc", ""}, want: "abc"},
	}
	for _, c := range cases {
		b := &BoundedBuffer{Max: c.max}
		for _, w := range c.writes {
			n, err := b.Write([]byte(w))
			if err != nil || n != len(w) {
				t.Fatalf("Write(%q) = %d, %v; want %d, nil", w, n, err, len(w))
			}
		}
		if b.String() != c.want || b.Truncated() != c.trunc {
			t.Errorf("max=%d writes=%q: got %q trunc=%v, want %q trunc=%v",
				c.max, c.writes, b.String(), b.Truncated(), c.want, c.trunc)
		}
	}
}

func TestRunRejectsUnregistered(t *testing.T) {
	_, err := Exec{}.Run(context.Background(), basecmd.ID("/bin/sh"))
	if err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("got %v, want allowlist rejection", err)
	}
}

func TestNewCmdWrapsDoas(t *testing.T) {
	spec, err := basecmd.Lookup(basecmd.PfRules, basecmd.Enabled{basecmd.FeaturePF: true})
	if err != nil {
		t.Fatal(err)
	}
	cmd, _, _ := newCmd(context.Background(), spec, 16)
	if got := strings.Join(cmd.Args, " "); cmd.Path != "/usr/bin/doas" || got != "/usr/bin/doas -n /sbin/pfctl -s rules" {
		t.Fatalf("path=%q args=%q", cmd.Path, got)
	}
}

func TestRunRejectsOptInNotEnabled(t *testing.T) {
	_, err := Exec{}.Run(context.Background(), basecmd.PfInfo)
	if err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("got %v, want opt-in rejection", err)
	}
}

// Regression: a nil Stdout/Stderr makes os/exec open /dev/null for writing,
// which needs pledge "wpath" and aborts the sandboxed server on OpenBSD.
func TestNewCmdNeverWritesDevNull(t *testing.T) {
	spec, err := basecmd.Lookup(basecmd.Uname, nil)
	if err != nil {
		t.Fatal(err)
	}
	cmd, _, _ := newCmd(context.Background(), spec, 16)
	if cmd.Stdout == nil || cmd.Stderr == nil {
		t.Fatal("Stdout/Stderr must be set; nil means O_WRONLY open of /dev/null")
	}
	if _, ok := cmd.Stdout.(*os.File); ok {
		t.Fatal("Stdout must not be an *os.File")
	}
	if _, ok := cmd.Stderr.(*os.File); ok {
		t.Fatal("Stderr must not be an *os.File")
	}
	if cmd.Stdin != nil {
		t.Fatal("Stdin should be nil (read-only /dev/null, covered by unveil r)")
	}
	if len(cmd.Env) != len(fixedEnv) {
		t.Errorf("env=%v", cmd.Env)
	}
}

// Regression: a non-empty Dir makes the child chdir after fork, under the
// parent's unveil, where "/" is not visible ("chdir /: no such file").
func TestNewCmdDoesNotChdir(t *testing.T) {
	spec, _ := basecmd.Lookup(basecmd.Uname, nil)
	cmd, _, _ := newCmd(context.Background(), spec, 16)
	if cmd.Dir != "" {
		t.Fatalf("Dir = %q; must be empty (sandbox.Apply sets cwd before unveil)", cmd.Dir)
	}
}

func TestFixedEnvHasNoInheritedVars(t *testing.T) {
	for _, kv := range fixedEnv {
		k, _, _ := strings.Cut(kv, "=")
		if k != "PATH" && k != "LC_ALL" {
			t.Errorf("unexpected env var %q", k)
		}
	}
	if strings.Contains(fixedEnv[0], "/usr/local") {
		t.Error("PATH must not include /usr/local")
	}
}

func TestLimiterCapsConcurrency(t *testing.T) {
	l := NewLimiter(2, 20*time.Millisecond)
	ctx := context.Background()
	if err := l.acquire(ctx); err != nil {
		t.Fatal(err)
	}
	if err := l.acquire(ctx); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := l.acquire(ctx)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("third acquire: %v, want ErrBusy", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("busy wait not bounded")
	}
	l.release()
	if err := l.acquire(ctx); err != nil {
		t.Fatalf("after release: %v", err)
	}
}

func TestLimiterHonoursCancel(t *testing.T) {
	l := NewLimiter(1, time.Minute)
	_ = l.acquire(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestRunBusyDoesNotExec(t *testing.T) {
	l := NewLimiter(1, 10*time.Millisecond)
	_ = l.acquire(context.Background()) // hold the only slot
	_, err := Exec{Limit: l}.Run(context.Background(), basecmd.Uname)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
}

func TestTimeoutFor(t *testing.T) {
	rc, err := basecmd.Lookup(basecmd.SvcEnabled, basecmd.Enabled{basecmd.FeatureServices: true})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := basecmd.Lookup(basecmd.Mounts, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		spec basecmd.Spec
		def  time.Duration
		want time.Duration
	}{
		{plain, 0, DefaultTimeout},
		{plain, time.Second, time.Second},
		{rc, 0, basecmd.RcctlTimeout},
		{rc, time.Minute, time.Minute}, // never lowers the runner's limit
	} {
		if got := timeoutFor(c.spec, c.def); got != c.want {
			t.Errorf("timeoutFor(%s, %s) = %s, want %s", c.spec.Path, c.def, got, c.want)
		}
	}
}
