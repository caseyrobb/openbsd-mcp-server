package collect

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
	"github.com/caseyrobb/openbsd-mcp-server/internal/execx"
)

// errRunner returns a fixed result and error for every command.
type errRunner struct {
	res   execx.Result
	err   error
	calls []basecmd.ID
}

func (e *errRunner) Run(_ context.Context, id basecmd.ID) (execx.Result, error) {
	e.calls = append(e.calls, id)
	return e.res, e.err
}

func nonZero(id basecmd.ID) error {
	return fmt.Errorf("%s: %w (status 1)", id, execx.ErrNonZeroExit)
}

func TestConfigCheckValid(t *testing.T) {
	r := &errRunner{res: execx.Result{Stderr: "configuration OK\n"}}
	got, err := ConfigCheck(context.Background(), r, "bgpd")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Valid || got.Output != "configuration OK" || got.Command != "/usr/bin/doas -n /usr/sbin/bgpd -n" {
		t.Errorf("got %+v", got)
	}
}

func TestConfigCheckInvalidIsAResultNotAnError(t *testing.T) {
	r := &errRunner{
		res: execx.Result{Stderr: "/etc/iked.conf: 12: syntax error\npsk \"hunter2\"\n"},
		err: nonZero(basecmd.CheckIKED),
	}
	got, err := ConfigCheck(context.Background(), r, "iked")
	if err != nil {
		t.Fatal(err)
	}
	if got.Valid || !strings.Contains(got.Output, "syntax error") {
		t.Errorf("got %+v", got)
	}
	if strings.Contains(got.Output, "hunter2") || got.Redactions == 0 {
		t.Errorf("psk not redacted: %+v", got)
	}
}

func TestConfigCheckDoasRefusalIsAnError(t *testing.T) {
	r := &errRunner{res: execx.Result{Stderr: "doas: Authorization required\n"}, err: nonZero(basecmd.CheckPF)}
	_, err := ConfigCheck(context.Background(), r, "pf")
	if err == nil || !strings.Contains(err.Error(), "doas: Authorization required") ||
		!strings.Contains(err.Error(), "-print-doas") {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigCheckExecFailureIsAnError(t *testing.T) {
	r := &errRunner{err: errors.New("fork/exec /usr/bin/doas: no such file or directory")}
	if _, err := ConfigCheck(context.Background(), r, "httpd"); err == nil {
		t.Fatal("want error")
	}
}

func TestConfigCheckUnknownDaemonRunsNothing(t *testing.T) {
	r := &errRunner{}
	for _, d := range []string{"", "named", "pf -f /tmp/x", "../pf", "PF"} {
		if _, err := ConfigCheck(context.Background(), r, d); !errors.Is(err, ErrUnknownView) {
			t.Errorf("%q: err = %v", d, err)
		}
	}
	if len(r.calls) != 0 {
		t.Errorf("ran %v", r.calls)
	}
}
