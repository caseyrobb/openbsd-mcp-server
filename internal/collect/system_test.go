package collect

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
	"github.com/caseyrobb/openbsd-mcp-server/internal/execx"
)

type fakeRunner struct {
	out   map[basecmd.ID]execx.Result
	fail  map[basecmd.ID]bool
	calls []basecmd.ID
}

func (f *fakeRunner) Run(_ context.Context, id basecmd.ID) (execx.Result, error) {
	f.calls = append(f.calls, id)
	if f.fail[id] {
		return f.out[id], fmt.Errorf("%s: %w (status 1)", id, execx.ErrNonZeroExit)
	}
	return f.out[id], nil
}

// Captured from OpenBSD 7.8/amd64 (values altered).
const sysctlOut = `kern.ostype=OpenBSD
kern.osrelease=7.8
kern.version=OpenBSD 7.8 (GENERIC.MP) #54: Sun Oct 12 12:58:11 MDT 2025
    deraadt@amd64.openbsd.org:/usr/src/sys/arch/amd64/compile/GENERIC.MP

kern.boottime=Mon Nov 24 09:12:01 2026
kern.securelevel=1
hw.machine=amd64
hw.model=Intel(R) Xeon(R) CPU E3-1230 v6 @ 3.50GHz
hw.ncpu=8
hw.ncpuonline=4
hw.physmem=17053437952
hw.usermem=17053425664
vm.loadavg=0.08 0.12 0.09
`

func TestSystemHappyPath(t *testing.T) {
	f := &fakeRunner{out: map[basecmd.ID]execx.Result{
		basecmd.Sysctl: {Stdout: sysctlOut},
		basecmd.Uname:  {Stdout: "OpenBSD fw1 7.8 GENERIC.MP#54 amd64\n"},
		basecmd.Uptime: {Stdout: "10:00AM  up 47 mins, 1 user, load averages: 0.08, 0.12, 0.09\n"},
		basecmd.Df:     {Stdout: "Filesystem  Size  Used Avail Capacity  Mounted on\n/dev/sd0a 986M 120M 817M 13% /\n"},
		basecmd.Vmstat: {Stdout: " procs ...\n", Truncated: true},
	}}
	got, err := System(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Errors) != 0 {
		t.Errorf("unexpected errors %v", got.Errors)
	}
	if got.Sysctl["hw.ncpuonline"] != "4" || got.Sysctl["kern.osrelease"] != "7.8" {
		t.Errorf("sysctl parse: %v", got.Sysctl)
	}
	wantVer := "OpenBSD 7.8 (GENERIC.MP) #54: Sun Oct 12 12:58:11 MDT 2025\n    deraadt@amd64.openbsd.org:/usr/src/sys/arch/amd64/compile/GENERIC.MP"
	if got.Sysctl["kern.version"] != wantVer {
		t.Errorf("kern.version = %q", got.Sysctl["kern.version"])
	}
	if got.Uname.Output != "OpenBSD fw1 7.8 GENERIC.MP#54 amd64" {
		t.Errorf("uname = %q", got.Uname.Output)
	}
	if !got.VMStat.Truncated {
		t.Error("truncation flag lost")
	}
	if len(f.calls) != 5 {
		t.Errorf("calls = %v", f.calls)
	}
}

func TestSystemPartialFailure(t *testing.T) {
	f := &fakeRunner{
		out:  map[basecmd.ID]execx.Result{basecmd.Sysctl: {Stdout: sysctlOut}},
		fail: map[basecmd.ID]bool{basecmd.Df: true},
	}
	got, err := System(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Errors) != 1 || got.Errors[0] != "df" {
		t.Errorf("errors = %v", got.Errors)
	}
	if !strings.Contains(got.Disk.Error, execx.ErrNonZeroExit.Error()) {
		t.Errorf("df error not recorded: %q", got.Disk.Error)
	}
	if got.Sysctl["hw.machine"] != "amd64" {
		t.Error("other sections should still be populated")
	}
}

func TestSystemCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := System(ctx, &fakeRunner{}); err == nil {
		t.Fatal("want error on cancelled context")
	}
}

func TestParseSysctlIgnoresUnrequestedKeys(t *testing.T) {
	m := parseSysctl("kern.ostype=OpenBSD\nkern.hostid=12345\n  indented-after-unwanted\nevil=1\n")
	if _, ok := m["kern.hostid"]; ok {
		t.Error("unrequested MIB leaked into output")
	}
	if _, ok := m["evil"]; ok {
		t.Error("unrequested key leaked into output")
	}
	if m["kern.ostype"] != "OpenBSD" {
		t.Errorf("got %v", m)
	}
}
