package collect

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
	"github.com/caseyrobb/openbsd-mcp-server/internal/execx"
)

const ifconfigOut = `lo0: flags=2008049<UP,LOOPBACK,RUNNING,MULTICAST,LRO> mtu 32768
	index 4 priority 0 llprio 3
	inet 127.0.0.1 netmask 0xff000000
iwx0: flags=808843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,AUTOCONF4> mtu 1500
	ieee80211: join homenet chan 36 bssid 00:11:22:33:44:55 -52dBm wpakey hunter2 wpaprotos wpa2
	inet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255
`

func TestNetworkDefaultNeverRunsPfctl(t *testing.T) {
	f := &fakeRunner{out: map[basecmd.ID]execx.Result{
		basecmd.Ifconfig: {Stdout: ifconfigOut},
		basecmd.Routes:   {Stdout: "Routing tables\n"},
	}}
	got, err := Network(context.Background(), f, false)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.calls, basecmd.PfInfo) {
		t.Fatal("pf_info executed without opt-in")
	}
	if got.PF.Error != PFUnavailable {
		t.Errorf("pf error = %q", got.PF.Error)
	}
	if len(got.Errors) != 0 {
		t.Errorf("errors = %v (unavailable PF is not an error)", got.Errors)
	}
}

func TestNetworkRedactsIfconfig(t *testing.T) {
	f := &fakeRunner{out: map[basecmd.ID]execx.Result{basecmd.Ifconfig: {Stdout: ifconfigOut}}}
	got, _ := Network(context.Background(), f, false)
	if strings.Contains(got.Interfaces.Output, "hunter2") {
		t.Fatal("wpakey leaked")
	}
	if !strings.Contains(got.Interfaces.Output, "wpakey <redacted>") || got.Redactions != 1 {
		t.Errorf("redactions=%d output:\n%s", got.Redactions, got.Interfaces.Output)
	}
	if !strings.Contains(got.Interfaces.Output, "inet 192.0.2.10") {
		t.Error("non-secret data lost")
	}
}

func TestNetworkPfEnabled(t *testing.T) {
	f := &fakeRunner{out: map[basecmd.ID]execx.Result{
		basecmd.PfInfo: {Stdout: "Status: Enabled for 0 days 00:47:01\n"},
	}}
	got, _ := Network(context.Background(), f, true)
	if got.PF.Output != "Status: Enabled for 0 days 00:47:01" || got.PF.Error != "" {
		t.Errorf("pf = %+v", got.PF)
	}
}

func TestNetworkPfDoasRefusalSurfaced(t *testing.T) {
	f := &fakeRunner{
		out:  map[basecmd.ID]execx.Result{basecmd.PfInfo: {Stderr: "doas: Operation not permitted\n"}},
		fail: map[basecmd.ID]bool{basecmd.PfInfo: true},
	}
	got, _ := Network(context.Background(), f, true)
	if !strings.Contains(got.PF.Error, "doas: Operation not permitted") {
		t.Errorf("pf error = %q", got.PF.Error)
	}
	if !slices.Equal(got.Errors, []string{"pf_info"}) {
		t.Errorf("errors = %v", got.Errors)
	}
}
