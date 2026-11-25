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

func TestNetworkNeverRunsOptInCommands(t *testing.T) {
	f := &fakeRunner{out: map[basecmd.ID]execx.Result{
		basecmd.Ifconfig: {Stdout: ifconfigOut},
		basecmd.Routes:   {Stdout: "Routing tables\n"},
	}}
	got, err := Network(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.calls, []basecmd.ID{basecmd.Ifconfig, basecmd.Routes}) {
		t.Fatalf("calls = %v", f.calls)
	}
	if len(got.Errors) != 0 {
		t.Errorf("errors = %v", got.Errors)
	}
}

func TestNetworkRedactsIfconfig(t *testing.T) {
	f := &fakeRunner{out: map[basecmd.ID]execx.Result{basecmd.Ifconfig: {Stdout: ifconfigOut}}}
	got, _ := Network(context.Background(), f)
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
