package collect

import (
	"os"
	"path/filepath"
	"testing"
)

// Real output captured on OpenBSD 8.0 (amd64 VM), with addresses replaced
// by documentation values. These catch format drift that the printf-built
// samples in parse_test.go would not.
func golden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "openbsd80", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestGoldenPfInfo(t *testing.T) {
	got, ok := ParsePfInfo(golden(t, "pfctl_info.txt"))
	if !ok || !got.Enabled || got.Uptime != "2 days 13:15:30" || got.Debug != "err" {
		t.Fatalf("got %+v", got)
	}
	st, c := got.Sections["State Table"], got.Sections["Counters"]
	if len(st) != 5 || len(c) != 17 {
		t.Errorf("state table %d counters, counters %d: %+v", len(st), len(c), got.Sections)
	}
	if st["current entries"].Total != 29 || st["current entries"].RatePerSec != nil {
		t.Errorf("current entries %+v", st["current entries"])
	}
	if s := st["searches"]; s.Total != 947972 || s.RatePerSec == nil || *s.RatePerSec != 4.3 {
		t.Errorf("searches %+v", s)
	}
	if c["short"].Total != 10 || c["no-route"].RatePerSec == nil {
		t.Errorf("counters %+v", c)
	}
}

func TestGoldenSensors(t *testing.T) {
	got, ok := ParseSensors(golden(t, "sensors.txt"))
	if !ok || len(got) != 3 {
		t.Fatalf("got %+v", got)
	}
	if s := got[0]; s.Device != "pvclock0" || s.Name != "timedelta0" || s.Number == nil || *s.Number != -0.0031 ||
		s.Unit != "secs" || s.Status != "OK" || s.Description != "" {
		t.Errorf("pvclock %+v", s)
	}
	if s := got[2]; s.Device != "viomb0" || s.Type != "raw" || s.Number == nil || *s.Number != 0 || s.Description != "current" {
		t.Errorf("viomb %+v", s)
	}
}

func TestGoldenNetstat(t *testing.T) {
	got, ok := ParseNetstatIfaces(golden(t, "netstat_in.txt"))
	if !ok || len(got) != 5 {
		t.Fatalf("got %+v", got)
	}
	want := []Interface{
		{Name: "lo0", Up: true, MTU: 32768, InPkts: 6, OutPkts: 6},
		{Name: "vio0", Up: true, MTU: 1500, Address: "00:00:5e:00:53:36", InPkts: 1500488, OutPkts: 107458},
		{Name: "vio1", MTU: 1500, Address: "00:00:5e:00:53:2a"},
		{Name: "enc0"},
		{Name: "pflog0", Up: true, MTU: 33136},
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("%d: got %+v, want %+v", i, got[i], w)
		}
	}
}

func TestGoldenNTP(t *testing.T) {
	st, ok := ParseNTPStatus(golden(t, "ntpctl_status.txt"))
	if !ok || !st.Synced || *st.Stratum != 4 || *st.PeersValid != 5 || *st.SensorsTotal != 1 || *st.ConstraintSecs != -1 {
		t.Errorf("status %+v", st)
	}
	peers, ok := ParseNTPPeers(golden(t, "ntpctl_peers.txt"))
	if !ok || len(peers) != 5 {
		t.Fatalf("peers %+v", peers)
	}
	sel := 0
	for _, p := range peers {
		if p.Selected {
			sel++
		}
		if !p.Valid || p.OffsetMsec == nil || p.TrustLevel != 10 {
			t.Errorf("peer %+v", p)
		}
	}
	if p := peers[1]; sel != 1 || !p.Selected || p.Peer != "162.159.200.1 from pool pool.ntp.org" ||
		*p.OffsetMsec != 24.5 || *p.JitterMsec != 143.992 || p.PollSecs != 1522 {
		t.Errorf("selected peer %+v (selected=%d)", p, sel)
	}
	if p := peers[2]; *p.Stratum != 1 || *p.OffsetMsec != -0.499 {
		t.Errorf("peer 2 %+v", p)
	}
}
