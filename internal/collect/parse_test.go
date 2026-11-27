package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
	"github.com/caseyrobb/openbsd-mcp-server/internal/execx"
)

// The samples below are built with the same printf formats as the base
// sources, so widths and spacing match the real programs.

// pfInfoSample follows pfctl_parser.c print_status with a loginterface.
func pfInfoSample() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-44s", "Status: Enabled for 0 days 00:13:12")
	fmt.Fprintf(&b, "%15s\n\n", "Debug: err")
	fmt.Fprintf(&b, "Interface Stats for %-16s %5s %16s\n", "em0", "IPv4", "IPv6")
	fmt.Fprintf(&b, "  %-25s %14d %16d\n", "Bytes In", 1000, 2000)
	fmt.Fprintf(&b, "  %-25s %14d %16d\n", "Bytes Out", 3000, 4000)
	fmt.Fprintf(&b, "  Packets In\n")
	fmt.Fprintf(&b, "    %-23s %14d %16d\n", "Passed", 10, 20)
	fmt.Fprintf(&b, "    %-23s %14d %16d\n", "Blocked", 1, 2)
	fmt.Fprintf(&b, "  Packets Out\n")
	fmt.Fprintf(&b, "    %-23s %14d %16d\n", "Passed", 30, 40)
	fmt.Fprintf(&b, "    %-23s %14d %16d\n\n", "Blocked", 3, 4)
	fmt.Fprintf(&b, "%-27s %14s %16s\n", "State Table", "Total", "Rate")
	fmt.Fprintf(&b, "  %-25s %14d %14s\n", "current entries", 5, "")
	fmt.Fprintf(&b, "  %-25s %14d %14s\n", "half-open tcp", 0, "")
	fmt.Fprintf(&b, "  %-25s %14d %14.1f/s\n", "searches", 4123, 5.2)
	fmt.Fprintf(&b, "  %-25s %14d %14.1f/s\n", "inserts", 85, 0.1)
	fmt.Fprintf(&b, "Counters\n")
	fmt.Fprintf(&b, "  %-25s %14d %14.1f/s\n", "match", 106, 0.1)
	fmt.Fprintf(&b, "  %-25s %14d %14.1f/s\n", "state-mismatch", 7, 0.0)
	return b.String()
}

func TestParsePfInfo(t *testing.T) {
	got, ok := ParsePfInfo(pfInfoSample())
	if !ok || !got.Enabled || got.Uptime != "0 days 00:13:12" || got.Debug != "err" {
		t.Fatalf("got %+v", got)
	}
	st := got.Sections["State Table"]
	if st["current entries"].Total != 5 || st["current entries"].RatePerSec != nil {
		t.Errorf("current entries = %+v", st["current entries"])
	}
	if c := st["searches"]; c.Total != 4123 || c.RatePerSec == nil || *c.RatePerSec != 5.2 {
		t.Errorf("searches = %+v", c)
	}
	if c := got.Sections["Counters"]["state-mismatch"]; c.Total != 7 || c.RatePerSec == nil || *c.RatePerSec != 0 {
		t.Errorf("state-mismatch = %+v", c)
	}
	ifs := got.Sections["Interface Stats for em0"]
	for name, want := range map[string]uint64{
		"Bytes In (IPv4)": 1000, "Bytes In (IPv6)": 2000,
		"Packets In Passed (IPv4)": 10, "Packets Out Blocked (IPv6)": 4,
	} {
		if ifs[name].Total != want {
			t.Errorf("%s = %d, want %d (%v)", name, ifs[name].Total, want, ifs)
		}
	}
}

func TestParsePfInfoDisabled(t *testing.T) {
	got, ok := ParsePfInfo(fmt.Sprintf("%-44s%15s\n\n", "Status: Disabled", "Debug: err"))
	if !ok || got.Enabled || got.Uptime != "" {
		t.Errorf("got %+v ok=%v", got, ok)
	}
}

const sensorsSample = `hw.sensors.cpu0.temp0=45.00 degC
hw.sensors.acpibat0.watthour0=40.11 Wh (last full capacity)
hw.sensors.acpibat0.raw0=2 (battery charging), OK
hw.sensors.acpiac0.indicator0=On (power supply)
hw.sensors.lm0.fan1=1234 RPM, WARNING
hw.sensors.acpibat0.percent0=75.50% (battery remaining), OK
hw.sensors.softraid0.drive0=online (sd2), OK
hw.sensors.softraid0.drive1=powering up (sd3), CRITICAL
hw.sensors.nmea0.timedelta0=-0.000123 secs (GPS (fix)), OK, Fri Nov 27 10:00:00.123
hw.sensors.it0.volt0=unknown
`

func TestParseSensors(t *testing.T) {
	got, ok := ParseSensors(sensorsSample)
	if !ok || len(got) != 10 {
		t.Fatalf("got %d sensors: %+v", len(got), got)
	}
	num := func(i int) float64 {
		if got[i].Number == nil {
			t.Fatalf("%d: no number: %+v", i, got[i])
		}
		return *got[i].Number
	}
	if s := got[0]; s.Device != "cpu0" || s.Name != "temp0" || s.Type != "temp" || num(0) != 45 || s.Unit != "degC" {
		t.Errorf("temp: %+v", s)
	}
	if s := got[1]; num(1) != 40.11 || s.Unit != "Wh" || s.Description != "last full capacity" {
		t.Errorf("watthour: %+v", s)
	}
	if s := got[2]; num(2) != 2 || s.Unit != "" || s.Description != "battery charging" || s.Status != "OK" {
		t.Errorf("raw: %+v", s)
	}
	if s := got[3]; s.Value != "On" || s.Number != nil || s.Description != "power supply" {
		t.Errorf("indicator: %+v", s)
	}
	if s := got[4]; num(4) != 1234 || s.Unit != "RPM" || s.Status != "WARNING" {
		t.Errorf("fan: %+v", s)
	}
	if s := got[5]; num(5) != 75.5 || s.Unit != "%" || s.Status != "OK" {
		t.Errorf("percent: %+v", s)
	}
	if s := got[7]; s.Value != "powering up" || s.Description != "sd3" || s.Status != "CRITICAL" {
		t.Errorf("drive: %+v", s)
	}
	if s := got[8]; num(8) != -0.000123 || s.Unit != "secs" || s.Description != "GPS (fix)" || s.Status != "OK" {
		t.Errorf("timedelta: %+v", s)
	}
	if s := got[9]; s.Value != "unknown" || s.Number != nil {
		t.Errorf("unknown: %+v", s)
	}
}

// netstatSample follows netstat if.c intpr: "%-7s %-5d " then the
// address columns, then "%8llu %5llu %8llu %5llu %5llu".
func netstatSample() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-7.7s %-5.5s %-11.11s %-17.17s %8.8s %5.5s %8.8s %5.5s %5.5s\n",
		"Name", "Mtu", "Network", "Address", "Ipkts", "Ifail", "Opkts", "Ofail", "Colls")
	row := func(name string, mtu int, net, addr string, n ...uint64) {
		fmt.Fprintf(&b, "%-7s %-5d %-11.11s %-17.17s %8d %5d %8d %5d %5d\n", name, mtu, net, addr, n[0], n[1], n[2], n[3], n[4])
	}
	row("lo0", 32768, "<Link>", "", 30, 0, 30, 0, 0)
	row("lo0", 32768, "127/8", "127.0.0.1", 30, 0, 30, 0, 0)
	row("em0", 1500, "<Link>", "00:11:22:33:44:55", 123456, 7, 65432, 1, 0)
	row("em0", 1500, "192.0.2/24", "192.0.2.10", 123456, 7, 65432, 1, 0)
	row("em1*", 1500, "<Link>", "00:11:22:33:44:66", 0, 0, 0, 0, 0)
	row("enc0*", 0, "<Link>", "", 0, 0, 0, 0, 0)
	return b.String()
}

func TestParseNetstatIfaces(t *testing.T) {
	got, ok := ParseNetstatIfaces(netstatSample())
	if !ok || len(got) != 4 {
		t.Fatalf("got %+v", got)
	}
	if g := got[0]; g.Name != "lo0" || !g.Up || g.MTU != 32768 || g.Address != "" || g.InPkts != 30 {
		t.Errorf("lo0: %+v", g)
	}
	if g := got[1]; g.Name != "em0" || g.Address != "00:11:22:33:44:55" || g.InPkts != 123456 || g.InFails != 7 ||
		g.OutPkts != 65432 || g.OutFails != 1 {
		t.Errorf("em0: %+v", g)
	}
	if g := got[2]; g.Name != "em1" || g.Up {
		t.Errorf("em1: %+v", g)
	}
	if g := got[3]; g.Name != "enc0" || g.Up || g.MTU != 0 {
		t.Errorf("enc0: %+v", g)
	}
}

func TestParseNTPStatus(t *testing.T) {
	synced, ok := ParseNTPStatus("4/4 peers valid, constraint offset -1s, clock synced, stratum 3\n")
	if !ok || !synced.Synced || *synced.Stratum != 3 || *synced.PeersValid != 4 || *synced.PeersTotal != 4 ||
		*synced.ConstraintSecs != -1 || synced.ClockOffsetMsec != nil {
		t.Errorf("synced: %+v", synced)
	}
	un, ok := ParseNTPStatus("0/2 peers valid, 1/1 sensors valid, clock unsynced, clock offset is -12.345ms\n")
	if !ok || un.Synced || un.Stratum != nil || *un.SensorsValid != 1 || *un.ClockOffsetMsec != -12.345 {
		t.Errorf("unsynced: %+v", un)
	}
	if _, ok := ParseNTPStatus("ntpctl: connect: /var/run/ntpd.sock: No such file\n"); ok {
		t.Error("parsed an error message")
	}
}

// ntpPeersSample follows ntpd.c show_peer_msg.
func ntpPeersSample() string {
	var b strings.Builder
	b.WriteString("peer\n   wt tl st  next  poll          offset       delay      jitter\n")
	fmt.Fprintf(&b, "%s\n %1s %2d %2d %2s %4ds %4ds", "192.0.2.1 from pool pool.ntp.org", "*", 1, 10, " 2", 23, 32)
	fmt.Fprintf(&b, "  %12.3fms %9.3fms  %8.3fms\n", 0.123, 1.234, 0.045)
	fmt.Fprintf(&b, "%s\n %1s %2d %2d %2s %4ds %4ds", "2001:db8::1 from pool pool.ntp.org", " ", 1, 2, " -", 5, 15)
	fmt.Fprintf(&b, "             ---- peer not valid ----\n")
	fmt.Fprintf(&b, "%s\n %1s %2d %2d %2s %4ds %4ds", "198.51.100.7", " ", 1, 10, "16", 100, 3000)
	fmt.Fprintf(&b, "  %12.3fms %9.3fms  %8.3fms\n", -1250.5, 20.0, 3.25)
	return b.String()
}

func TestParseNTPPeers(t *testing.T) {
	got, ok := ParseNTPPeers(ntpPeersSample())
	if !ok || len(got) != 3 {
		t.Fatalf("got %+v", got)
	}
	if p := got[0]; p.Peer != "192.0.2.1 from pool pool.ntp.org" || !p.Selected || p.Weight != 1 || p.TrustLevel != 10 ||
		*p.Stratum != 2 || p.NextSecs != 23 || p.PollSecs != 32 || !p.Valid || *p.OffsetMsec != 0.123 ||
		*p.DelayMsec != 1.234 || *p.JitterMsec != 0.045 {
		t.Errorf("peer 0: %+v", p)
	}
	if p := got[1]; p.Selected || p.Stratum != nil || p.Valid || p.OffsetMsec != nil {
		t.Errorf("peer 1: %+v", p)
	}
	if p := got[2]; *p.Stratum != 16 || *p.OffsetMsec != -1250.5 {
		t.Errorf("peer 2: %+v", p)
	}
}

// Parsers must never panic or invent data on unrelated text.
func TestParsersOnGarbage(t *testing.T) {
	for _, in := range []string{"", "\n\n", "no peers configured\n", "garbage\x00\xff", strings.Repeat("  x 1\n", 5)} {
		ParsePfInfo(in)
		if _, ok := ParseSensors(in); ok {
			t.Errorf("sensors from %q", in)
		}
		if _, ok := ParseNetstatIfaces(in); ok {
			t.Errorf("interfaces from %q", in)
		}
		if _, ok := ParseNTPPeers(in); ok {
			t.Errorf("peers from %q", in)
		}
	}
}

func TestStatusAttachesData(t *testing.T) {
	r := &errRunner{res: execx.Result{Stdout: netstatSample()}}
	got, err := Status(context.Background(), r, NetworkViews, "interfaces")
	if err != nil {
		t.Fatal(err)
	}
	ifs, ok := got.Data.([]Interface)
	if !ok || len(ifs) != 4 {
		t.Fatalf("data = %#v", got.Data)
	}
	// A view without a parser, or output a parser cannot read, has no data.
	r = &errRunner{res: execx.Result{Stdout: "whatever\n"}}
	got, _ = Status(context.Background(), r, NetworkViews, "interfaces")
	raw, _ := json.Marshal(got)
	if got.Data != nil || strings.Contains(string(raw), `"data"`) {
		t.Errorf("unparseable output produced data: %s", raw)
	}
	got, _ = Status(context.Background(), r, NetworkViews, "arp")
	if got.Data != nil {
		t.Errorf("arp has data: %#v", got.Data)
	}
}

func TestParsersOnlyForRegisteredViews(t *testing.T) {
	inView := map[basecmd.ID]bool{}
	for _, s := range Subsystems {
		for _, v := range s.Views {
			inView[v.ID] = true
		}
	}
	for id := range parsers {
		if !inView[id] {
			t.Errorf("parser for %s, which no view runs", id)
		}
	}
}

// bgpSummarySample follows bgpctl output.c show_summary_head/show_summary.
func bgpSummarySample() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-28s %-10s %10s %10s %5s %-8s %s\n", "Neighbor", "AS", "MsgRcvd", "MsgSent", "OutQ", "Up/Down", "State/PrfRcvd")
	row := func(name, as string, rcvd, sent, q int, updown, state string) {
		fmt.Fprintf(&b, "%-*s %s %10d %10d %5d %-8s %s\n", 28-len(as), name, as, rcvd, sent, q, updown, state)
	}
	row("upstream one", "65001", 1234, 1200, 0, "1d02h03m", "  1520")
	row("192.0.2.2", "65002", 5, 6, 0, "Never", "Active")
	row("peer-with-max", "4200000000", 10, 10, 2, "00:12:34", "    12/100")
	row("rs template", "65003", 0, 0, 0, "Never", "Template")
	return b.String()
}

func TestParseBGPSummary(t *testing.T) {
	got, ok := ParseBGPSummary(bgpSummarySample())
	if !ok || len(got) != 4 {
		t.Fatalf("got %+v", got)
	}
	if n := got[0]; n.Neighbor != "upstream one" || n.AS != "65001" || n.MsgRcvd != 1234 || n.MsgSent != 1200 ||
		n.UpDown != "1d02h03m" || !n.Established || n.State != "Established" || *n.Prefixes != 1520 || n.MaxPrefix != nil {
		t.Errorf("established: %+v", n)
	}
	if n := got[1]; n.Established || n.State != "Active" || n.Prefixes != nil || n.UpDown != "Never" {
		t.Errorf("active: %+v", n)
	}
	if n := got[2]; n.AS != "4200000000" || n.OutQ != 2 || *n.Prefixes != 12 || *n.MaxPrefix != 100 {
		t.Errorf("max prefix: %+v", n)
	}
	if n := got[3]; n.Neighbor != "rs template" || n.State != "Template" || n.Established {
		t.Errorf("template: %+v", n)
	}
}

// ospfNbrSample follows ospfctl output.c show_neighbor (with Address) or
// ospf6ctl.c show_nbr_msg (without).
func ospfNbrSample(v6 bool) string {
	var b strings.Builder
	if v6 {
		fmt.Fprintf(&b, "%-15s %-3s %-12s %-9s %-11s %s\n", "ID", "Pri", "State", "DeadTime", "Iface", "Uptime")
		fmt.Fprintf(&b, "%-15s %-3d %-12s %-10s", "10.0.0.2", 1, "FULL/DR", "00:00:35")
		fmt.Fprintf(&b, "%-11s %s\n", "vio0", "01:02:03")
		fmt.Fprintf(&b, "%-15s %-3d %-12s %-10s", "10.0.0.3", 0, "2-WAY/OTHER", "00:00:31")
		fmt.Fprintf(&b, "%-11s %s\n", "vio1", "-")
		return b.String()
	}
	fmt.Fprintf(&b, "%-15s %-3s %-12s %-8s %-15s %-9s %s\n", "ID", "Pri", "State", "DeadTime", "Address", "Iface", "Uptime")
	fmt.Fprintf(&b, "%-15s %-3d %-12s %-9s", "10.0.0.2", 1, "FULL/DR", "00:00:35")
	fmt.Fprintf(&b, "%-15s %-9s %s\n", "192.0.2.2", "vio0", "1d02h03m")
	fmt.Fprintf(&b, "%-15s %-3d %-12s %-9s", "10.0.0.3", 1, "INIT/BCKUP", "00:00:39")
	fmt.Fprintf(&b, "%-15s %-9s %s\n", "192.0.2.3", "vio0", "-")
	return b.String()
}

func TestParseOSPFNeighbors(t *testing.T) {
	got, ok := ParseOSPFNeighbors(ospfNbrSample(false))
	if !ok || len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if n := got[0]; n.ID != "10.0.0.2" || n.Priority != 1 || n.State != "FULL" || n.Role != "DR" || !n.Full ||
		n.DeadTime != "00:00:35" || n.Address != "192.0.2.2" || n.Interface != "vio0" || n.Uptime != "1d02h03m" {
		t.Errorf("v4 full: %+v", n)
	}
	if n := got[1]; n.State != "INIT" || n.Full || n.Uptime != "" {
		t.Errorf("v4 init: %+v", n)
	}
	got, ok = ParseOSPFNeighbors(ospfNbrSample(true))
	if !ok || len(got) != 2 {
		t.Fatalf("v6 got %+v", got)
	}
	if n := got[0]; n.Address != "" || n.Interface != "vio0" || n.Uptime != "01:02:03" || !n.Full {
		t.Errorf("v6 full: %+v", n)
	}
	if n := got[1]; n.State != "2-WAY" || n.Role != "OTHER" || n.Priority != 0 || n.Interface != "vio1" || n.Uptime != "" {
		t.Errorf("v6 2-way: %+v", n)
	}
}

// swapSample follows swapctl swaplist.c list_swap with dolong.
func swapSample(devs int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-*s %*s %8s %8s %8s  %s\n", 11, "Device", 10, "512-blocks", "Used", "Avail", "Capacity", "Priority")
	fmt.Fprintf(&b, "%-*s %*d ", 11, "/dev/sd0b", 10, 4194304)
	fmt.Fprintf(&b, "%8d %8d %5.0f%%    %d\n", 1024, 4193280, 0.02, 0)
	if devs > 1 {
		fmt.Fprintf(&b, "%-*s %*d ", 11, "/dev/sd1b", 10, 2097152)
		fmt.Fprintf(&b, "%8d %8d %5.0f%%    %d\n", 1048576, 1048576, 50.0, 1)
		fmt.Fprintf(&b, "%-*s %*d %8d %8d %5.0f%%\n", 11, "Total", 10, 6291456, 1049600, 5241856, 17.0)
	}
	return b.String()
}

func TestParseSwap(t *testing.T) {
	got, ok := ParseSwap(swapSample(2))
	if !ok || len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if d := got[0]; d.Device != "/dev/sd0b" || d.TotalBytes != 4194304*512 || d.UsedBytes != 1024*512 ||
		d.AvailBytes != 4193280*512 || d.CapacityPct != 0 || d.Priority != 0 {
		t.Errorf("sd0b: %+v", d)
	}
	if d := got[1]; d.CapacityPct != 50 || d.Priority != 1 {
		t.Errorf("sd1b: %+v", d)
	}
	if _, ok := ParseSwap("No swap devices configured\n"); ok {
		t.Error("parsed no-swap message")
	}
	k := strings.Replace(swapSample(1), "512-blocks", " 1K-blocks", 1)
	if got, ok := ParseSwap(k); !ok || got[0].TotalBytes != 4194304*1024 {
		t.Errorf("1K blocks: %+v", got)
	}
}

func TestParseKeyValues(t *testing.T) {
	got, ok := ParseKeyValues("total.num.queries=1234\ntime.up=86400.123456\nuptime.human=1d\nnum.answer.rcode.NOERROR=7\n" +
		"bad key=1\n=3\nx=NaN\ny=+Inf\nnot a stat line\n")
	if !ok || len(got) != 3 || got["total.num.queries"] != 1234 || got["time.up"] != 86400.123456 ||
		got["num.answer.rcode.NOERROR"] != 7 {
		t.Errorf("got %v", got)
	}
	if _, err := json.Marshal(got); err != nil {
		t.Errorf("not JSON-encodable: %v", err)
	}
}

// Every parser must survive arbitrary text and return JSON-encodable data:
// a parser panic or an unencodable value would turn a working view into a
// tool error.
func FuzzParsers(f *testing.F) {
	for _, s := range []string{pfInfoSample(), sensorsSample, netstatSample(), ntpPeersSample(), bgpSummarySample(),
		ospfNbrSample(false), ospfNbrSample(true), swapSample(2), "a=1\nb=NaN\n", "hw.sensors.x0.temp0=NaN degC\nhw.sensors.x0.raw0=-Inf\n", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for id, p := range parsers {
			if _, err := json.Marshal(p(s)); err != nil {
				t.Errorf("%s: %v", id, err)
			}
		}
	})
}

func TestParseSSHDConfig(t *testing.T) {
	in := "port 22\naddressfamily any\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:22\nPermitRootLogin no\n" +
		"passwordauthentication no\nsubsystem sftp /usr/libexec/sftp-server\nhostkey /etc/ssh/ssh_host_ed25519_key\n" +
		"hostkey /etc/ssh/ssh_host_rsa_key\nsshd: no hostkeys available -- exiting.\n"
	got, ok := ParseSSHDConfig(in)
	if !ok || got["port"][0] != "22" || len(got["listenaddress"]) != 2 || got["permitrootlogin"][0] != "no" ||
		got["subsystem"][0] != "sftp /usr/libexec/sftp-server" || len(got["hostkey"]) != 2 {
		t.Errorf("got %v", got)
	}
	if _, has := got["sshd:"]; has {
		t.Error("error line parsed as a keyword")
	}
}

func TestParsePatches(t *testing.T) {
	got, ok := ParsePatches("79-001_xserver\n80-001_sshd\n80-003_libcrypto\n80-002_ld.so\nrollback.tgz\n")
	if !ok || len(got.Installed) != 3 || got.Latest["80"].Number != 3 || got.Latest["80"].Name != "libcrypto" ||
		got.Latest["79"].Name != "xserver" {
		t.Errorf("got %+v", got)
	}
	if _, ok := ParsePatches(""); ok {
		t.Error("no patches parsed as some")
	}
}
