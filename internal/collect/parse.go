package collect

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
)

// Structured parsers for the busiest views. Each takes the redacted text
// output and returns typed data, or nil when nothing could be parsed. A
// parser never fails the call: the text output is always returned too, and
// Data is a convenience on top of it. Formats are taken from the base
// sources (pfctl_parser.c print_status, sysctl.c print_sensor, netstat
// if.c intpr, ntpd.c show_status_msg/show_peer_msg).
var parsers = map[basecmd.ID]func(string) any{
	basecmd.PfInfo:    func(s string) any { return nilIfEmpty(ParsePfInfo(s)) },
	basecmd.Sensors:   func(s string) any { return nilIfEmpty(ParseSensors(s)) },
	basecmd.NetIfaces: func(s string) any { return nilIfEmpty(ParseNetstatIfaces(s)) },
	basecmd.NTPStatus: func(s string) any { return nilIfEmpty(ParseNTPStatus(s)) },
	basecmd.NTPPeers:  func(s string) any { return nilIfEmpty(ParseNTPPeers(s)) },
}

// nilIfEmpty turns a zero-length result into a nil interface, so Data is
// omitted from the JSON rather than sent as null or [].
func nilIfEmpty[T any](v T, ok bool) any {
	if !ok {
		return nil
	}
	return v
}

// --- pfctl -s info ---

// PfCounter is one pfctl -s info counter.
type PfCounter struct {
	Total uint64 `json:"total"`
	// RatePerSec is pf's own average since it was enabled; absent when pf
	// does not print one (current entries, or pf never ran).
	RatePerSec *float64 `json:"rate_per_sec,omitempty"`
}

// PfInfo is pfctl -s info.
type PfInfo struct {
	Enabled bool   `json:"enabled"`
	Uptime  string `json:"uptime,omitempty"` // "0 days 00:13:12"
	Debug   string `json:"debug,omitempty"`
	// Sections maps a section ("State Table", "Counters", "Interface
	// Stats for em0", ...) to its counters by name ("current entries",
	// "match", ...). Interface stats with IPv4/IPv6 columns use "<name>
	// (IPv4)" / "<name> (IPv6)".
	Sections map[string]map[string]PfCounter `json:"sections"`
}

var (
	pfStatusRe  = regexp.MustCompile(`^Status: (\S+)(?: for (.+?))?\s*(?:Debug: (\S+))?\s*$`)
	pfCounterRe = regexp.MustCompile(`^\s{2,}(\S(?:.*?\S)?)\s+(\d+)(?:\s+([\d.]+)/s|\s+(\d+))?\s*$`)
)

func ParsePfInfo(s string) (PfInfo, bool) {
	out := PfInfo{Sections: map[string]map[string]PfCounter{}}
	section, sub := "", ""
	ok := false
	for _, l := range strings.Split(s, "\n") {
		if m := pfStatusRe.FindStringSubmatch(l); m != nil {
			out.Enabled, out.Uptime, out.Debug = m[1] == "Enabled", m[2], m[3]
			ok = true
			continue
		}
		if strings.TrimSpace(l) == "" {
			continue
		}
		if !strings.HasPrefix(l, " ") {
			// Section header, e.g. "State Table   Total   Rate" or
			// "Interface Stats for em0   IPv4   IPv6".
			section, sub = strings.TrimSpace(strings.SplitN(l, "  ", 2)[0]), ""
			continue
		}
		m := pfCounterRe.FindStringSubmatch(l)
		if m == nil {
			// "  Packets In" sub-header inside interface stats.
			if t := strings.TrimSpace(l); !strings.ContainsAny(t, "0123456789") {
				sub = t
			}
			continue
		}
		if section == "" {
			continue
		}
		name := m[1]
		if sub != "" && strings.HasPrefix(l, "    ") {
			name = sub + " " + name
		}
		total, err := strconv.ParseUint(m[2], 10, 64)
		if err != nil {
			continue
		}
		if out.Sections[section] == nil {
			out.Sections[section] = map[string]PfCounter{}
		}
		c := PfCounter{Total: total}
		if m[3] != "" {
			if r, err := strconv.ParseFloat(m[3], 64); err == nil {
				c.RatePerSec = &r
			}
		}
		if m[4] != "" { // two columns: IPv4 and IPv6
			v6, err := strconv.ParseUint(m[4], 10, 64)
			if err != nil {
				continue
			}
			out.Sections[section][name+" (IPv4)"] = c
			out.Sections[section][name+" (IPv6)"] = PfCounter{Total: v6}
			ok = true
			continue
		}
		out.Sections[section][name] = c
		ok = true
	}
	return out, ok
}

// --- sysctl hw.sensors ---

// Sensor is one hw.sensors entry.
type Sensor struct {
	Device      string   `json:"device"`           // "cpu0", "acpibat0"
	Name        string   `json:"name"`             // "temp0"
	Type        string   `json:"type"`             // "temp", "fan", "volt", "indicator", ...
	Value       string   `json:"value"`            // as printed: "45.00", "On", "online"
	Number      *float64 `json:"number,omitempty"` // Value as a number, when it is one
	Unit        string   `json:"unit,omitempty"`   // "degC", "RPM", "VDC", "%", ...
	Description string   `json:"description,omitempty"`
	Status      string   `json:"status,omitempty"` // OK, WARNING, CRITICAL, UNKNOWN
}

var (
	sensorRe       = regexp.MustCompile(`^hw\.sensors\.([^.=\s]+)\.([a-z]+)(\d+)=(.*)$`)
	sensorTimeRe   = regexp.MustCompile(`, [A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d\.\d{3}$`)
	sensorStatusRe = regexp.MustCompile(`, (OK|WARNING|CRITICAL|UNKNOWN)$`)
)

func ParseSensors(s string) ([]Sensor, bool) {
	var out []Sensor
	for _, l := range strings.Split(s, "\n") {
		m := sensorRe.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		x := Sensor{Device: m[1], Type: m[2], Name: m[2] + m[3]}
		rest := sensorTimeRe.ReplaceAllString(m[4], "")
		if sm := sensorStatusRe.FindStringSubmatch(rest); sm != nil {
			x.Status = sm[1]
			rest = strings.TrimSuffix(rest, sm[0])
		}
		if i := strings.Index(rest, " ("); i >= 0 && strings.HasSuffix(rest, ")") {
			x.Description = rest[i+2 : len(rest)-1]
			rest = rest[:i]
		}
		x.Value = rest
		num, unit, _ := strings.Cut(rest, " ")
		if strings.HasSuffix(num, "%") && unit == "" {
			num, unit = strings.TrimSuffix(num, "%"), "%"
		}
		if f, err := strconv.ParseFloat(num, 64); err == nil {
			x.Value, x.Number, x.Unit = num, &f, unit
		}
		out = append(out, x)
	}
	return out, len(out) > 0
}

// --- netstat -in ---

// Interface is one interface's link-level counters from netstat -in.
type Interface struct {
	Name     string `json:"name"`
	Up       bool   `json:"up"` // netstat marks down interfaces with '*'
	MTU      int    `json:"mtu"`
	Address  string `json:"address,omitempty"` // link-layer address, if any
	InPkts   uint64 `json:"in_packets"`
	InFails  uint64 `json:"in_fails"` // errors + queue drops
	OutPkts  uint64 `json:"out_packets"`
	OutFails uint64 `json:"out_fails"`
	Colls    uint64 `json:"collisions"`
}

// ParseNetstatIfaces reads the <Link> rows, which carry each interface's
// totals; per-address rows repeat the same counters and are skipped.
func ParseNetstatIfaces(s string) ([]Interface, bool) {
	var out []Interface
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 8 || f[2] != "<Link>" {
			continue
		}
		mtu, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		n := make([]uint64, 5)
		bad := false
		for i, v := range f[len(f)-5:] {
			if n[i], err = strconv.ParseUint(v, 10, 64); err != nil {
				bad = true
			}
		}
		if bad {
			continue
		}
		x := Interface{Name: strings.TrimSuffix(f[0], "*"), Up: !strings.HasSuffix(f[0], "*"), MTU: mtu,
			InPkts: n[0], InFails: n[1], OutPkts: n[2], OutFails: n[3], Colls: n[4]}
		if len(f) == 9 {
			x.Address = f[3]
		}
		out = append(out, x)
	}
	return out, len(out) > 0
}

// --- ntpctl -s status / peers ---

// NTPStatus is ntpctl -s status.
type NTPStatus struct {
	PeersValid      *int     `json:"peers_valid,omitempty"`
	PeersTotal      *int     `json:"peers_total,omitempty"`
	SensorsValid    *int     `json:"sensors_valid,omitempty"`
	SensorsTotal    *int     `json:"sensors_total,omitempty"`
	ConstraintSecs  *int64   `json:"constraint_offset_secs,omitempty"`
	Synced          bool     `json:"synced"`
	Stratum         *int     `json:"stratum,omitempty"`
	ClockOffsetMsec *float64 `json:"clock_offset_ms,omitempty"` // only printed while unsynced
}

var (
	ntpPeersRe   = regexp.MustCompile(`(\d+)/(\d+) peers valid`)
	ntpSensorsRe = regexp.MustCompile(`(\d+)/(\d+) sensors valid`)
	ntpConstrRe  = regexp.MustCompile(`constraint offset (-?\d+)s`)
	ntpSyncedRe  = regexp.MustCompile(`clock synced, stratum (\d+)`)
	ntpOffsetRe  = regexp.MustCompile(`clock offset is (-?[\d.]+)ms`)
)

func ParseNTPStatus(s string) (NTPStatus, bool) {
	var out NTPStatus
	ok := false
	pair := func(re *regexp.Regexp, a, b **int) {
		if m := re.FindStringSubmatch(s); m != nil {
			x, _ := strconv.Atoi(m[1])
			y, _ := strconv.Atoi(m[2])
			*a, *b, ok = &x, &y, true
		}
	}
	pair(ntpPeersRe, &out.PeersValid, &out.PeersTotal)
	pair(ntpSensorsRe, &out.SensorsValid, &out.SensorsTotal)
	if m := ntpConstrRe.FindStringSubmatch(s); m != nil {
		v, _ := strconv.ParseInt(m[1], 10, 64)
		out.ConstraintSecs, ok = &v, true
	}
	if m := ntpSyncedRe.FindStringSubmatch(s); m != nil {
		v, _ := strconv.Atoi(m[1])
		out.Synced, out.Stratum, ok = true, &v, true
	} else if strings.Contains(s, "clock unsynced") {
		ok = true
	}
	if m := ntpOffsetRe.FindStringSubmatch(s); m != nil {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil {
			out.ClockOffsetMsec = &v
		}
	}
	return out, ok
}

// NTPPeer is one peer from ntpctl -s peers.
type NTPPeer struct {
	Peer       string   `json:"peer"` // "192.0.2.1 from pool pool.ntp.org"
	Selected   bool     `json:"selected"`
	Weight     int      `json:"weight"`
	TrustLevel int      `json:"trust_level"`
	Stratum    *int     `json:"stratum,omitempty"`
	NextSecs   int64    `json:"next_secs"`
	PollSecs   int64    `json:"poll_secs"`
	Valid      bool     `json:"valid"`
	OffsetMsec *float64 `json:"offset_ms,omitempty"`
	DelayMsec  *float64 `json:"delay_ms,omitempty"`
	JitterMsec *float64 `json:"jitter_ms,omitempty"`
}

// " *  1 10  2   23s   32s         0.123ms     1.234ms     0.045ms"
var ntpPeerStatsRe = regexp.MustCompile(
	`^ ([* ]) +(\d+) +(\d+) +(\d+|-) +(-?\d+)s +(-?\d+)s(?: +(-?[\d.]+)ms +(-?[\d.]+)ms +(-?[\d.]+)ms| +---- peer not valid ----)\s*$`)

func ParseNTPPeers(s string) ([]NTPPeer, bool) {
	lines := strings.Split(s, "\n")
	var out []NTPPeer
	for i := 1; i < len(lines); i++ {
		m := ntpPeerStatsRe.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		p := NTPPeer{Peer: strings.TrimSpace(lines[i-1]), Selected: m[1] == "*"}
		p.Weight, _ = strconv.Atoi(m[2])
		p.TrustLevel, _ = strconv.Atoi(m[3])
		if m[4] != "-" {
			st, _ := strconv.Atoi(m[4])
			p.Stratum = &st
		}
		p.NextSecs, _ = strconv.ParseInt(m[5], 10, 64)
		p.PollSecs, _ = strconv.ParseInt(m[6], 10, 64)
		if m[7] != "" {
			p.Valid = true
			p.OffsetMsec, p.DelayMsec, p.JitterMsec = msec(m[7]), msec(m[8]), msec(m[9])
		}
		out = append(out, p)
	}
	return out, len(out) > 0
}

func msec(s string) *float64 {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return &v
}
