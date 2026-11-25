package collect

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
	"github.com/caseyrobb/openbsd-mcp-server/internal/execx"
	"github.com/caseyrobb/openbsd-mcp-server/internal/redact"
)

// View maps a client-facing view name to one registered command.
type View struct {
	Name        string
	ID          basecmd.ID
	Description string
}

// nonZeroOK lists commands whose non-zero exit is part of the answer
// (rcctl ls failed exits 1 when it lists anything). A doas refusal is
// still an error.
var nonZeroOK = map[basecmd.ID]bool{basecmd.SvcFailed: true}

// Subsystem is one command family exposed as a <Name>_status tool.
type Subsystem struct {
	Name string // "pf", "unbound", "bgp", "system", ...
	// Feature gates the whole tool; "" means always available.
	Feature basecmd.Feature
	Views   []View // order is the order shown in the schema enum
	// Hint is appended to errors that look like an access/setup problem.
	Hint string
}

// The fixed view tables. Adding a view means adding a basecmd ID first,
// where the registry tests enforce read-only arguments.
var (
	PF = Subsystem{
		Name: "pf", Feature: basecmd.FeaturePF,
		Views: []View{
			{"info", basecmd.PfInfo, "pfctl -s info: status, counters, state table summary"},
			{"rules", basecmd.PfRules, "pfctl -s rules: loaded filter/NAT rules"},
			{"tables", basecmd.PfTables, "pfctl -s Tables: table names"},
			{"memory", basecmd.PfMemory, "pfctl -s memory: pool hard limits"},
			{"timeouts", basecmd.PfTimeouts, "pfctl -s timeouts: state timeouts"},
			{"interfaces", basecmd.PfInterfaces, "pfctl -s Interfaces: interfaces and groups pf knows"},
			{"queues", basecmd.PfQueues, "pfctl -s queue: queue definitions"},
		},
		Hint: "pfctl runs via 'doas -n'; check /etc/doas.conf against: obsd-mcp -enable pf -print-doas <user>",
	}
	Unbound = Subsystem{
		Name: "unbound", Feature: basecmd.FeatureUnbound,
		Views: []View{
			{"status", basecmd.UnboundStatus, "unbound-control status: version, uptime, threads, modules"},
			{"stats", basecmd.UnboundStats, "unbound-control stats_noreset: counters (never reset)"},
			{"forwards", basecmd.UnboundForwards, "unbound-control list_forwards"},
			{"stubs", basecmd.UnboundStubs, "unbound-control list_stubs"},
			{"local_zones", basecmd.UnboundLocalZones, "unbound-control list_local_zones"},
			{"auth_zones", basecmd.UnboundAuthZones, "unbound-control list_auth_zones"},
			{"insecure", basecmd.UnboundInsecure, "unbound-control list_insecure: domain-insecure trust points"},
		},
		Hint: "unbound-control runs via 'doas -n' and needs unbound running with remote-control enabled; " +
			"check /etc/doas.conf against: obsd-mcp -enable unbound -print-doas <user>",
	}
	BGP = Subsystem{
		Name: "bgp", Feature: basecmd.FeatureBGP,
		Views: []View{
			{"summary", basecmd.BGPSummary, "bgpctl show summary: neighbors, state, prefixes"},
			{"neighbors", basecmd.BGPNeighbors, "bgpctl show neighbor: per-neighbor detail"},
			{"nexthops", basecmd.BGPNexthops, "bgpctl show nexthop"},
			{"interfaces", basecmd.BGPInterfaces, "bgpctl show interfaces"},
			{"rib_memory", basecmd.BGPRIBMemory, "bgpctl show rib memory"},
		},
		Hint: "bgpctl uses bgpd's restricted socket; add 'socket \"" + basecmd.BGPRestrictedSocket +
			"\" restricted' to /etc/bgpd.conf and reload bgpd",
	}
)

// Always-available subsystems: unprivileged commands only.
var (
	SystemViews = Subsystem{
		Name: "system",
		Views: []View{
			{"sensors", basecmd.Sensors, "sysctl hw.sensors: temperatures, fans, voltages, batteries (empty if none)"},
			{"mounts", basecmd.Mounts, "mount: mounted filesystems and options"},
			{"swap", basecmd.Swap, "swapctl -l: swap devices and usage"},
			{"processes_cpu", basecmd.ProcsCPU, "ps -axr: all processes by CPU (program name only, no arguments)"},
			{"processes_memory", basecmd.ProcsMem, "ps -axm: all processes by memory (program name only, no arguments)"},
		},
	}
	NetworkViews = Subsystem{
		Name: "network",
		Views: []View{
			{"protocols", basecmd.NetProto, "netstat -s: per-protocol statistics (ip, tcp, udp, icmp, ...)"},
			{"interfaces", basecmd.NetIfaces, "netstat -in: per-interface packets, errors and collisions"},
			{"mbufs", basecmd.NetMbufs, "netstat -m: network memory (mbuf) usage"},
			{"sockets_inet", basecmd.NetSock4, "netstat -an -f inet: IPv4 sockets and listeners"},
			{"sockets_inet6", basecmd.NetSock6, "netstat -an -f inet6: IPv6 sockets and listeners"},
			{"arp", basecmd.NetARP, "arp -an: IPv4 neighbor (ARP) table"},
			{"ndp", basecmd.NetNDP, "ndp -an: IPv6 neighbor table"},
		},
	}
)

// Opt-in subsystems that need doas.
var (
	NTP = Subsystem{
		Name: "ntp", Feature: basecmd.FeatureNTP,
		Views: []View{
			{"status", basecmd.NTPStatus, "ntpctl -s status: sync state and clock offset"},
			{"peers", basecmd.NTPPeers, "ntpctl -s peers: servers, offset, delay, jitter"},
			{"sensors", basecmd.NTPSensors, "ntpctl -s Sensors: time sensors in use"},
			{"all", basecmd.NTPAll, "ntpctl -s all: status, peers and sensors"},
		},
		Hint: "ntpctl runs via 'doas -n' and needs ntpd running; " +
			"check /etc/doas.conf against: obsd-mcp -enable ntp -print-doas <user>",
	}
	Services = Subsystem{
		Name: "services", Feature: basecmd.FeatureServices,
		Views: []View{
			{"enabled", basecmd.SvcEnabled, "rcctl ls on: services enabled at boot"},
			{"started", basecmd.SvcStarted, "rcctl ls started: services currently running"},
			{"failed", basecmd.SvcFailed, "rcctl ls failed: enabled services that are not running"},
		},
		Hint: "rcctl runs via 'doas -n'; check /etc/doas.conf against: obsd-mcp -enable services -print-doas <user>",
	}
)

// Subsystems lists every *_status tool, always-available ones first.
var Subsystems = []Subsystem{SystemViews, NetworkViews, PF, Unbound, BGP, NTP, Services}

// ViewNames returns the view names in order (the schema enum).
func (s Subsystem) ViewNames() []string {
	out := make([]string, len(s.Views))
	for i, v := range s.Views {
		out[i] = v.Name
	}
	return out
}

// ErrUnknownView is returned for a view not in the subsystem's table.
var ErrUnknownView = errors.New("unknown view")

// StatusResult is the output of a *_status tool.
type StatusResult struct {
	Subsystem string `json:"subsystem"`
	View      string `json:"view"`
	Command   string `json:"command" jsonschema:"the exact fixed command line that was run"`
	Output    string `json:"output" jsonschema:"command output with secret values replaced by <redacted>"`
	Truncated bool   `json:"truncated,omitempty"`
	// Redactions counts values removed from the output.
	Redactions int `json:"redactions,omitempty"`
	// ExitStatus is set when a NonZeroOK view exited non-zero.
	ExitStatus int `json:"exit_status,omitempty"`
}

// Status runs one view. A failing command is returned as an error (the tool
// reports it to the client), with the first stderr line and a setup hint.
func Status(ctx context.Context, r execx.Runner, s Subsystem, view string) (StatusResult, error) {
	var v *View
	for i := range s.Views {
		if s.Views[i].Name == view {
			v = &s.Views[i]
		}
	}
	if v == nil {
		return StatusResult{}, fmt.Errorf("%w %q for %s (valid: %s)", ErrUnknownView, view, s.Name,
			strings.Join(s.ViewNames(), ", "))
	}

	res, err := r.Run(ctx, v.ID)
	if cerr := ctx.Err(); cerr != nil {
		return StatusResult{}, cerr
	}
	if err != nil && nonZeroOK[v.ID] && errors.Is(err, execx.ErrNonZeroExit) &&
		!strings.HasPrefix(strings.TrimSpace(res.Stderr), "doas:") {
		err = nil
	}
	if err != nil {
		msg := err.Error()
		if line := strings.TrimSpace(res.Stderr); line != "" {
			l, _ := redact.Line(firstLine(line))
			msg += ": " + l
		}
		// A timeout is not an access problem; the setup hint would mislead.
		if s.Hint != "" && !errors.Is(err, execx.ErrTimeout) {
			msg += " (hint: " + s.Hint + ")"
		}
		return StatusResult{}, errors.New(msg)
	}

	red := redact.Text(strings.TrimRight(res.Stdout, "\n"))
	return StatusResult{
		Subsystem:  s.Name,
		View:       v.Name,
		Command:    basecmd.Describe(v.ID),
		Output:     red.Text,
		Truncated:  res.Truncated,
		Redactions: red.Count,
		ExitStatus: res.ExitCode,
	}, nil
}
