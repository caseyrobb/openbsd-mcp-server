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

// Subsystem is one opt-in daemon/tool family exposed as a *_status tool.
type Subsystem struct {
	Name    string // "pf", "unbound", "bgp"
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

// Subsystems lists all opt-in subsystems.
var Subsystems = []Subsystem{PF, Unbound, BGP}

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
	if err != nil {
		msg := err.Error()
		if line := strings.TrimSpace(res.Stderr); line != "" {
			l, _ := redact.Line(firstLine(line))
			msg += ": " + l
		}
		return StatusResult{}, fmt.Errorf("%s (hint: %s)", msg, s.Hint)
	}

	red := redact.Text(strings.TrimRight(res.Stdout, "\n"))
	return StatusResult{
		Subsystem:  s.Name,
		View:       v.Name,
		Command:    basecmd.Describe(v.ID),
		Output:     red.Text,
		Truncated:  res.Truncated,
		Redactions: red.Count,
	}, nil
}
