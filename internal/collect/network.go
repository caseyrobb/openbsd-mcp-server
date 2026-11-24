package collect

import (
	"context"
	"strings"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
	"github.com/caseyrobb/openbsd-mcp-server/internal/execx"
	"github.com/caseyrobb/openbsd-mcp-server/internal/redact"
)

// PFUnavailable is reported when pf_info is not enabled.
const PFUnavailable = "unavailable: pfctl needs root (/dev/pf is 0600). " +
	"Start the server with -pf-doas and add the exact-args doas.conf rule; see docs/ARCHITECTURE.md"

// NetworkSummary is the result of the network_summary tool.
type NetworkSummary struct {
	Interfaces Section `json:"interfaces" jsonschema:"ifconfig output, secrets redacted"`
	Routes     Section `json:"routes" jsonschema:"netstat -rn output"`
	PF         Section `json:"pf" jsonschema:"pfctl -s info output, or why it is unavailable"`
	// Redactions counts values removed from command output.
	Redactions int      `json:"redactions,omitempty"`
	Errors     []string `json:"errors,omitempty"`
}

// Network collects interfaces, routes and (if enabled) PF status. pfEnabled
// mirrors the -pf-doas flag; when false, pfctl is never executed.
func Network(ctx context.Context, r execx.Runner, pfEnabled bool) (NetworkSummary, error) {
	var out NetworkSummary
	run := func(id basecmd.ID) Section {
		res, err := r.Run(ctx, id)
		red := redact.Text(strings.TrimRight(res.Stdout, "\n"))
		out.Redactions += red.Count
		s := Section{Output: red.Text, Truncated: res.Truncated}
		if err != nil {
			s.Error = err.Error()
			// doas -n prints its refusal on stderr; surface it (redacted).
			if msg := strings.TrimSpace(res.Stderr); msg != "" {
				m, _ := redact.Line(firstLine(msg))
				s.Error += ": " + m
			}
			out.Errors = append(out.Errors, string(id))
		}
		return s
	}

	out.Interfaces = run(basecmd.Ifconfig)
	out.Routes = run(basecmd.Routes)
	if pfEnabled {
		out.PF = run(basecmd.PfInfo)
	} else {
		out.PF = Section{Error: PFUnavailable}
	}

	if err := ctx.Err(); err != nil {
		return NetworkSummary{}, err
	}
	return out, nil
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	if len(l) > 200 {
		l = l[:200]
	}
	return l
}
