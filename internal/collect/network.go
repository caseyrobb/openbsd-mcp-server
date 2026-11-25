package collect

import (
	"context"
	"strings"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
	"github.com/caseyrobb/openbsd-mcp-server/internal/execx"
	"github.com/caseyrobb/openbsd-mcp-server/internal/redact"
)

// NetworkSummary is the result of the network_summary tool. PF state lives
// in the separate, opt-in pf_status tool.
type NetworkSummary struct {
	Interfaces Section `json:"interfaces" jsonschema:"ifconfig output, secrets redacted"`
	Routes     Section `json:"routes" jsonschema:"netstat -rn output"`
	// Redactions counts values removed from command output.
	Redactions int      `json:"redactions,omitempty"`
	Errors     []string `json:"errors,omitempty"`
}

// Network collects interfaces and routes. Both work unprivileged.
func Network(ctx context.Context, r execx.Runner) (NetworkSummary, error) {
	var out NetworkSummary
	run := func(id basecmd.ID) Section {
		res, err := r.Run(ctx, id)
		red := redact.Text(strings.TrimRight(res.Stdout, "\n"))
		out.Redactions += red.Count
		s := Section{Output: red.Text, Truncated: res.Truncated}
		if err != nil {
			s.Error = err.Error()
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
