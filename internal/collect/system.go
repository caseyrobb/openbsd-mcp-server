// Package collect gathers read-only OpenBSD base-system state. Collectors
// know nothing about MCP; they take an execx.Runner and return plain structs.
package collect

import (
	"context"
	"strings"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
	"github.com/caseyrobb/openbsd-mcp-server/internal/execx"
)

// Section is the raw, bounded output of one command.
type Section struct {
	Output    string `json:"output"`
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
}

// SystemOverview is the result of the system_overview tool.
type SystemOverview struct {
	Sysctl map[string]string `json:"sysctl" jsonschema:"selected kern/hw/vm sysctl values keyed by MIB name"`
	Uname  Section           `json:"uname"`
	Uptime Section           `json:"uptime"`
	Disk   Section           `json:"disk" jsonschema:"df -h output"`
	VMStat Section           `json:"vmstat"`
	// Errors lists sections that failed. Partial results are still returned.
	Errors []string `json:"errors,omitempty"`
}

// System collects the system overview. A failing command degrades only its
// own section; the overall call fails only if the context is cancelled.
func System(ctx context.Context, r execx.Runner) (SystemOverview, error) {
	var out SystemOverview
	run := func(id basecmd.ID) Section {
		res, err := r.Run(ctx, id)
		s := Section{Output: strings.TrimRight(res.Stdout, "\n"), Truncated: res.Truncated}
		if err != nil {
			s.Error = err.Error()
			out.Errors = append(out.Errors, string(id))
		}
		return s
	}

	sys := run(basecmd.Sysctl)
	out.Sysctl = parseSysctl(sys.Output)
	out.Uname = run(basecmd.Uname)
	out.Uptime = run(basecmd.Uptime)
	out.Disk = run(basecmd.Df)
	out.VMStat = run(basecmd.Vmstat)

	if err := ctx.Err(); err != nil {
		return SystemOverview{}, err
	}
	return out, nil
}

// parseSysctl parses `sysctl name...` output ("name=value" per line) and keeps
// only the MIBs we asked for. kern.version spans multiple lines; continuation
// lines are appended to the preceding value.
func parseSysctl(s string) map[string]string {
	want := make(map[string]bool, len(basecmd.SysctlNames))
	for _, n := range basecmd.SysctlNames {
		want[n] = true
	}
	m := map[string]string{}
	last := ""
	for _, line := range strings.Split(s, "\n") {
		if line == "" {
			continue
		}
		// Continuation lines (kern.version's second line) are indented.
		if line[0] == ' ' || line[0] == '\t' {
			if last != "" {
				m[last] += "\n" + line
			}
			continue
		}
		last = ""
		if k, v, ok := strings.Cut(line, "="); ok && want[k] {
			m[k] = v
			last = k
		}
	}
	for k, v := range m {
		m[k] = strings.TrimSpace(v)
	}
	return m
}
