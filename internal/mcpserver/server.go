// Package mcpserver is the only package that knows about MCP. It maps tools
// onto collectors and never touches the filesystem or exec directly.
package mcpserver

import (
	"context"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/caseyrobb/openbsd-mcp-server/internal/collect"
	"github.com/caseyrobb/openbsd-mcp-server/internal/confread"
	"github.com/caseyrobb/openbsd-mcp-server/internal/execx"
)

const (
	Name    = "obsd-mcp"
	Version = "0.1.0"
)

// ConfigReader is what config_read needs from the config reader. The
// production implementation is *confread.Reader, which owns all path
// validation, safe-open and redaction logic; this package only adapts it to
// MCP, so tests can substitute a fake.
type ConfigReader interface {
	// Paths returns the allowlist, exposed to clients as the schema enum.
	Paths() []string
	// Read returns the redacted file. Errors must be safe to show a client.
	Read(path string) (confread.File, error)
}

// Config holds the dependencies for every tool.
type Config struct {
	Runner execx.Runner
	// PFEnabled mirrors -pf-doas. The runner must also have pf_info enabled.
	PFEnabled bool
	// Conf enables config_read. Leave nil (untyped) to omit the tool.
	Conf ConfigReader
}

func ptr[T any](v T) *T { return &v }

// readOnly is attached to every tool. It is a hint for clients; the real
// guarantee is pledge(2) without wpath/cpath plus fixed-argv execution.
var readOnly = &mcp.ToolAnnotations{
	ReadOnlyHint:    true,
	IdempotentHint:  true,
	DestructiveHint: ptr(false),
	OpenWorldHint:   ptr(false),
}

// ConfigReadInput is the argument to config_read.
type ConfigReadInput struct {
	Path string `json:"path"`
}

// New builds the MCP server with all tools registered.
func New(c Config) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: Name, Version: Version}, nil)

	mcp.AddTool(s, &mcp.Tool{
		Name:  "system_overview",
		Title: "OpenBSD system overview",
		Description: "Read-only snapshot of the OpenBSD base system: uname, uptime, " +
			"selected kern/hw/vm sysctl values, df -h and vmstat. Takes no arguments.",
		Annotations: readOnly,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, collect.SystemOverview, error) {
		out, err := collect.System(ctx, c.Runner)
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:  "network_summary",
		Title: "OpenBSD network and PF summary",
		Description: "Read-only network state: ifconfig (secrets redacted), netstat -rn, " +
			"and pfctl -s info when the operator enabled it. Takes no arguments.",
		Annotations: readOnly,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, collect.NetworkSummary, error) {
		out, err := collect.Network(ctx, c.Runner, c.PFEnabled)
		return nil, out, err
	})

	if c.Conf != nil {
		paths := c.Conf.Paths()
		enum := make([]any, len(paths))
		for i, p := range paths {
			enum[i] = p
		}
		mcp.AddTool(s, &mcp.Tool{
			Name:  "config_read",
			Title: "Read an allowlisted base config file",
			Description: "Returns the contents of one allowlisted OpenBSD base-system config file " +
				"with secret values replaced by <redacted>. Only the paths in the enum are accepted. " +
				"Some (e.g. /etc/pf.conf, /etc/hostname.*) are root-only by default and will report permission denied.",
			Annotations: readOnly,
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"path": {Type: "string", Enum: enum, Description: "absolute path of an allowlisted config file"},
				},
				Required:             []string{"path"},
				AdditionalProperties: &jsonschema.Schema{Not: &jsonschema.Schema{}},
			},
		}, func(_ context.Context, _ *mcp.CallToolRequest, in ConfigReadInput) (*mcp.CallToolResult, confread.File, error) {
			// The schema enum is a convenience; Read re-validates everything.
			f, err := c.Conf.Read(in.Path)
			return nil, f, err
		})
	}

	return s
}
