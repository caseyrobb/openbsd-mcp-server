package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
	"github.com/caseyrobb/openbsd-mcp-server/internal/collect"
	"github.com/caseyrobb/openbsd-mcp-server/internal/confread"
	"github.com/caseyrobb/openbsd-mcp-server/internal/execx"
)

type stubRunner struct{}

func (stubRunner) Run(_ context.Context, id basecmd.ID) (execx.Result, error) {
	if id == basecmd.Sysctl {
		return execx.Result{Stdout: "kern.ostype=OpenBSD\nhw.machine=amd64\n"}, nil
	}
	return execx.Result{Stdout: string(id) + " output\n"}, nil
}

// fakeConf stands in for *confread.Reader. Path validation and redaction are
// tested in internal/confread and internal/redact; here we only test the MCP
// adaptation: schema, argument plumbing and error mapping.
type fakeConf struct {
	files map[string]confread.File
	errs  map[string]error
	reads []string
}

func newFakeConf() *fakeConf {
	return &fakeConf{
		files: map[string]confread.File{
			"/etc/rc.conf.local": {Path: "/etc/rc.conf.local", Mode: "0644", Size: 28,
				Content: "pf=YES\nx_password=<redacted>\n", Redactions: 1},
		},
		errs: map[string]error{
			"/etc/pf.conf": fmt.Errorf("%w: /etc/pf.conf is mode 0600", confread.ErrPermission),
		},
	}
}

func (f *fakeConf) Paths() []string { return []string{"/etc/pf.conf", "/etc/rc.conf.local"} }

func (f *fakeConf) Read(p string) (confread.File, error) {
	f.reads = append(f.reads, p)
	if err, ok := f.errs[p]; ok {
		return confread.File{}, err
	}
	if file, ok := f.files[p]; ok {
		return file, nil
	}
	return confread.File{}, confread.ErrNotAllowed
}

// The production reader must satisfy the interface.
var _ ConfigReader = (*confread.Reader)(nil)

func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	cs, _ := connectWith(t, Config{Runner: stubRunner{}, Conf: newFakeConf()})
	return cs
}

func connectWith(t *testing.T, cfg Config) (*mcp.ClientSession, Config) {
	t.Helper()
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	if _, err := New(cfg).Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	cs, err := c.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs, cfg
}

func TestToolsAreReadOnly(t *testing.T) {
	cs := connect(t)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) == 0 {
		t.Fatal("no tools registered")
	}
	for _, tool := range res.Tools {
		a := tool.Annotations
		if a == nil || !a.ReadOnlyHint || a.DestructiveHint == nil || *a.DestructiveHint {
			t.Errorf("tool %q is not annotated read-only/non-destructive", tool.Name)
		}
	}
}

func TestSystemOverviewCall(t *testing.T) {
	cs := connect(t)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "system_overview"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res.Content)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var got collect.SystemOverview
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Sysctl["kern.ostype"] != "OpenBSD" || got.Uptime.Output != "uptime output" {
		t.Errorf("unexpected result %+v", got)
	}
}

func TestUnknownToolRejected(t *testing.T) {
	cs := connect(t)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "run_command"})
	if err == nil && (res == nil || !res.IsError) {
		t.Fatal("unknown tool call should fail")
	}
}

func callText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func TestNetworkSummaryCall(t *testing.T) {
	cs := connect(t)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "network_summary"})
	if err != nil || res.IsError {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var got collect.NetworkSummary
	json.Unmarshal(raw, &got)
	if got.PF.Error != collect.PFUnavailable || got.Interfaces.Output != "ifconfig output" {
		t.Errorf("got %+v", got)
	}
}

func TestConfigReadCall(t *testing.T) {
	fc := newFakeConf()
	cs, _ := connectWith(t, Config{Runner: stubRunner{}, Conf: fc})
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "config_read", Arguments: map[string]any{"path": "/etc/rc.conf.local"},
	})
	if err != nil || res.IsError {
		t.Fatalf("err=%v res=%s", err, callText(res))
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var f confread.File
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f != fc.files["/etc/rc.conf.local"] {
		t.Errorf("got %+v, want reader result passed through unchanged", f)
	}
	if !slices.Equal(fc.reads, []string{"/etc/rc.conf.local"}) {
		t.Errorf("reads = %v", fc.reads)
	}
}

func TestConfigReadErrorIsToolError(t *testing.T) {
	cs := connect(t)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "config_read", Arguments: map[string]any{"path": "/etc/pf.conf"},
	})
	if err != nil {
		t.Fatalf("protocol error %v; want a tool-level error result", err)
	}
	if !res.IsError || !strings.Contains(callText(res), "permission denied: /etc/pf.conf is mode 0600") {
		t.Fatalf("IsError=%v text=%q", res.IsError, callText(res))
	}
}

// Schema-invalid arguments must be rejected by the SDK before the reader is
// ever called.
func TestConfigReadSchemaRejectsBeforeReader(t *testing.T) {
	fc := newFakeConf()
	cs, _ := connectWith(t, Config{Runner: stubRunner{}, Conf: fc})
	for _, args := range []map[string]any{
		{"path": "/etc/master.passwd"},
		{"path": "/etc/../etc/rc.conf.local"},
		{"path": "/etc/passwd"},
		{"path": "/usr/local/etc/foo"},
		{"path": 42},
		{},
		{"path": "/etc/rc.conf.local", "extra": "x"},
	} {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "config_read", Arguments: args})
		if err == nil && !res.IsError {
			t.Errorf("args %v accepted: %s", args, callText(res))
		}
	}
	if len(fc.reads) != 0 {
		t.Errorf("reader called for schema-invalid input: %v", fc.reads)
	}
}

func TestConfigReadSchemaIsEnum(t *testing.T) {
	cs := connect(t)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		if tool.Name != "config_read" {
			continue
		}
		raw, _ := json.Marshal(tool.InputSchema)
		var schema struct {
			Properties struct {
				Path struct {
					Enum []string `json:"enum"`
				} `json:"path"`
			} `json:"properties"`
		}
		json.Unmarshal(raw, &schema)
		if !slices.Equal(schema.Properties.Path.Enum, newFakeConf().Paths()) {
			t.Errorf("enum = %v, want reader Paths()", schema.Properties.Path.Enum)
		}
		return
	}
	t.Fatal("config_read not registered")
}

func TestConfigReadOmittedWithoutReader(t *testing.T) {
	cs, _ := connectWith(t, Config{Runner: stubRunner{}})
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		if tool.Name == "config_read" {
			t.Fatal("config_read registered without a reader")
		}
	}
}
