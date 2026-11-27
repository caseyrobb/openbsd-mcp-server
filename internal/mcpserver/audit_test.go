package mcpserver

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/caseyrobb/openbsd-mcp-server/internal/audit"
	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
	"github.com/caseyrobb/openbsd-mcp-server/internal/collect"
	"github.com/caseyrobb/openbsd-mcp-server/internal/execx"
)

type memLog struct {
	mu    sync.Mutex
	lines []string
	pris  []audit.Priority
}

func (m *memLog) Log(p audit.Priority, msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lines = append(m.lines, msg)
	m.pris = append(m.pris, p)
}

func (m *memLog) find(t *testing.T, substr string) (string, audit.Priority) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, l := range m.lines {
		if strings.Contains(l, substr) {
			return l, m.pris[i]
		}
	}
	t.Fatalf("no audit line containing %q in:\n%s", substr, strings.Join(m.lines, "\n"))
	return "", 0
}

// secretRunner returns output containing a secret, to prove audit lines
// never include tool output.
type secretRunner struct{}

func (secretRunner) Run(_ context.Context, id basecmd.ID) (execx.Result, error) {
	return execx.Result{Stdout: "wpakey hunter2 TOPSECRET-OUTPUT\n"}, nil
}

func TestAuditLogsInitializeAndCalls(t *testing.T) {
	ml := &memLog{}
	cs, _ := connectWith(t, Config{Runner: secretRunner{}, Features: allFeatures, Audit: ml})
	ctx := context.Background()

	if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "network_status",
		Arguments: map[string]any{"view": "arp"}}); err != nil {
		t.Fatal(err)
	}
	line, pri := ml.find(t, `tool="network_status"`)
	if !strings.Contains(line, `args={"view"="arp"}`) || !strings.Contains(line, "result=ok") ||
		!strings.Contains(line, `client="test"`) ||
		!strings.Contains(line, "redactions=1") || pri != audit.Info {
		t.Errorf("line = %q (pri %d)", line, pri)
	}

	// Injection attempt in a rejected argument: logged escaped, on one line.
	cs.CallTool(ctx, &mcp.CallToolParams{Name: "pf_status",
		Arguments: map[string]any{"view": "rules\nevent=tool_call tool=fake result=ok"}})
	line, pri = ml.find(t, `tool="pf_status"`)
	if !strings.Contains(line, `rules\nevent=tool_call`) || pri == audit.Info {
		t.Errorf("line = %q (pri %d)", line, pri)
	}

	// Unknown tools are audited too.
	cs.CallTool(ctx, &mcp.CallToolParams{Name: "run_command", Arguments: map[string]any{"cmd": "id"}})
	ml.find(t, `tool="run_command"`)

	ml.mu.Lock()
	defer ml.mu.Unlock()
	for _, l := range ml.lines {
		if strings.ContainsAny(l, "\n\r") {
			t.Errorf("multi-line audit entry: %q", l)
		}
		if strings.Contains(l, "hunter2") || strings.Contains(l, "TOPSECRET") {
			t.Errorf("audit line contains tool output: %q", l)
		}
	}
}

func TestAuditRecordsConfigCheckValidity(t *testing.T) {
	ml := &memLog{}
	cs, _ := connectWith(t, Config{Runner: stubRunner{}, Features: allFeatures, Audit: ml})
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "config_check",
		Arguments: map[string]any{"daemon": "bgpd"}})
	if err != nil || res.IsError {
		t.Fatalf("err=%v res=%s", err, callText(res))
	}
	line, _ := ml.find(t, `tool="config_check"`)
	if !strings.Contains(line, "valid=true") {
		t.Errorf("line = %q", line)
	}
}

func TestFormatArgs(t *testing.T) {
	cases := map[string]string{
		``:                                     `{}`,
		`{}`:                                   `{}`,
		`{"view":"rules"}`:                     `{"view"="rules"}`,
		`{"n":5,"b":true}`:                     `{"b"=true,"n"=5}`,
		`{"n":1e300,"o":{"x":1},"l":[1]}`:      `{"l"=<[]interface {}>,"n"=1e+300,"o"=<map[string]interface {}>}`,
		`not json`:                             `<invalid json, 8 bytes>`,
		`{"a":"","b":"","c":"","d":"","e":""}`: `{"a"="","b"="","c"="","d"="",+1 more}`,
	}
	for in, want := range cases {
		if got := formatArgs(json.RawMessage(in)); got != want {
			t.Errorf("formatArgs(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestConfigCheckToolOnlyWithFeature(t *testing.T) {
	cs, _ := connectWith(t, Config{Runner: stubRunner{}, Features: basecmd.Enabled{basecmd.FeatureConfCheck: true}})
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "config_check",
		Arguments: map[string]any{"daemon": "pf"}})
	if err != nil || res.IsError {
		t.Fatalf("err=%v res=%s", err, callText(res))
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var got collect.ConfigCheckResult
	json.Unmarshal(raw, &got)
	if !got.Valid || got.Command != "/usr/bin/doas -n /sbin/pfctl -n -f /etc/pf.conf" {
		t.Errorf("got %+v", got)
	}
	// Not a listed daemon: rejected by the schema enum.
	res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "config_check",
		Arguments: map[string]any{"daemon": "named"}})
	if err == nil && !res.IsError {
		t.Error("config_check accepted unknown daemon")
	}
}

func TestLogTailToolOnlyWithFeature(t *testing.T) {
	cs, _ := connectWith(t, Config{Runner: stubRunner{}})
	if slices.Contains(toolNames(t, cs), "log_tail") {
		t.Fatal("log_tail registered without logs")
	}
	cs, _ = connectWith(t, Config{Runner: stubRunner{}, Features: basecmd.Enabled{basecmd.FeatureLogs: true}})
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "log_tail",
		Arguments: map[string]any{"log": "authlog", "lines": 5, "match": "sshd"}})
	if err != nil || res.IsError {
		t.Fatalf("err=%v res=%s", err, callText(res))
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var got collect.LogTailResult
	json.Unmarshal(raw, &got)
	if got.Log != "authlog" || got.Command != "/usr/bin/doas -n /usr/bin/tail -n 1000 /var/log/authlog" {
		t.Errorf("got %+v", got)
	}
	// The schema rejects paths, out-of-range counts and extra arguments
	// before anything runs.
	for _, args := range []map[string]any{
		{"log": "/etc/master.passwd"},
		{"log": "authlog", "lines": 100000},
		{"log": "authlog", "lines": 0.5},
		{"log": "authlog", "file": "/etc/spwd.db"},
		{"lines": 5},
	} {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "log_tail", Arguments: args})
		if err == nil && !res.IsError {
			t.Errorf("args %v accepted: %s", args, callText(res))
		}
	}
}
