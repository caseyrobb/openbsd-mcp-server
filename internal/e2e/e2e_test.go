// Package e2e tests the installed server the way a client reaches it: over
// ssh(1) to a dedicated account that sshd pins to the server with the
// -print-sshd block, using the doas rules from -print-doas. scripts/e2e.sh
// sets that up in the CI VM from the built package and runs this test.
//
// Without OBSDMCP_E2E_SSH every test is skipped, so it is harmless in
// `go test ./...` and in the VM's unit-test pass.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type env struct {
	target   string // user@host
	key      string
	features []string
	version  string
}

func setup(t *testing.T) env {
	t.Helper()
	e := env{target: os.Getenv("OBSDMCP_E2E_SSH"), key: os.Getenv("OBSDMCP_E2E_KEY"),
		version: os.Getenv("OBSDMCP_E2E_VERSION")}
	if e.target == "" {
		t.Skip("OBSDMCP_E2E_SSH not set; run through scripts/e2e.sh")
	}
	if f := os.Getenv("OBSDMCP_E2E_FEATURES"); f != "" {
		e.features = strings.Split(f, ",")
	}
	return e
}

// ssh builds an ssh command that ignores user config and trusts the host
// key on first use, into a per-test known_hosts file.
func (e env) ssh(t *testing.T, extra ...string) *exec.Cmd {
	t.Helper()
	args := []string{"-F", "/dev/null", "-i", e.key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=" + filepath.Join(t.TempDir(), "known_hosts")}
	args = append(args, extra...)
	return exec.Command("/usr/bin/ssh", args...)
}

func (e env) has(f string) bool { return slices.Contains(e.features, f) }

func connect(t *testing.T, e env) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	c := mcp.NewClient(&mcp.Implementation{Name: "obsd-mcp-e2e", Version: "1"}, nil)
	cs, err := c.Connect(ctx, &mcp.CommandTransport{Command: e.ssh(t, "-T", e.target)}, nil)
	if err != nil {
		t.Fatalf("connect over ssh: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s %v: %v", tool, args, err)
	}
	if res.IsError {
		var msg string
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				msg += tc.Text
			}
		}
		t.Fatalf("%s %v: tool error: %s", tool, args, msg)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out map[string]any
	json.Unmarshal(raw, &out)
	return out
}

func TestServerOverSSH(t *testing.T) {
	e := setup(t)
	cs := connect(t, e)
	ctx := context.Background()

	tl, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var tools []string
	for _, tool := range tl.Tools {
		tools = append(tools, tool.Name)
	}
	want := []string{"system_overview", "network_summary", "system_status", "network_status", "config_read"}
	for f, tool := range map[string]string{"pf": "pf_status", "logs": "log_tail", "security": "security_status"} {
		if e.has(f) {
			want = append(want, tool)
		}
	}
	for _, w := range want {
		if !slices.Contains(tools, w) {
			t.Errorf("tool %s missing: %v", w, tools)
		}
	}
	if !e.has("pf") && slices.Contains(tools, "pf_status") {
		t.Error("pf_status registered without pf")
	}

	ov := call(t, cs, "system_overview", nil)
	if b, _ := json.Marshal(ov); !bytes.Contains(b, []byte("OpenBSD")) {
		t.Errorf("system_overview: %s", b)
	}
	if ni := call(t, cs, "network_status", map[string]any{"view": "interfaces"}); ni["data"] == nil {
		t.Errorf("network_status interfaces has no parsed data: %v", ni)
	}
	if e.has("pf") {
		if d, _ := call(t, cs, "pf_status", map[string]any{"view": "info"})["data"].(map[string]any); d == nil || d["sections"] == nil {
			t.Errorf("pf info data: %v", d)
		}
	}
	if e.has("security") {
		d, _ := call(t, cs, "security_status", map[string]any{"view": "sysctl"})["data"].(map[string]any)
		if _, ok := d["kern.securelevel"]; !ok {
			t.Errorf("security sysctl data: %v", d)
		}
		d, _ = call(t, cs, "security_status", map[string]any{"view": "sshd"})["data"].(map[string]any)
		if d["permitrootlogin"] == nil {
			t.Errorf("security sshd data: %v", d)
		}
		call(t, cs, "security_status", map[string]any{"view": "patches"})
		call(t, cs, "security_status", map[string]any{"view": "logins"})
	}

	pl, err := cs.ListPrompts(ctx, nil)
	if err != nil || len(pl.Prompts) == 0 {
		t.Errorf("prompts: %v, %v", pl, err)
	}

	// The audit log saw this session: its start line carries the ssh
	// client address, and the calls above were logged.
	if e.has("logs") {
		var out string
		for i := 0; i < 10; i++ {
			r := call(t, cs, "log_tail", map[string]any{"log": "daemon", "lines": 500, "match": "obsd-mcp"})
			out, _ = r["output"].(string)
			if strings.Contains(out, "event=tool_call tool=\"pf_status\"") || !e.has("pf") &&
				strings.Contains(out, "event=tool_call") {
				break
			}
			time.Sleep(time.Second)
		}
		for _, w := range []string{"event=session_start", `ssh_client="127.0.0.1 `, "event=tool_call", `client="obsd-mcp-e2e"`} {
			if !strings.Contains(out, w) {
				t.Errorf("audit log missing %q in:\n%s", w, out)
			}
		}
		if e.version != "" && !strings.Contains(out, `version="`+e.version+`"`) {
			t.Errorf("audit log has no session_start for version %s", e.version)
		}
	}
}

// ForceCommand wins over the command the client asks for.
func TestForcedCommand(t *testing.T) {
	e := setup(t)
	cmd := e.ssh(t, "-T", e.target, "/usr/bin/id; echo PWNED")
	cmd.Stdin = nil // /dev/null: the server sees EOF and exits
	out, _ := cmd.CombinedOutput()
	if bytes.Contains(out, []byte("uid=")) || bytes.Contains(out, []byte("PWNED")) {
		t.Fatalf("client command ran:\n%s", out)
	}
}

// DisableForwarding refuses remote forwards, so ExitOnForwardFailure fails.
func TestNoForwarding(t *testing.T) {
	e := setup(t)
	cmd := e.ssh(t, "-T", "-o", "ExitOnForwardFailure=yes", "-R", "0:127.0.0.1:22", e.target)
	cmd.Stdin = nil
	out, err := cmd.CombinedOutput()
	if err == nil || !bytes.Contains(bytes.ToLower(out), []byte("forwarding")) {
		t.Fatalf("remote forward was not refused (err=%v):\n%s", err, out)
	}
}

// PermitTTY no: a forced TTY request is refused.
func TestNoTTY(t *testing.T) {
	e := setup(t)
	cmd := e.ssh(t, "-tt", e.target)
	cmd.Stdin = nil
	out, _ := cmd.CombinedOutput()
	if !bytes.Contains(out, []byte("PTY allocation request failed")) {
		t.Fatalf("TTY not refused:\n%s", out)
	}
}
