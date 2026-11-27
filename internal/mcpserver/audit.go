package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/caseyrobb/openbsd-mcp-server/internal/audit"
)

// auditMiddleware logs every initialize, tools/call and prompts/get, including calls the
// SDK rejects before a handler runs (unknown tool, schema violation). It
// records what was asked and how it ended, never the tool output.
//
// Clients on the sessionless protocol (2026-07-28) never send initialize,
// so each tool_call line also carries the client identity from the session.
func auditMiddleware(l audit.Logger) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			switch method {
			case "initialize", "tools/call", "prompts/get":
			default:
				return next(ctx, method, req)
			}
			start := time.Now()
			res, err := next(ctx, method, req)
			ms := time.Since(start).Milliseconds()
			switch method {
			case "initialize":
				logInitialize(l, req, err)
			case "prompts/get":
				logPromptGet(l, req, err)
			default:
				logToolCall(l, req, res, err, ms)
			}
			return res, err
		}
	}
}

func logInitialize(l audit.Logger, req mcp.Request, err error) {
	msg := "event=initialize"
	if p, ok := req.GetParams().(*mcp.InitializeParams); ok && p != nil {
		if p.ClientInfo != nil {
			msg += " client=" + audit.Sanitize(p.ClientInfo.Name, 64) +
				" client_version=" + audit.Sanitize(p.ClientInfo.Version, 32)
		}
		msg += " protocol=" + audit.Sanitize(p.ProtocolVersion, 32)
	}
	if err != nil {
		msg += " result=error error=" + audit.Sanitize(err.Error(), 200)
		l.Log(audit.Warning, msg)
		return
	}
	l.Log(audit.Info, msg)
}

func logPromptGet(l audit.Logger, req mcp.Request, err error) {
	msg := "event=prompt_get"
	if p, ok := req.GetParams().(*mcp.GetPromptParams); ok && p != nil {
		raw, _ := json.Marshal(p.Arguments)
		msg += " prompt=" + audit.Sanitize(p.Name, 64) + " args=" + formatArgs(raw)
	}
	msg += " client=" + clientName(req)
	if err != nil {
		l.Log(audit.Notice, msg+" result=error error="+audit.Sanitize(err.Error(), 200))
		return
	}
	l.Log(audit.Info, msg+" result=ok")
}

func logToolCall(l audit.Logger, req mcp.Request, res mcp.Result, err error, ms int64) {
	var b strings.Builder
	b.WriteString("event=tool_call")
	if p, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok && p != nil {
		fmt.Fprintf(&b, " tool=%s args=%s", audit.Sanitize(p.Name, 64), formatArgs(p.Arguments))
	}
	b.WriteString(" client=" + clientName(req))
	fmt.Fprintf(&b, " ms=%d", ms)

	pri := audit.Info
	switch r, _ := res.(*mcp.CallToolResult); {
	case err != nil:
		pri = audit.Warning
		b.WriteString(" result=error error=" + audit.Sanitize(err.Error(), 200))
	case r == nil:
		b.WriteString(" result=ok")
	case r.IsError:
		pri = audit.Notice
		b.WriteString(" result=tool_error error=" + audit.Sanitize(firstText(r), 200))
	default:
		b.WriteString(" result=ok" + summarize(r.StructuredContent))
	}
	l.Log(pri, b.String())
}

// formatArgs renders arguments as {key="value",...} with every key and
// value sanitized and the number of keys capped. Only the shape is logged
// for non-string values.
func formatArgs(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Sprintf("<invalid json, %d bytes>", len(raw))
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	const maxKeys = 4
	var parts []string
	for i, k := range keys {
		if i == maxKeys {
			parts = append(parts, fmt.Sprintf("+%d more", len(keys)-maxKeys))
			break
		}
		v := "<" + fmt.Sprintf("%T", m[k]) + ">"
		switch x := m[k].(type) {
		case string:
			v = audit.Sanitize(x, 64)
		case float64:
			v = strconv.FormatFloat(x, 'g', 10, 64)
		case bool:
			v = strconv.FormatBool(x)
		}
		parts = append(parts, audit.Sanitize(k, 32)+"="+v)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// summarize pulls the shared result fields (redactions, truncated, valid)
// out of any tool's structured output, plus its size.
func summarize(sc any) string {
	if sc == nil {
		return ""
	}
	b, err := json.Marshal(sc)
	if err != nil {
		return ""
	}
	var f struct {
		Redactions int   `json:"redactions"`
		Truncated  bool  `json:"truncated"`
		Valid      *bool `json:"valid"`
	}
	_ = json.Unmarshal(b, &f)
	out := fmt.Sprintf(" bytes=%d redactions=%d truncated=%t", len(b), f.Redactions, f.Truncated)
	if f.Valid != nil {
		out += fmt.Sprintf(" valid=%t", *f.Valid)
	}
	return out
}

func firstText(r *mcp.CallToolResult) string {
	for _, c := range r.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			return t.Text
		}
	}
	return ""
}

// clientName is the sanitized client name the session reported, if any.
func clientName(req mcp.Request) string {
	if ss, ok := req.GetSession().(*mcp.ServerSession); ok && ss != nil {
		if ip := ss.InitializeParams(); ip != nil && ip.ClientInfo != nil {
			return audit.Sanitize(ip.ClientInfo.Name, 64)
		}
	}
	return `""`
}
