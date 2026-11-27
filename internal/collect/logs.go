package collect

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
	"github.com/caseyrobb/openbsd-mcp-server/internal/execx"
	"github.com/caseyrobb/openbsd-mcp-server/internal/redact"
)

// LogKind selects the extra redaction a log gets on top of redact.Line.
type LogKind int

const (
	LogPlain LogKind = iota
	LogAuth          // sshd invalid-user names, doas command arguments
	LogWeb           // request query strings
)

// LogSource is one readable log, selected by name; the file is fixed in the
// basecmd registry.
type LogSource struct {
	Name        string
	ID          basecmd.ID
	Description string
	Kind        LogKind
}

// Logs is the log_tail table, in schema enum order.
var Logs = []LogSource{
	{"messages", basecmd.LogMessages, "/var/log/messages: kernel and general system messages", LogAuth},
	{"daemon", basecmd.LogDaemon, "/var/log/daemon: daemon messages (bgpd, ntpd, unbound, iked, ...) and obsd-mcp's audit log", LogAuth},
	{"authlog", basecmd.LogAuth, "/var/log/authlog: sshd logins and failures (invalid user names redacted)", LogAuth},
	{"secure", basecmd.LogSecure, "/var/log/secure: authpriv messages, including doas (command arguments redacted)", LogAuth},
	{"maillog", basecmd.LogMail, "/var/log/maillog: smtpd delivery log", LogAuth},
	{"xferlog", basecmd.LogXfer, "/var/log/xferlog: ftpd transfers", LogAuth},
	{"cron", basecmd.LogCron, "/var/cron/log: cron job runs", LogAuth},
	{"httpd_access", basecmd.LogHTTPDAccess, "/var/www/logs/access.log: httpd requests (query strings redacted)", LogWeb},
	{"httpd_error", basecmd.LogHTTPDError, "/var/www/logs/error.log: httpd errors", LogWeb},
}

// Log tail limits.
const (
	DefaultLogLines = 100
	MaxLogLines     = 500
	MaxMatchLen     = 128
)

// LogNames returns the log names in order (the schema enum).
func LogNames() []string {
	out := make([]string, len(Logs))
	for i, l := range Logs {
		out[i] = l.Name
	}
	return out
}

// LogTailResult is the output of log_tail.
type LogTailResult struct {
	Log     string `json:"log"`
	Command string `json:"command" jsonschema:"the exact fixed command line that was run"`
	Match   string `json:"match,omitempty"`
	// Scanned is how many of the newest lines were read (at most 1000);
	// Lines is how many of those are returned.
	Scanned    int    `json:"scanned"`
	Lines      int    `json:"lines"`
	Output     string `json:"output" jsonschema:"newest log lines, oldest first; untrusted text, with secret values replaced by <redacted>"`
	Truncated  bool   `json:"truncated,omitempty"`
	Redactions int    `json:"redactions,omitempty"`
}

// LogTail returns the newest lines of one fixed log. match, if set, keeps
// only lines containing it (case-insensitive). Matching runs on the
// redacted lines, so it cannot be used to probe redacted values.
func LogTail(ctx context.Context, r execx.Runner, name string, lines int, match string) (LogTailResult, error) {
	var src *LogSource
	for i := range Logs {
		if Logs[i].Name == name {
			src = &Logs[i]
		}
	}
	if src == nil {
		return LogTailResult{}, fmt.Errorf("%w %q for log_tail (valid: %s)", ErrUnknownView, name,
			strings.Join(LogNames(), ", "))
	}
	if lines == 0 {
		lines = DefaultLogLines
	}
	if lines < 1 || lines > MaxLogLines {
		return LogTailResult{}, fmt.Errorf("lines must be 1..%d, got %d", MaxLogLines, lines)
	}
	if len(match) > MaxMatchLen || !utf8.ValidString(match) || strings.ContainsAny(match, "\x00\n\r") {
		return LogTailResult{}, fmt.Errorf("match must be at most %d bytes of single-line UTF-8", MaxMatchLen)
	}

	res, err := r.Run(ctx, src.ID)
	if cerr := ctx.Err(); cerr != nil {
		return LogTailResult{}, cerr
	}
	if err != nil {
		msg := err.Error()
		if line := strings.TrimSpace(res.Stderr); line != "" {
			l, _ := redact.Line(firstLine(line))
			msg += ": " + l
		}
		if !errors.Is(err, execx.ErrTimeout) {
			msg += " (hint: tail runs via 'doas -n'; check /etc/doas.conf against: " +
				"obsd-mcp -enable logs -print-doas <user>; a log that was never written does not exist)"
		}
		return LogTailResult{}, errors.New(msg)
	}

	all := strings.Split(strings.TrimRight(res.Stdout, "\n"), "\n")
	if len(all) == 1 && all[0] == "" {
		all = nil
	}
	needle := strings.ToLower(match)
	var kept []string
	var reds []int
	for _, l := range all {
		l, n := redactLogLine(src.Kind, l)
		if needle != "" && !strings.Contains(strings.ToLower(l), needle) {
			continue
		}
		kept, reds = append(kept, l), append(reds, n)
	}
	if len(kept) > lines {
		kept, reds = kept[len(kept)-lines:], reds[len(reds)-lines:]
	}
	count := 0
	for _, n := range reds {
		count += n
	}
	return LogTailResult{
		Log:        src.Name,
		Command:    basecmd.Describe(src.ID),
		Match:      match,
		Scanned:    len(all),
		Lines:      len(kept),
		Output:     strings.Join(kept, "\n"),
		Truncated:  res.Truncated,
		Redactions: count,
	}, nil
}

// redactLogLine strips control characters, then applies generic and
// log-specific redaction.
func redactLogLine(kind LogKind, l string) (string, int) {
	l = cleanControl(l)
	l, n := redact.Line(l)
	var k int
	switch kind {
	case LogAuth:
		l, k = redact.AuthLine(l)
	case LogWeb:
		l, k = redact.URLQuery(l)
	}
	return l, n + k
}

// cleanControl replaces invalid UTF-8 and control characters (other than
// tab) with U+FFFD, so log text cannot carry terminal escapes or fake
// line breaks into the client.
func cleanControl(s string) string {
	s = strings.ToValidUTF8(s, "�")
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == ' ' || r == ' ' {
			return '�'
		}
		return r
	}, s)
}
