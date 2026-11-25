// Package audit records one line per MCP event (session start, client
// identity, every tool call) for the operator. On OpenBSD it writes to
// syslogd via sendsyslog(2), which pledge allows under "stdio", so auditing
// needs no extra pledge promise, no unveil path and no socket.
//
// Audit lines never contain tool output. Every client-supplied value is
// passed through Sanitize first.
package audit

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"unicode/utf8"
)

// Priority is a syslog severity.
type Priority int

const (
	Warning Priority = 4
	Notice  Priority = 5
	Info    Priority = 6
)

// facility is LOG_DAEMON; lines land in /var/log/daemon by default.
const facility = 3 << 3

// Logger records audit lines. Implementations are safe for concurrent use.
type Logger interface {
	Log(p Priority, msg string)
}

// ErrUnsupported is returned by NewSyslog where sendsyslog is unavailable.
var ErrUnsupported = errors.New("audit: syslog not supported on this platform")

// Sanitize renders untrusted text as a quoted, ASCII-only Go string of at most max
// runes, so a value can never inject newlines, control characters or fake
// key=value pairs into an audit line.
func Sanitize(s string, max int) string {
	if !utf8.ValidString(s) {
		s = string([]rune(s)) // replaces invalid bytes with U+FFFD
	}
	if r := []rune(s); len(r) > max {
		s = string(r[:max]) + "…"
	}
	return strconv.QuoteToASCII(s)
}

// Writer is a Logger for an io.Writer (stderr in development).
type Writer struct {
	W  io.Writer
	mu sync.Mutex
}

func (w *Writer) Log(p Priority, msg string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fmt.Fprintf(w.W, "obsd-mcp audit: %s\n", msg)
}

// syslogLine formats an RFC 3164 message the way libc syslog_r does for
// sendsyslog: "<pri>tag[pid]: msg". syslogd adds the timestamp and host.
func syslogLine(p Priority, tag string, pid int, msg string) []byte {
	return fmt.Appendf(nil, "<%d>%s[%d]: %s", facility|int(p), tag, pid, msg)
}
