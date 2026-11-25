//go:build openbsd && (amd64 || arm64)

package audit

import "testing"

// TestSendsyslog exercises the libc trampoline for real. It needs syslogd
// running (the default on OpenBSD); the line lands in /var/log/daemon.
func TestSendsyslog(t *testing.T) {
	if err := sendsyslog(syslogLine(Info, "obsd-mcp-test", 1, "audit self-test")); err != nil {
		t.Fatalf("sendsyslog: %v", err)
	}
}
