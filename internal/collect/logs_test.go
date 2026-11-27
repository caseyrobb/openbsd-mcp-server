package collect

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
	"github.com/caseyrobb/openbsd-mcp-server/internal/execx"
)

const authSample = `Nov 27 10:00:01 h sshd[1]: Invalid user hunter2 from 192.0.2.7 port 50000
Nov 27 10:00:02 h sshd[1]: Accepted publickey for jdoe from 192.0.2.8 port 22 ssh2
Nov 27 10:00:03 h doas: jdoe ran command mysql -pS3CR3T as root from /home/jdoe
Nov 27 10:00:04 h sshd[1]: Failed password for root from 192.0.2.9 port 22 ssh2
`

func TestLogTailRedactsAndKeepsOrder(t *testing.T) {
	r := &errRunner{res: execx.Result{Stdout: authSample}}
	got, err := LogTail(context.Background(), r, "authlog", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 || r.calls[0] != basecmd.LogAuth {
		t.Fatalf("ran %v", r.calls)
	}
	if got.Command != "/usr/bin/doas -n /usr/bin/tail -n 1000 /var/log/authlog" {
		t.Errorf("command %q", got.Command)
	}
	for _, secret := range []string{"hunter2", "S3CR3T"} {
		if strings.Contains(got.Output, secret) {
			t.Errorf("output leaks %q:\n%s", secret, got.Output)
		}
	}
	if got.Scanned != 4 || got.Lines != 4 || got.Redactions != 2 {
		t.Errorf("scanned=%d lines=%d redactions=%d", got.Scanned, got.Lines, got.Redactions)
	}
	if !strings.HasPrefix(got.Output, "Nov 27 10:00:01") || !strings.HasSuffix(got.Output, "ssh2") {
		t.Errorf("order:\n%s", got.Output)
	}
}

func TestLogTailLinesKeepsNewest(t *testing.T) {
	r := &errRunner{res: execx.Result{Stdout: authSample}}
	got, err := LogTail(context.Background(), r, "authlog", 2, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Lines != 2 || !strings.HasPrefix(got.Output, "Nov 27 10:00:03") || got.Redactions != 1 {
		t.Errorf("got %+v", got)
	}
}

func TestLogTailMatch(t *testing.T) {
	r := &errRunner{res: execx.Result{Stdout: authSample}}
	got, err := LogTail(context.Background(), r, "authlog", 10, "SSHD")
	if err != nil {
		t.Fatal(err)
	}
	if got.Lines != 3 || strings.Contains(got.Output, "doas") || got.Match != "SSHD" {
		t.Errorf("got %+v", got)
	}
}

// Matching runs after redaction, so match cannot confirm a hidden value.
func TestLogTailMatchCannotProbeSecrets(t *testing.T) {
	for _, probe := range []string{"hunter2", "S3CR3T", "pS3"} {
		r := &errRunner{res: execx.Result{Stdout: authSample}}
		got, err := LogTail(context.Background(), r, "authlog", 10, probe)
		if err != nil {
			t.Fatal(err)
		}
		if got.Lines != 0 {
			t.Errorf("match %q found %d lines:\n%s", probe, got.Lines, got.Output)
		}
	}
}

func TestLogTailWebQueryRedacted(t *testing.T) {
	r := &errRunner{res: execx.Result{Stdout: `example.org 192.0.2.7 - - [27/Nov/2026:10:00:00 +0000] "GET /a?session=x HTTP/1.1" 200 1` + "\n"}}
	got, err := LogTail(context.Background(), r, "httpd_access", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got.Output, "session=x") || got.Redactions != 1 {
		t.Errorf("got %+v", got)
	}
}

func TestLogTailStripsControlCharacters(t *testing.T) {
	r := &errRunner{res: execx.Result{Stdout: "a\x1b[31mred\x07\tb\xffc\u2028d\n"}}
	got, err := LogTail(context.Background(), r, "messages", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Output != "a\uFFFD[31mred\uFFFD\tb\uFFFDc\uFFFDd" {
		t.Errorf("output %q", got.Output)
	}
}

func TestLogTailEmpty(t *testing.T) {
	got, err := LogTail(context.Background(), &errRunner{}, "cron", 0, "")
	if err != nil || got.Scanned != 0 || got.Lines != 0 || got.Output != "" {
		t.Errorf("got %+v, %v", got, err)
	}
}

func TestLogTailRejectsBadInputWithoutRunning(t *testing.T) {
	cases := []struct {
		name, match string
		lines       int
	}{
		{"../../etc/master.passwd", "", 0},
		{"/var/log/authlog", "", 0},
		{"authlog", "", -1},
		{"authlog", "", MaxLogLines + 1},
		{"authlog", strings.Repeat("a", MaxMatchLen+1), 0},
		{"authlog", "a\nb", 0},
		{"authlog", "\xff", 0},
	}
	for _, c := range cases {
		r := &errRunner{}
		if _, err := LogTail(context.Background(), r, c.name, c.lines, c.match); err == nil || len(r.calls) != 0 {
			t.Errorf("LogTail(%q, %d, %q): err=%v calls=%v", c.name, c.lines, c.match, err, r.calls)
		}
	}
}

func TestLogTailErrorHasHintUnlessTimeout(t *testing.T) {
	r := &errRunner{res: execx.Result{Stderr: "tail: /var/log/xferlog: No such file or directory\n"},
		err: nonZero(basecmd.LogXfer)}
	_, err := LogTail(context.Background(), r, "xferlog", 0, "")
	if err == nil || !strings.Contains(err.Error(), "No such file") || !strings.Contains(err.Error(), "hint") {
		t.Errorf("err = %v", err)
	}
	r = &errRunner{err: fmt.Errorf("%s: %w after 5s", basecmd.LogXfer, execx.ErrTimeout)}
	if _, err := LogTail(context.Background(), r, "xferlog", 0, ""); err == nil || strings.Contains(err.Error(), "hint") {
		t.Errorf("timeout err = %v", err)
	}
}

func TestLogsCoverEveryLogCommand(t *testing.T) {
	seen := map[basecmd.ID]bool{}
	for _, l := range Logs {
		if basecmd.FeatureOf(l.ID) != basecmd.FeatureLogs {
			t.Errorf("%s: %s is not a logs command", l.Name, l.ID)
		}
		seen[l.ID] = true
	}
	for _, id := range []basecmd.ID{basecmd.LogMessages, basecmd.LogDaemon, basecmd.LogAuth, basecmd.LogSecure,
		basecmd.LogMail, basecmd.LogXfer, basecmd.LogCron, basecmd.LogHTTPDAccess, basecmd.LogHTTPDError, basecmd.LogDaily, basecmd.LogSecurityOut} {
		if !seen[id] {
			t.Errorf("%s has no log_tail entry", id)
		}
	}
}
