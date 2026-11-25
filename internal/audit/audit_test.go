package audit

import (
	"bytes"
	"strings"
	"testing"
)

func TestSanitize(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"rules", 64, `"rules"`},
		{"a\nb", 64, `"a\nb"`},
		{"x result=ok", 64, `"x result=ok"`},
		{"\x1b[31mred", 64, `"\x1b[31mred"`},
		{"\xff\xfe", 64, `"\ufffd\ufffd"`},
		{`quote " and backslash \`, 64, `"quote \" and backslash \\"`},
		{strings.Repeat("a", 10), 4, `"aaaa\u2026"`},
		{"a\u2028b", 64, `"a\u2028b"`},
	}
	for _, c := range cases {
		if got := Sanitize(c.in, c.max); got != c.want {
			t.Errorf("Sanitize(%q, %d) = %s, want %s", c.in, c.max, got, c.want)
		}
	}
}

func TestSanitizeNeverEmitsNewline(t *testing.T) {
	for _, s := range []string{"\n", "\r\n", "a b", "\x00", strings.Repeat("\n", 500)} {
		if got := Sanitize(s, 64); strings.ContainsAny(got, "\n\r\x00") {
			t.Errorf("Sanitize(%q) = %q contains a raw control character", s, got)
		}
	}
}

func TestSyslogLine(t *testing.T) {
	got := string(syslogLine(Info, "obsd-mcp", 42, "tool=x result=ok"))
	if got != "<30>obsd-mcp[42]: tool=x result=ok" {
		t.Fatalf("got %q", got)
	}
}

func TestWriter(t *testing.T) {
	var b bytes.Buffer
	(&Writer{W: &b}).Log(Info, "hello")
	if b.String() != "obsd-mcp audit: hello\n" {
		t.Fatalf("got %q", b.String())
	}
}
