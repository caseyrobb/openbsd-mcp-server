package execx

import (
	"context"
	"strings"
	"testing"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
)

func TestBoundedBuffer(t *testing.T) {
	cases := []struct {
		max    int
		writes []string
		want   string
		trunc  bool
	}{
		{max: 5, writes: []string{"abc"}, want: "abc"},
		{max: 5, writes: []string{"abcde"}, want: "abcde"},
		{max: 5, writes: []string{"abcdef"}, want: "abcde", trunc: true},
		{max: 5, writes: []string{"abc", "def", "ghi"}, want: "abcde", trunc: true},
		{max: 0, writes: []string{"x"}, want: "", trunc: true},
		{max: 3, writes: []string{"abc", ""}, want: "abc"},
	}
	for _, c := range cases {
		b := &BoundedBuffer{Max: c.max}
		for _, w := range c.writes {
			n, err := b.Write([]byte(w))
			if err != nil || n != len(w) {
				t.Fatalf("Write(%q) = %d, %v; want %d, nil", w, n, err, len(w))
			}
		}
		if b.String() != c.want || b.Truncated() != c.trunc {
			t.Errorf("max=%d writes=%q: got %q trunc=%v, want %q trunc=%v",
				c.max, c.writes, b.String(), b.Truncated(), c.want, c.trunc)
		}
	}
}

func TestRunRejectsUnregistered(t *testing.T) {
	_, err := Exec{}.Run(context.Background(), basecmd.ID("/bin/sh"))
	if err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("got %v, want allowlist rejection", err)
	}
}

func TestRunRejectsOptInNotEnabled(t *testing.T) {
	_, err := Exec{}.Run(context.Background(), basecmd.PfInfo)
	if err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("got %v, want opt-in rejection", err)
	}
}

func TestFixedEnvHasNoInheritedVars(t *testing.T) {
	for _, kv := range fixedEnv {
		k, _, _ := strings.Cut(kv, "=")
		if k != "PATH" && k != "LC_ALL" {
			t.Errorf("unexpected env var %q", k)
		}
	}
	if strings.Contains(fixedEnv[0], "/usr/local") {
		t.Error("PATH must not include /usr/local")
	}
}
