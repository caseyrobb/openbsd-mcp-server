package deploy

import (
	"strings"
	"testing"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
)

func TestCommand(t *testing.T) {
	en, err := basecmd.ParseFeatures("services,pf")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		bin  string
		en   basecmd.Enabled
		want string
	}{
		{PackagePath, nil, PackagePath},
		{PackagePath, en, PackagePath + " -enable pf,services"}, // canonical order
		{"/home/mcp/bin/obsd-mcp", basecmd.Enabled{}, "/home/mcp/bin/obsd-mcp"},
	} {
		got, err := Command(c.bin, c.en)
		if err != nil || got != c.want {
			t.Errorf("Command(%q) = %q, %v; want %q", c.bin, got, err, c.want)
		}
	}
}

// Anything that could break out of a quoted command="..." or be expanded by
// $SHELL -c is rejected.
func TestCommandRejectsUnsafePaths(t *testing.T) {
	for _, bin := range []string{
		"", "obsd-mcp", "./obsd-mcp", "/usr/local/../bin/sh", "/usr/local/libexec/",
		"/tmp/a b", `/tmp/a"b`, "/tmp/a;sh", "/tmp/$(id)", "/tmp/`id`", "/tmp/a\nb",
		"/tmp/a'b", "/tmp/a*", "/tmp/~x",
	} {
		if got, err := Command(bin, nil); err == nil {
			t.Errorf("Command(%q) = %q, want error", bin, got)
		}
	}
}

func TestSSHDConfig(t *testing.T) {
	en, _ := basecmd.ParseFeatures("pf,confcheck")
	got, err := SSHDConfig("obsdmcp", PackagePath, en)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"\nMatch User obsdmcp\n",
		"\n\tForceCommand /usr/local/libexec/obsd-mcp -enable pf,confcheck\n",
		"\n\tAuthenticationMethods publickey\n",
		"\n\tDisableForwarding yes\n",
		"\n\tPermitTTY no\n",
		"\n\tPermitTunnel no\n",
		"\n\tPermitUserRC no\n",
		`restrict,command="/usr/local/libexec/obsd-mcp -enable pf,confcheck"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if !strings.HasSuffix(got, "\nMatch all\n") {
		t.Errorf("block must end with Match all:\n%s", got)
	}
	// Every non-comment line is a Match or an indented keyword inside one.
	for _, l := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if !strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "Match ") && !strings.HasPrefix(l, "\t") {
			t.Errorf("unexpected line %q", l)
		}
	}
}

func TestSSHDConfigRejectsBadInput(t *testing.T) {
	for _, user := range []string{"", "root user", "Bad", "a\nMatch all", "x;y", strings.Repeat("a", 33)} {
		if _, err := SSHDConfig(user, PackagePath, nil); err == nil {
			t.Errorf("user %q accepted", user)
		}
	}
	if _, err := SSHDConfig("obsdmcp", "/tmp/x y", nil); err == nil {
		t.Error("unsafe path accepted")
	}
}
