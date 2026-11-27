package redact

import (
	"strings"
	"testing"
)

func TestLine(t *testing.T) {
	cases := []struct {
		in, want string
		n        int
	}{
		// hostname.if(5)
		{"join homenet wpakey hunter2", "join homenet wpakey <redacted>", 1},
		{"nwid foo wpakey \"a b c\" up", "nwid foo wpakey \"<redacted>\" up", 1},
		{"nwkey 0x1234567890", "nwkey <redacted>", 1},
		{"wgkey kVd0Zr2pW5c8Mq2jQ0K0+aXyZw1PZ1cH2bD2y4ZJ6mE=", "wgkey <redacted>", 1},
		{"wgpeer PUBKEY= wgendpoint 192.0.2.1 51820 wgpsk SECRETPSK= wgaip 10.0.0.2/32",
			"wgpeer PUBKEY= wgendpoint 192.0.2.1 51820 wgpsk <redacted> wgaip 10.0.0.2/32", 1},
		// keyword forms
		{`neighbor 192.0.2.1 { tcp md5sig password "s3cr3t" }`, `neighbor 192.0.2.1 { tcp md5sig password "<redacted>" }`, 1},
		{"psk=abc123", "psk=<redacted>", 1},
		{"secret: topsecret", "secret: <redacted>", 1},
		{"auth-key mykey # comment", "auth-key <redacted> # comment", 1},
		// rc.conf.local style assignment
		{"foo_password=bar", "foo_password=<redacted>", 1},
		{"API_TOKEN='abc'", "API_TOKEN='<redacted>'", 1},
		{`x_secret="a" y_token=b`, `x_secret="<redacted>" y_token=<redacted>`, 2},
		// must NOT redact
		{"PasswordAuthentication no", "PasswordAuthentication no", 0},
		{"PermitEmptyPasswords no", "PermitEmptyPasswords no", 0},
		{"pass in on egress proto tcp to port ssh", "pass in on egress proto tcp to port ssh", 0},
		{"inet 192.0.2.10 255.255.255.0", "inet 192.0.2.10 255.255.255.0", 0},
		{"sshd_flags=", "sshd_flags=", 0},
		{"nopassword here", "nopassword here", 0},
		{"wpakey", "wpakey", 0},
		// idempotent
		{"wpakey <redacted>", "wpakey <redacted>", 0},
	}
	for _, c := range cases {
		got, n := Line(c.in)
		if got != c.want || n != c.n {
			t.Errorf("Line(%q) = %q, %d; want %q, %d", c.in, got, n, c.want, c.n)
		}
	}
}

func TestTextPrivateKeyBlock(t *testing.T) {
	in := strings.Join([]string{
		"before",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ",
		"-----END OPENSSH PRIVATE KEY-----",
		"after wpakey x",
	}, "\n")
	r := Text(in)
	if strings.Contains(r.Text, "b3BlbnNz") {
		t.Fatalf("key material leaked:\n%s", r.Text)
	}
	want := "before\n<redacted> (private key block)\nafter wpakey <redacted>"
	if r.Text != want || r.Count != 2 {
		t.Errorf("got %q (%d), want %q (2)", r.Text, r.Count, want)
	}
}

func TestTextUnterminatedKeyBlockRedactsToEnd(t *testing.T) {
	// Simulates a file truncated at the size cap mid-key.
	r := Text("ok\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nMIIEpA")
	if strings.Contains(r.Text, "MIIE") {
		t.Fatalf("key material leaked: %q", r.Text)
	}
}

func TestTextPublicMaterialKept(t *testing.T) {
	in := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
	if r := Text(in); r.Text != in || r.Count != 0 {
		t.Errorf("certificate should not be redacted: %q", r.Text)
	}
}

func TestAuthLine(t *testing.T) {
	cases := []struct{ in, want string }{
		{"sshd[1]: Invalid user hunter2 from 192.0.2.7 port 50000",
			"sshd[1]: Invalid user <redacted> from 192.0.2.7 port 50000"},
		{"sshd[1]: Failed password for invalid user admin from 192.0.2.7 port 22 ssh2",
			"sshd[1]: Failed password for invalid user <redacted> from 192.0.2.7 port 22 ssh2"},
		{"sshd[1]: Connection closed by invalid user s3cr3t pass 192.0.2.7 port 4 [preauth]",
			"sshd[1]: Connection closed by invalid user <redacted> 192.0.2.7 port 4 [preauth]"},
		{"sshd[1]: Disconnected from invalid user bob 2001:db8::1 port 22 [preauth]",
			"sshd[1]: Disconnected from invalid user <redacted> 2001:db8::1 port 22 [preauth]"},
		{"sshd[1]: input_userauth_request: invalid user x y [preauth]",
			"sshd[1]: input_userauth_request: invalid user <redacted> [preauth]"},
		// OpenBSD 8.0 sshd-session, as seen on a real host.
		{"testbsd sshd-session[20040]: Connection closed by invalid user jdoe 192.0.2.88 port 37760 [preauth]",
			"testbsd sshd-session[20040]: Connection closed by invalid user <redacted> 192.0.2.88 port 37760 [preauth]"},
		{"sshd[1]: Accepted publickey for jdoe from 192.0.2.7 port 22 ssh2",
			"sshd[1]: Accepted publickey for jdoe from 192.0.2.7 port 22 ssh2"},
		{"doas: jdoe ran command mysql -u root -pS3CR3T as root from /home/jdoe",
			"doas: jdoe ran command mysql <redacted> as root from /home/jdoe"},
		{"doas: obsdmcp ran command /sbin/pfctl -s rules as root from /",
			"doas: obsdmcp ran command /sbin/pfctl <redacted> as root from /"},
		{"doas: jdoe ran command ls as root from /tmp",
			"doas: jdoe ran command ls as root from /tmp"},
		{"doas: command not permitted for jdoe: cat /etc/master.passwd",
			"doas: command not permitted for jdoe: cat <redacted>"},
		{"doas: failed auth for jdoe", "doas: failed auth for jdoe"},
	}
	for _, c := range cases {
		got, _ := AuthLine(c.in)
		if got != c.want {
			t.Errorf("AuthLine(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
		// Idempotent: redacting twice changes nothing more.
		if again, n := AuthLine(got); again != got || n != 0 {
			t.Errorf("not idempotent: %q -> %q (%d)", got, again, n)
		}
	}
}

func TestURLQuery(t *testing.T) {
	in := `example.org 192.0.2.7 - - [27/Nov/2026:10:00:00 +0000] "GET /reset?token=abc&u=1 HTTP/1.1" 200 12`
	got, n := URLQuery(in)
	want := `example.org 192.0.2.7 - - [27/Nov/2026:10:00:00 +0000] "GET /reset?<redacted> HTTP/1.1" 200 12`
	if got != want || n != 1 {
		t.Errorf("got %q (%d)", got, n)
	}
	if got, n := URLQuery(`"GET /index.html HTTP/1.1" 200`); n != 0 || got != `"GET /index.html HTTP/1.1" 200` {
		t.Errorf("no query changed: %q", got)
	}
}

// Non-ASCII before the key must not shift offsets (strings.ToLower can
// change byte lengths, e.g. for U+0130).
func TestAuthLineNonASCII(t *testing.T) {
	in := "sshd[1]: \u0130\u0130\u0130 Invalid user p\u00e4ss from 192.0.2.7 port 1"
	got, n := AuthLine(in)
	want := "sshd[1]: \u0130\u0130\u0130 Invalid user <redacted> from 192.0.2.7 port 1"
	if got != want || n != 1 {
		t.Errorf("got %q (%d), want %q", got, n, want)
	}
}

func FuzzAuthLine(f *testing.F) {
	for _, s := range []string{"Invalid user x from y port 1", "a ran command b c as d from e",
		"command not permitted for u: x y", "invalid user ", "\u0130invalid user \u0130 port "} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, _ := AuthLine(s) // must not panic
		if again, n := AuthLine(got); n != 0 || again != got {
			t.Errorf("not idempotent: %q -> %q -> %q", s, got, again)
		}
	})
}

func TestLineKeepsSSHDPasswordProse(t *testing.T) {
	for _, l := range []string{
		"sshd[1]: Failed password for root from 192.0.2.9 port 22 ssh2",
		"sshd[1]: Accepted password for jdoe from 192.0.2.9 port 22 ssh2",
	} {
		if got, n := Line(l); got != l || n != 0 {
			t.Errorf("Line(%q) = %q (%d)", l, got, n)
		}
	}
	if got, _ := Line("password hunter2"); got != "password <redacted>" {
		t.Errorf("value still redacted: %q", got)
	}
}
