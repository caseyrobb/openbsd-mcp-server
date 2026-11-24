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
