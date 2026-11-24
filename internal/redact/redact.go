// Package redact removes secret values from base-system config and command
// output. It keeps the keyword and replaces only the value, so the agent can
// still see that (for example) a wpakey is configured.
//
// Redaction is a second line of defence. The first is the file allowlist,
// which keeps known secret stores (master.passwd, iked.conf, ipsec.conf,
// private keys) from being read at all.
package redact

import (
	"regexp"
	"strings"
)

// Marker replaces every redacted value.
const Marker = "<redacted>"

// keywordValue matches a whole-word secret keyword followed by its value, as
// used in OpenBSD configs:
//
//	hostname.if:  wpakey hunter2 | nwkey 0x1234 | wgkey AAA= | wgpeer ... wgpsk BBB=
//	pf/bgpd/etc:  password "x" | secret x | psk "x" | auth-key x
//
// The keyword must be a whole token, so "PasswordAuthentication no" in
// sshd_config is left alone.
var keywordValue = regexp.MustCompile(
	`(?i)(^|[\s"'{(,;])` +
		`(wpakey|nwkey|wgkey|wgpsk|psk|password|passwd|secret|auth-key|authkey|auth-md5|private-key|privkey)` +
		`(\s*[=:]\s*|\s+)` +
		`("[^"]*"|'[^']*'|[^\s"'#;,)}]+)`)

// assignment matches NAME=value where NAME contains a secret-ish word, e.g.
// rc.conf.local style "foo_password=bar" or "API_TOKEN='x'".
var assignment = regexp.MustCompile(
	`(?i)(^|[\s;])` +
		`([A-Za-z0-9_.-]*(?:password|passwd|secret|token|apikey|api_key|psk)[A-Za-z0-9_.-]*)` +
		`(=)` +
		`("[^"]*"|'[^']*'|[^\s"';#]+)`)

// Result is redacted text plus how many values were removed.
type Result struct {
	Text  string
	Count int
}

// Text redacts s line by line. PEM private key blocks are collapsed to a
// single marker line; an unterminated block is redacted to end of input.
func Text(s string) Result {
	var out []string
	count := 0
	inKey := false
	for _, line := range strings.Split(s, "\n") {
		if inKey {
			if strings.Contains(line, "-----END") {
				inKey = false
			}
			continue
		}
		if strings.Contains(line, "-----BEGIN") && strings.Contains(line, "PRIVATE KEY") {
			out = append(out, Marker+" (private key block)")
			count++
			inKey = !strings.Contains(line, "-----END")
			continue
		}
		var n int
		line, n = Line(line)
		count += n
		out = append(out, line)
	}
	return Result{Text: strings.Join(out, "\n"), Count: count}
}

// Line redacts a single line and returns the number of values replaced.
func Line(line string) (string, int) {
	n := 0
	repl := func(re *regexp.Regexp) func(string) string {
		return func(m string) string {
			sub := re.FindStringSubmatch(m)
			if sub[4] == Marker || sub[4] == `"`+Marker+`"` {
				return m
			}
			n++
			v := Marker
			if strings.HasPrefix(sub[4], `"`) {
				v = `"` + Marker + `"`
			} else if strings.HasPrefix(sub[4], `'`) {
				v = `'` + Marker + `'`
			}
			return sub[1] + sub[2] + sub[3] + v
		}
	}
	line = keywordValue.ReplaceAllStringFunc(line, repl(keywordValue))
	line = assignment.ReplaceAllStringFunc(line, repl(assignment))
	return line, n
}
