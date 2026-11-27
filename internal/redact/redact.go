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
			// Log prose, not a value: sshd "Failed password for root".
			if strings.EqualFold(sub[4], "for") {
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

// AuthLine redacts what auth logs record from untrusted or private input:
//
//   - sshd "invalid user NAME": NAME is whatever the client sent, and people
//     regularly type a password into the user prompt.
//   - doas "ran command CMD ARGS as" and "command not permitted for U: CMD
//     ARGS": arguments can carry passwords or tokens. The program is kept.
//
// It returns the line and the number of values replaced.
func AuthLine(line string) (string, int) {
	n := 0
	line, k := redactInvalidUsers(line)
	n += k
	if i := strings.Index(line, " ran command "); i >= 0 {
		start := i + len(" ran command ")
		end := strings.LastIndex(line, " as ")
		if f := strings.LastIndex(line, " from "); f > start && (end < start || end > f) {
			end = -1
			if a := strings.LastIndex(line[:f], " as "); a > start {
				end = a
			}
		}
		if end > start {
			var r bool
			line, r = keepProgram(line, start, end)
			if r {
				n++
			}
		}
	} else if i := strings.Index(line, "command not permitted for "); i >= 0 {
		if c := strings.Index(line[i:], ": "); c >= 0 {
			var r bool
			line, r = keepProgram(line, i+c+2, len(line))
			if r {
				n++
			}
		}
	}
	return line, n
}

// keepProgram replaces the arguments in line[start:end] (a command line)
// with Marker, keeping the first word, the program.
func keepProgram(line string, start, end int) (string, bool) {
	cmd := line[start:end]
	sp := strings.IndexByte(cmd, ' ')
	if sp < 0 || strings.TrimSpace(cmd[sp:]) == "" || strings.TrimSpace(cmd[sp:]) == Marker {
		return line, false
	}
	return line[:start] + cmd[:sp] + " " + Marker + line[end:], true
}

// redactInvalidUsers replaces the client-supplied name after each
// "invalid user " (any case). The name ends before " from ", before the
// address in "<addr> port", or before " [preauth]"; otherwise at end of line.
func redactInvalidUsers(line string) (string, int) {
	const key = "invalid user "
	n := 0
	for pos := 0; ; {
		// ASCII-only lowering keeps byte offsets aligned with line.
		i := strings.Index(asciiLower(line[pos:]), key)
		if i < 0 {
			return line, n
		}
		start := pos + i + len(key)
		rest := line[start:]
		end := len(rest)
		if j := strings.Index(rest, " from "); j >= 0 && j < end {
			end = j
		}
		if j := strings.Index(rest, " port "); j >= 0 && j < end {
			// "invalid user NAME 192.0.2.1 port 22": drop the address too.
			if k := strings.LastIndexByte(rest[:j], ' '); k >= 0 {
				end = k
			} else {
				end = 0
			}
		}
		if j := strings.Index(rest, " [preauth]"); j >= 0 && j < end {
			end = j
		}
		if end == 0 || rest[:end] == Marker {
			pos = start
			continue
		}
		line = line[:start] + Marker + rest[end:]
		n++
		pos = start + len(Marker)
	}
}

// urlQuery matches the query string of a request target in a web log.
var urlQuery = regexp.MustCompile(`(\s"?(?:GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS|CONNECT|TRACE)\s+[^\s?"]*)\?[^\s"]*`)

// URLQuery replaces query strings in web server log request lines, which
// often carry session tokens, API keys or reset codes.
func URLQuery(line string) (string, int) {
	n := 0
	line = urlQuery.ReplaceAllStringFunc(line, func(m string) string {
		n++
		return urlQuery.FindStringSubmatch(m)[1] + "?" + Marker
	})
	return line, n
}

// asciiLower lowercases A-Z only, so the result has the same byte length
// (and offsets) as s, unlike strings.ToLower on non-ASCII input.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
