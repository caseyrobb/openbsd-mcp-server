package collect

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
	"github.com/caseyrobb/openbsd-mcp-server/internal/execx"
	"github.com/caseyrobb/openbsd-mcp-server/internal/redact"
)

// ConfigChecks maps a daemon name to its configtest command. Each runs the
// daemon's documented check-only mode via doas; nothing is loaded.
var ConfigChecks = Subsystem{
	Name: "config", Feature: basecmd.FeatureConfCheck,
	Views: []View{
		{"pf", basecmd.CheckPF, "pfctl -n -f /etc/pf.conf: parse the ruleset without loading it"},
		{"bgpd", basecmd.CheckBGPD, "bgpd -n: /etc/bgpd.conf"},
		{"httpd", basecmd.CheckHTTPD, "httpd -n: /etc/httpd.conf"},
		{"relayd", basecmd.CheckRelayd, "relayd -n: /etc/relayd.conf"},
		{"smtpd", basecmd.CheckSMTPD, "smtpd -n: /etc/mail/smtpd.conf"},
		{"iked", basecmd.CheckIKED, "iked -n: /etc/iked.conf"},
		{"ntpd", basecmd.CheckNTPD, "ntpd -n: /etc/ntpd.conf"},
		{"ospfd", basecmd.CheckOSPFD, "ospfd -n: /etc/ospfd.conf"},
		{"ospf6d", basecmd.CheckOSPF6D, "ospf6d -n: /etc/ospf6d.conf"},
		{"dhcpd", basecmd.CheckDHCPD, "dhcpd -n: /etc/dhcpd.conf"},
		{"unwind", basecmd.CheckUnwind, "unwind -n: /etc/unwind.conf"},
		{"vmd", basecmd.CheckVMD, "vmd -n: /etc/vm.conf"},
		{"snmpd", basecmd.CheckSNMPD, "snmpd -n: /etc/snmpd.conf"},
		{"sshd", basecmd.CheckSSHD, "sshd -t: /etc/ssh/sshd_config and host keys"},
		{"unbound", basecmd.CheckUnbound, "unbound-checkconf: /var/unbound/etc/unbound.conf"},
	},
	Hint: "configtests run via 'doas -n'; check /etc/doas.conf against: obsd-mcp -enable confcheck -print-doas <user>",
}

// ConfigCheckResult is the output of config_check. An invalid or missing
// config is a normal result (Valid false), not a tool error.
type ConfigCheckResult struct {
	Daemon  string `json:"daemon"`
	Command string `json:"command" jsonschema:"the exact fixed command line that was run"`
	Valid   bool   `json:"valid" jsonschema:"true if the configtest exited 0"`
	Output  string `json:"output" jsonschema:"combined stdout and stderr, secret values replaced by <redacted>"`
	// Truncated and Redactions are as in StatusResult.
	Truncated  bool `json:"truncated,omitempty"`
	Redactions int  `json:"redactions,omitempty"`
}

// ConfigCheck runs one daemon's configtest. It errors only when the check
// could not run: unknown daemon, exec failure, timeout or a doas refusal.
func ConfigCheck(ctx context.Context, r execx.Runner, daemon string) (ConfigCheckResult, error) {
	s := ConfigChecks
	var v *View
	for i := range s.Views {
		if s.Views[i].Name == daemon {
			v = &s.Views[i]
		}
	}
	if v == nil {
		return ConfigCheckResult{}, fmt.Errorf("%w %q for config_check (valid: %s)", ErrUnknownView, daemon,
			strings.Join(s.ViewNames(), ", "))
	}

	res, err := r.Run(ctx, v.ID)
	if cerr := ctx.Err(); cerr != nil {
		return ConfigCheckResult{}, cerr
	}
	stderr := strings.TrimSpace(res.Stderr)
	if err != nil && (!errors.Is(err, execx.ErrNonZeroExit) || strings.HasPrefix(stderr, "doas:")) {
		msg := err.Error()
		if stderr != "" {
			l, _ := redact.Line(firstLine(stderr))
			msg += ": " + l
		}
		return ConfigCheckResult{}, fmt.Errorf("%s (hint: %s)", msg, s.Hint)
	}

	combined := strings.TrimSpace(strings.TrimSpace(res.Stdout) + "\n" + stderr)
	red := redact.Text(combined)
	return ConfigCheckResult{
		Daemon:     v.Name,
		Command:    basecmd.Describe(v.ID),
		Valid:      err == nil,
		Output:     red.Text,
		Truncated:  res.Truncated,
		Redactions: red.Count,
	}, nil
}
