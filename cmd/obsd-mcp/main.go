// Command obsd-mcp is a read-only MCP server for the OpenBSD base system.
// It speaks MCP over stdio only; remote access is via ssh(1) forced command.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/caseyrobb/openbsd-mcp-server/internal/audit"
	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
	"github.com/caseyrobb/openbsd-mcp-server/internal/confread"
	"github.com/caseyrobb/openbsd-mcp-server/internal/deploy"
	"github.com/caseyrobb/openbsd-mcp-server/internal/execx"
	"github.com/caseyrobb/openbsd-mcp-server/internal/mcpserver"
	"github.com/caseyrobb/openbsd-mcp-server/internal/sandbox"
)

func main() {
	printPolicy := flag.Bool("print-policy", false, "print the unveil/pledge policy and exit")
	unsafeDev := flag.Bool("unsafe-dev", false, "allow running without pledge/unveil on non-OpenBSD (development only)")
	enable := flag.String("enable", "", "comma-separated opt-in features: pf, unbound, bgp, ntp, services, confcheck")
	printDoas := flag.String("print-doas", "", "print the doas.conf rules USER needs for -enable, then exit")
	printSSHD := flag.String("print-sshd", "", "print an sshd_config Match block that pins USER to this server with -enable, then exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(mcpserver.Name, mcpserver.Version)
		return
	}

	// MCP owns stdout; all diagnostics go to stderr.
	log.SetOutput(os.Stderr)
	log.SetFlags(0)
	log.SetPrefix("obsd-mcp: ")

	if os.Geteuid() == 0 {
		log.Fatal("refusing to run as root; use a dedicated unprivileged user")
	}
	if err := basecmd.Validate(); err != nil {
		log.Fatal(err)
	}

	enabled, err := basecmd.ParseFeatures(*enable)
	if err != nil {
		log.Fatalf("-enable: %v", err)
	}
	if *printDoas != "" {
		rules, err := basecmd.DoasRules(*printDoas, enabled)
		if err != nil {
			log.Fatalf("-print-doas: %v", err)
		}
		if len(rules) == 0 {
			fmt.Println("# no doas rules needed for the enabled features")
		}
		for _, r := range rules {
			fmt.Println(r)
		}
		return
	}
	if *printSSHD != "" {
		bin := serverPath()
		block, err := deploy.SSHDConfig(*printSSHD, bin, enabled)
		if err != nil {
			log.Fatalf("-print-sshd: %v", err)
		}
		if w := ownerWarning(bin); w != "" {
			log.Printf("-print-sshd: WARNING: %s", w)
		}
		fmt.Print(block)
		return
	}

	// Expands /etc/hostname.* now, while /etc is still listable.
	conf, err := confread.New()
	if err != nil {
		log.Fatal(err)
	}
	for _, x := range conf.Excluded() {
		log.Printf("config_read: excluded %s", x)
	}

	policy, err := sandbox.NewPolicy(basecmd.Binaries(enabled), conf.Paths())
	if err != nil {
		log.Fatal(err)
	}
	if *printPolicy {
		fmt.Print(policy.String())
		return
	}

	auditLog, err := audit.NewSyslog("obsd-mcp")
	if err != nil {
		// Not OpenBSD amd64/arm64 (e.g. -unsafe-dev on Linux): stderr.
		auditLog = &audit.Writer{W: os.Stderr}
	}

	// Build everything that might need extra privileges *before* sandboxing.
	server := mcpserver.New(mcpserver.Config{
		Runner: execx.Exec{
			Enabled: enabled,
			Limit:   execx.NewLimiter(execx.DefaultConcurrency, execx.DefaultQueueWait),
		},
		Features: enabled,
		Conf:     conf,
		Audit:    auditLog,
	})

	skipped, err := sandbox.Apply(policy)
	switch {
	case errors.Is(err, sandbox.ErrUnsupported) && *unsafeDev:
		log.Print("WARNING: running WITHOUT pledge/unveil (-unsafe-dev)")
	case err != nil:
		log.Fatalf("sandbox: %v", err)
	}
	for _, p := range skipped {
		log.Printf("unveil: %s not present, skipped", p)
	}

	start := time.Now()
	auditLog.Log(audit.Info, fmt.Sprintf("event=session_start version=%s uid=%d features=%s ssh_client=%s",
		audit.Sanitize(mcpserver.Version, 64), os.Getuid(), audit.Sanitize(strings.Join(enabled.List(), ","), 128),
		audit.Sanitize(sshClient(), 64)))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	runErr := server.Run(ctx, &mcp.StdioTransport{})
	auditLog.Log(audit.Info, fmt.Sprintf("event=session_end seconds=%d", int(time.Since(start).Seconds())))
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		log.Fatal(runErr)
	}
}

// sshClient is the client address and port from SSH_CLIENT, set by sshd for
// forced commands ("addr port localport"); empty for a local session.
func sshClient() string {
	f := strings.Fields(os.Getenv("SSH_CLIENT"))
	if len(f) >= 2 {
		return f[0] + " " + f[1]
	}
	return ""
}

// ownerWarning flags a server binary that someone other than root could
// replace: whoever can write it controls what the forced command runs.
func ownerWarning(bin string) string {
	fi, err := os.Stat(bin)
	if err != nil {
		return fmt.Sprintf("%s: %v (install the server there before reloading sshd)", bin, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if ok && st.Uid != 0 {
		return fmt.Sprintf("%s is not owned by root; install it root-owned, e.g. %s", bin, deploy.PackagePath)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Sprintf("%s is group- or world-writable", bin)
	}
	return ""
}

// serverPath is this binary's absolute path for -print-sshd, falling back to
// the package location when it cannot be determined (OpenBSD derives it
// from argv[0], which is relative when run through $PATH).
func serverPath() string {
	p, err := os.Executable()
	if err == nil {
		p, err = filepath.EvalSymlinks(p)
	}
	if err == nil {
		var fi os.FileInfo
		if fi, err = os.Stat(p); err == nil && fi.Mode().IsRegular() && filepath.IsAbs(p) {
			return p
		}
	}
	return deploy.PackagePath
}
