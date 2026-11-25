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
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
	"github.com/caseyrobb/openbsd-mcp-server/internal/confread"
	"github.com/caseyrobb/openbsd-mcp-server/internal/execx"
	"github.com/caseyrobb/openbsd-mcp-server/internal/mcpserver"
	"github.com/caseyrobb/openbsd-mcp-server/internal/sandbox"
)

func main() {
	printPolicy := flag.Bool("print-policy", false, "print the unveil/pledge policy and exit")
	unsafeDev := flag.Bool("unsafe-dev", false, "allow running without pledge/unveil on non-OpenBSD (development only)")
	enable := flag.String("enable", "", "comma-separated opt-in features: pf, unbound, bgp")
	printDoas := flag.String("print-doas", "", "print the doas.conf rules USER needs for -enable, then exit")
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

	// Build everything that might need extra privileges *before* sandboxing.
	server := mcpserver.New(mcpserver.Config{
		Runner:   execx.Exec{Enabled: enabled},
		Features: enabled,
		Conf:     conf,
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}
