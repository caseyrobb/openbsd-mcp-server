// Package execx runs allowlisted base-system commands with no shell, a
// scrubbed environment, a hard timeout and a bounded output buffer.
package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/caseyrobb/openbsd-mcp-server/internal/basecmd"
)

const (
	DefaultTimeout   = 5 * time.Second
	DefaultMaxOutput = 256 << 10 // 256 KiB per stream
)

// Result is the outcome of one command run.
type Result struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Truncated bool
}

// Runner executes a registered command by ID. Collectors depend on this
// interface so they can be tested with fakes on any OS.
type Runner interface {
	Run(ctx context.Context, id basecmd.ID) (Result, error)
}

// Exec is the real Runner.
type Exec struct {
	Timeout   time.Duration
	MaxOutput int
	// Enabled lists the opt-in commands (e.g. pf_info) the operator allowed.
	Enabled basecmd.Enabled
}

// fixedEnv is the entire environment children see. No inherited variables.
var fixedEnv = []string{"PATH=/bin:/sbin:/usr/bin:/usr/sbin", "LC_ALL=C"}

// ErrNonZeroExit is wrapped when the command exits non-zero.
var ErrNonZeroExit = errors.New("non-zero exit")

func (e Exec) Run(ctx context.Context, id basecmd.ID) (Result, error) {
	spec, err := basecmd.Lookup(id, e.Enabled)
	if err != nil {
		return Result{}, err
	}
	timeout, max := e.Timeout, e.MaxOutput
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if max <= 0 {
		max = DefaultMaxOutput
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, spec.Path, spec.Args...)
	cmd.Env = fixedEnv
	cmd.Dir = "/"
	cmd.Stdin = nil // os/exec opens /dev/null read-only; unveiled "r"
	stdout := &BoundedBuffer{Max: max}
	stderr := &BoundedBuffer{Max: max}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = time.Second

	runErr := cmd.Run()
	res := Result{
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		Truncated: stdout.Truncated() || stderr.Truncated(),
	}
	if ctx.Err() == context.DeadlineExceeded {
		return res, fmt.Errorf("%s: timed out after %s", id, timeout)
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, fmt.Errorf("%s: %w (status %d)", id, ErrNonZeroExit, res.ExitCode)
	}
	if runErr != nil {
		return res, fmt.Errorf("%s: %w", id, runErr)
	}
	return res, nil
}

// BoundedBuffer keeps at most Max bytes and silently discards the rest,
// recording that truncation happened. It never returns a write error, so a
// chatty child is not killed by SIGPIPE mid-write.
type BoundedBuffer struct {
	Max       int
	buf       bytes.Buffer
	truncated bool
}

func (b *BoundedBuffer) Write(p []byte) (int, error) {
	room := b.Max - b.buf.Len()
	if room <= 0 {
		if len(p) > 0 {
			b.truncated = true
		}
		return len(p), nil
	}
	if len(p) > room {
		b.buf.Write(p[:room])
		b.truncated = true
		return len(p), nil
	}
	b.buf.Write(p)
	return len(p), nil
}

func (b *BoundedBuffer) String() string  { return b.buf.String() }
func (b *BoundedBuffer) Truncated() bool { return b.truncated }
