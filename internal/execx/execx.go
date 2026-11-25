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
	// DefaultConcurrency caps child processes running at once, so a
	// misbehaving client cannot fork-storm the host.
	DefaultConcurrency = 4
	// DefaultQueueWait is how long a call waits for a free slot.
	DefaultQueueWait = 2 * time.Second
)

// ErrBusy is returned when no command slot frees up within the queue wait.
var ErrBusy = errors.New("too many commands running; retry shortly")

// Limiter caps how many commands run at once. It is shared by every Run on
// the same Exec value, so it must be a pointer.
type Limiter struct {
	slots chan struct{}
	wait  time.Duration
}

// NewLimiter allows n concurrent commands; callers wait up to wait for a slot.
func NewLimiter(n int, wait time.Duration) *Limiter {
	if n < 1 {
		n = 1
	}
	return &Limiter{slots: make(chan struct{}, n), wait: wait}
}

func (l *Limiter) acquire(ctx context.Context) error {
	t := time.NewTimer(l.wait)
	defer t.Stop()
	select {
	case l.slots <- struct{}{}:
		return nil
	case <-t.C:
		return fmt.Errorf("%w (limit %d)", ErrBusy, cap(l.slots))
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *Limiter) release() { <-l.slots }

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
	// Enabled lists the opt-in features the operator allowed.
	Enabled basecmd.Enabled
	// Limit caps concurrent commands; nil means unlimited (tests only).
	Limit *Limiter
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
	if e.Limit != nil {
		if err := e.Limit.acquire(ctx); err != nil {
			return Result{}, fmt.Errorf("%s: %w", id, err)
		}
		defer e.Limit.release()
	}
	// The timeout starts once a slot is held: it bounds the command only.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd, stdout, stderr := newCmd(ctx, spec, max)
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

// newCmd builds the exec.Cmd for spec.
//
// Stdout and Stderr MUST be non-nil writers. When they are nil, os/exec opens
// /dev/null with O_WRONLY in this process before forking. Go calls open(2)
// directly, not libc's __pledge_open(), so the kernel's /dev/null exemption
// does not apply. The open needs "wpath", and pledge kills the server with
// SIGABRT ("pledge wpath, syscall 5"). Stdin stays nil: os/exec then opens
// /dev/null O_RDONLY, which "rpath" plus the unveil "r" rule allow.
//
// Dir MUST stay empty. A non-empty Dir makes the forked child chdir(2)
// before execve, while it still carries our unveil restrictions, and "/"
// is not unveiled, so this fails with ENOENT. Instead, sandbox.Apply
// chdirs the server to "/" before unveiling, and children inherit that cwd.
func newCmd(ctx context.Context, spec basecmd.Spec, max int) (*exec.Cmd, *BoundedBuffer, *BoundedBuffer) {
	prog, args := spec.Argv() // adds the "doas -n" wrapper for Doas specs
	cmd := exec.CommandContext(ctx, prog, args...)
	cmd.Env = fixedEnv
	cmd.Stdin = nil
	stdout := &BoundedBuffer{Max: max}
	stderr := &BoundedBuffer{Max: max}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = time.Second
	return cmd, stdout, stderr
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
