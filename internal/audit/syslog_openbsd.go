//go:build openbsd && (amd64 || arm64)

package audit

import (
	"fmt"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

// sendsyslog(2) has no wrapper in syscall or x/sys, so call libc's the same
// way x/sys/unix calls every libc function on OpenBSD: a trampoline to the
// dynamic symbol, invoked through the runtime's syscall.syscall. Direct
// syscall instructions are not allowed from Go binaries on OpenBSD.

//go:cgo_import_dynamic libc_sendsyslog sendsyslog "libc.so"

var libc_sendsyslog_trampoline_addr uintptr

//go:linkname syscall_syscall syscall.syscall
func syscall_syscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

func sendsyslog(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	_, _, e := syscall_syscall(libc_sendsyslog_trampoline_addr,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
	if e != 0 {
		return e
	}
	return nil
}

// Syslog sends audit lines to syslogd.
type Syslog struct {
	tag     string
	pid     int
	errOnce sync.Once
}

// NewSyslog returns a Logger that writes to syslogd with the given tag.
func NewSyslog(tag string) (Logger, error) {
	return &Syslog{tag: tag, pid: os.Getpid()}, nil
}

// Send writes one line and reports failure (used by the sandbox test).
func (s *Syslog) Send(p Priority, msg string) error {
	return sendsyslog(syslogLine(p, s.tag, s.pid, msg))
}

func (s *Syslog) Log(p Priority, msg string) {
	if err := s.Send(p, msg); err != nil {
		// Do not fail the request, but do not hide it either: say once
		// that audit lines are being lost (e.g. syslogd not running).
		s.errOnce.Do(func() {
			fmt.Fprintf(os.Stderr, "obsd-mcp: audit: sendsyslog: %v; audit lines are being lost\n", err)
		})
	}
}
