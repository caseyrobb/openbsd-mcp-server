//go:build openbsd

package sandbox

import (
	"errors"
	"fmt"
	"io/fs"

	"golang.org/x/sys/unix"
)

// Apply unveils every rule, locks unveil, then pledges. It must be called
// after all initialisation and before the first MCP request is read. Any
// failure is fatal to the caller: we never continue unsandboxed.
//
// The working directory is set to "/" first; see execx.newCmd.
//
// A missing file (ENOENT) is skipped rather than fatal, so an absent optional
// config like /etc/rc.conf.local does not stop startup; it stays invisible.
func Apply(p Policy) (skipped []string, err error) {
	// Move to "/" while it is still visible. Children inherit this cwd, so
	// execx never asks a forked (still-unveiled) child to chdir.
	if err := unix.Chdir("/"); err != nil {
		return nil, fmt.Errorf("chdir(\"/\"): %w", err)
	}
	for _, r := range p.Unveil {
		if err := unix.Unveil(r.Path, r.Perms); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				skipped = append(skipped, r.Path)
				continue
			}
			return skipped, fmt.Errorf("unveil(%q, %q): %w", r.Path, r.Perms, err)
		}
	}
	if err := unix.UnveilBlock(); err != nil {
		return skipped, fmt.Errorf("unveil(NULL, NULL): %w", err)
	}
	// execpromises is left unset (NULL): children are fixed-argv base
	// binaries that pledge themselves. See docs/ARCHITECTURE.md.
	if err := unix.PledgePromises(p.Promises); err != nil {
		return skipped, fmt.Errorf("pledge(%q): %w", p.Promises, err)
	}
	return skipped, nil
}
