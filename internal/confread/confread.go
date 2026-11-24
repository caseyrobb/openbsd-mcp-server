// Package confread reads allowlisted OpenBSD base-system config files.
//
// Every request goes through the same pipeline:
//
//  1. validate: reject (never normalise) NUL/control chars, relative paths,
//     "." or ".." components, and anything where path.Clean(p) != p
//  2. deny: known secret stores and package paths are refused even if they
//     were accidentally allowlisted
//  3. allow: exact match against the startup-computed allowlist
//  4. resolve: realpath must equal the requested path (no symlinked ancestors)
//  5. lstat: regular file, not a symlink, owned by root
//  6. open O_RDONLY|O_NOFOLLOW|O_NONBLOCK, fstat, and require the same inode as
//     step 5 (closes the swap race)
//  7. read at most MaxSize bytes, refuse binary content, redact secrets
//
// On OpenBSD the sandbox also unveils exactly Paths() with "r", so a bug in
// this package still cannot reach a file outside the allowlist.
package confread

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/caseyrobb/openbsd-mcp-server/internal/redact"
)

// MaxSize is the largest number of bytes returned for one file.
const MaxSize = 64 << 10

// Fixed is the static allowlist. All entries are base-system files.
var Fixed = []string{
	"/etc/fstab",
	"/etc/hosts",
	"/etc/httpd.conf",
	"/etc/mygate",
	"/etc/myname",
	"/etc/ntpd.conf",
	"/etc/pf.conf",
	"/etc/rc.conf.local",
	"/etc/resolv.conf",
	"/etc/ssh/sshd_config",
	"/etc/sysctl.conf",
	"/etc/syslog.conf",
}

// hostnameIf matches hostname.if(5) names such as hostname.em0, hostname.vlan10.
var hostnameIf = regexp.MustCompile(`^hostname\.[a-z]+[0-9]+$`)

// Errors returned by Read. They are safe to show to the client.
var (
	ErrInvalidPath = errors.New("invalid path")
	ErrDenied      = errors.New("path is denylisted")
	ErrNotAllowed  = errors.New("path is not in the config allowlist")
	ErrNotPresent  = errors.New("file is not present on this system")
	ErrNotRegular  = errors.New("not a regular file")
	ErrSymlink     = errors.New("symlinks are not followed")
	ErrOwner       = errors.New("file is not owned by root")
	ErrChanged     = errors.New("file changed while being opened")
	ErrBinary      = errors.New("file does not look like text")
	ErrPermission  = errors.New("permission denied")
)

// File is the result of reading one config file.
type File struct {
	Path       string `json:"path"`
	Mode       string `json:"mode" jsonschema:"octal permission bits"`
	Size       int64  `json:"size"`
	Content    string `json:"content" jsonschema:"file contents with secret values replaced by <redacted>"`
	Truncated  bool   `json:"truncated,omitempty"`
	Redactions int    `json:"redactions,omitempty"`
}

// Reader holds the allowlist. Create it before the sandbox is applied (the
// hostname.* glob needs to list /etc).
type Reader struct {
	root    string // "" in production; a temp dir in tests
	allowed map[string]bool
	owner   int // required uid; production is 0
	max     int64
}

// New returns the production reader: the Fixed allowlist plus every
// /etc/hostname.if present at startup, root-owned files only.
func New() (*Reader, error) { return newReader("", 0, MaxSize) }

func newReader(root string, owner int, max int64) (*Reader, error) {
	r := &Reader{root: root, allowed: map[string]bool{}, owner: owner, max: max}
	for _, p := range Fixed {
		r.allowed[p] = true
	}
	matches, err := filepath.Glob(filepath.Join(root, "/etc/hostname.*"))
	if err != nil {
		return nil, err
	}
	for _, m := range matches {
		if b := filepath.Base(m); hostnameIf.MatchString(b) {
			r.allowed["/etc/"+b] = true
		}
	}
	for p := range r.allowed {
		if err := validate(p); err != nil {
			return nil, fmt.Errorf("confread: allowlist entry %q: %w", p, err)
		}
		if denied(p) {
			return nil, fmt.Errorf("confread: allowlist entry %q is denylisted", p)
		}
	}
	return r, nil
}

// Paths returns the sorted allowlist. The sandbox unveils each with "r".
func (r *Reader) Paths() []string {
	out := make([]string, 0, len(r.allowed))
	for p := range r.allowed {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func validate(p string) error {
	if p == "" || len(p) > 256 {
		return fmt.Errorf("%w: empty or too long", ErrInvalidPath)
	}
	for _, c := range p {
		if c < 0x20 || c == 0x7f || c == utf8.RuneError {
			return fmt.Errorf("%w: control or invalid character", ErrInvalidPath)
		}
	}
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("%w: must be absolute", ErrInvalidPath)
	}
	for _, c := range strings.Split(p[1:], "/") {
		if c == ".." || c == "." {
			return fmt.Errorf("%w: %q components are not allowed", ErrInvalidPath, c)
		}
	}
	if path.Clean(p) != p {
		return fmt.Errorf("%w: not in canonical form", ErrInvalidPath)
	}
	return nil
}

var (
	denyPrefixes = []string{
		"/usr/local/", "/etc/pkg/", "/var/db/pkg/", "/etc/ssl/private/",
		"/etc/iked/", "/etc/isakmpd/", "/root/", "/home/",
	}
	denyNames = []string{
		"master.passwd", "spwd.db", "pwd.db", "doas.conf", "iked.conf", "ipsec.conf",
		"authorized_keys", ".env", "skeykeys",
	}
	denyGlobs = []string{"ssh_host_*", "*.key", "*.pem", "id_*", "*.secret", "*.db"}
)

func denied(p string) bool {
	for _, d := range denyPrefixes {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	b := path.Base(p)
	for _, n := range denyNames {
		if b == n {
			return true
		}
	}
	for _, g := range denyGlobs {
		if ok, _ := path.Match(g, b); ok {
			return true
		}
	}
	return false
}

// Read returns the redacted contents of an allowlisted file.
func (r *Reader) Read(p string) (File, error) {
	if err := validate(p); err != nil {
		return File{}, err
	}
	if denied(p) {
		return File{}, ErrDenied
	}
	if !r.allowed[p] {
		return File{}, ErrNotAllowed
	}
	full := filepath.Join(r.root, p)
	if r.root == "" {
		full = p
	}

	lfi, err := os.Lstat(full)
	if err != nil {
		return File{}, r.mapErr(p, nil, err)
	}
	if lfi.Mode()&fs.ModeSymlink != 0 {
		return File{}, ErrSymlink
	}
	if !lfi.Mode().IsRegular() {
		return File{}, ErrNotRegular
	}
	if err := r.checkResolved(full); err != nil {
		return File{}, err
	}
	if st, ok := lfi.Sys().(*syscall.Stat_t); ok && r.owner >= 0 && int(st.Uid) != r.owner {
		return File{}, ErrOwner
	}

	f, err := os.OpenFile(full, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return File{}, r.mapErr(p, lfi, err)
	}
	defer f.Close()
	ffi, err := f.Stat()
	if err != nil {
		return File{}, r.mapErr(p, lfi, err)
	}
	if !os.SameFile(lfi, ffi) || !ffi.Mode().IsRegular() {
		return File{}, ErrChanged
	}

	data, err := io.ReadAll(io.LimitReader(f, r.max+1))
	if err != nil {
		return File{}, r.mapErr(p, ffi, err)
	}
	truncated := int64(len(data)) > r.max
	if truncated {
		data = data[:r.max]
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return File{}, ErrBinary
	}
	red := redact.Text(strings.ToValidUTF8(string(data), "�"))
	return File{
		Path:       p,
		Mode:       fmt.Sprintf("%04o", ffi.Mode().Perm()),
		Size:       ffi.Size(),
		Content:    red.Text,
		Truncated:  truncated,
		Redactions: red.Count,
	}, nil
}

// checkResolved is the realpath check: the fully resolved path must be the
// requested path, so no ancestor directory may be a symlink.
func (r *Reader) checkResolved(full string) error {
	real, err := filepath.EvalSymlinks(full)
	if err != nil {
		return ErrNotPresent
	}
	want := full
	if r.root != "" {
		rr, err := filepath.EvalSymlinks(r.root)
		if err != nil {
			return err
		}
		want = filepath.Join(rr, strings.TrimPrefix(full, r.root))
	}
	if real != want {
		return ErrSymlink
	}
	return nil
}

// mapErr converts OS errors into client-safe errors without echoing raw
// OS strings, which can include paths outside the request.
func (r *Reader) mapErr(p string, fi fs.FileInfo, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return ErrNotPresent
	case errors.Is(err, fs.ErrPermission):
		if fi != nil {
			return fmt.Errorf("%w: %s is mode %04o; obsd-mcp runs unprivileged "+
				"(see docs/ARCHITECTURE.md, privilege notes)", ErrPermission, p, fi.Mode().Perm())
		}
		return ErrPermission
	case errors.Is(err, syscall.ELOOP):
		return ErrSymlink
	default:
		return fmt.Errorf("read %s failed", p)
	}
}
