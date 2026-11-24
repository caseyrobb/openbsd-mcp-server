package confread

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// fakeRoot builds <tmp>/etc with the given files and returns a Reader rooted
// there that accepts files owned by the current user.
func fakeRoot(t *testing.T, files map[string]string) (*Reader, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc", "ssh"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r, err := newReader(root, os.Getuid(), MaxSize)
	if err != nil {
		t.Fatal(err)
	}
	return r, root
}

func TestReadAllowlistedAndRedacted(t *testing.T) {
	r, _ := fakeRoot(t, map[string]string{
		"etc/rc.conf.local": "pf=YES\nfoo_password=hunter2\n",
	})
	f, err := r.Read("/etc/rc.conf.local")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.Content, "hunter2") {
		t.Fatal("secret leaked")
	}
	if f.Content != "pf=YES\nfoo_password=<redacted>\n" || f.Redactions != 1 || f.Mode != "0644" {
		t.Errorf("got %+v", f)
	}
}

func TestTraversalAndMalformedRejected(t *testing.T) {
	r, _ := fakeRoot(t, map[string]string{"etc/hosts": "127.0.0.1 localhost\n"})
	bad := []string{
		"",
		"etc/hosts",
		"./etc/hosts",
		"/etc/../etc/hosts",
		"/etc/./hosts",
		"/etc//hosts",
		"/etc/hosts/",
		"/etc/hosts/..",
		"/../etc/hosts",
		"/etc/hosts\x00",
		"/etc/hosts\n",
		"/etc/\x7fhosts",
		"/etc/hosts\xff",
		"/" + strings.Repeat("a", 300),
	}
	for _, p := range bad {
		if _, err := r.Read(p); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("Read(%q) err = %v, want ErrInvalidPath", p, err)
		}
	}
}

func TestDenylistedRejected(t *testing.T) {
	r, _ := fakeRoot(t, nil)
	for _, p := range []string{
		"/etc/master.passwd",
		"/etc/spwd.db",
		"/etc/doas.conf",
		"/etc/iked.conf",
		"/etc/ipsec.conf",
		"/etc/ssl/private/server.key",
		"/etc/ssh/ssh_host_ed25519_key",
		"/etc/ssl/server.pem",
		"/usr/local/etc/smb.conf",
		"/etc/pkg/pkg.conf",
		"/root/.ssh/authorized_keys",
		"/home/user/.env",
	} {
		if _, err := r.Read(p); !errors.Is(err, ErrDenied) {
			t.Errorf("Read(%q) err = %v, want ErrDenied", p, err)
		}
	}
}

func TestNotAllowlistedRejected(t *testing.T) {
	r, root := fakeRoot(t, map[string]string{"etc/passwd": "root:*:0:0::/root:/bin/ksh\n"})
	for _, p := range []string{"/etc/passwd", "/etc/shells", "/etc/rc", "/var/log/messages", "/etc"} {
		if _, err := r.Read(p); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("Read(%q) err = %v, want ErrNotAllowed", p, err)
		}
	}
	_ = root
}

func TestSymlinkRejected(t *testing.T) {
	r, root := fakeRoot(t, map[string]string{"etc/secret": "wpakey x\n"})
	if err := os.Symlink(filepath.Join(root, "etc/secret"), filepath.Join(root, "etc/hosts")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read("/etc/hosts"); !errors.Is(err, ErrSymlink) {
		t.Fatalf("err = %v, want ErrSymlink", err)
	}
}

func TestSymlinkedAncestorRejected(t *testing.T) {
	r, root := fakeRoot(t, nil)
	other := filepath.Join(root, "elsewhere")
	os.MkdirAll(other, 0o755)
	os.WriteFile(filepath.Join(other, "sshd_config"), []byte("Port 22\n"), 0o644)
	os.RemoveAll(filepath.Join(root, "etc/ssh"))
	if err := os.Symlink(other, filepath.Join(root, "etc/ssh")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read("/etc/ssh/sshd_config"); !errors.Is(err, ErrSymlink) {
		t.Fatalf("err = %v, want ErrSymlink", err)
	}
}

func TestNotPresent(t *testing.T) {
	r, _ := fakeRoot(t, nil)
	if _, err := r.Read("/etc/mygate"); !errors.Is(err, ErrNotPresent) {
		t.Fatalf("err = %v, want ErrNotPresent", err)
	}
}

func TestNonRegularRejected(t *testing.T) {
	r, root := fakeRoot(t, nil)
	os.Mkdir(filepath.Join(root, "etc/myname"), 0o755)
	if _, err := r.Read("/etc/myname"); !errors.Is(err, ErrNotRegular) {
		t.Errorf("dir: err = %v, want ErrNotRegular", err)
	}
	// A FIFO must be rejected without blocking.
	if err := syscall.Mkfifo(filepath.Join(root, "etc/mygate"), 0o644); err != nil {
		t.Skip("mkfifo unsupported:", err)
	}
	if _, err := r.Read("/etc/mygate"); !errors.Is(err, ErrNotRegular) {
		t.Errorf("fifo: err = %v, want ErrNotRegular", err)
	}
}

func TestOwnerEnforced(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/hosts"), []byte("x\n"), 0o644)
	r, err := newReader(root, os.Getuid()+1, MaxSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read("/etc/hosts"); !errors.Is(err, ErrOwner) {
		t.Fatalf("err = %v, want ErrOwner", err)
	}
}

func TestSizeBound(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/hosts"), []byte(strings.Repeat("a", 100)), 0o644)
	r, _ := newReader(root, os.Getuid(), 10)
	f, err := r.Read("/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Content) != 10 || !f.Truncated || f.Size != 100 {
		t.Errorf("len=%d truncated=%v size=%d", len(f.Content), f.Truncated, f.Size)
	}
	// Exactly at the limit is not truncated.
	os.WriteFile(filepath.Join(root, "etc/hosts"), []byte(strings.Repeat("a", 10)), 0o644)
	if f, _ := r.Read("/etc/hosts"); f.Truncated {
		t.Error("file of exactly max bytes reported truncated")
	}
}

func TestBinaryRejected(t *testing.T) {
	r, _ := fakeRoot(t, map[string]string{"etc/hosts": "a\x00b"})
	if _, err := r.Read("/etc/hosts"); !errors.Is(err, ErrBinary) {
		t.Fatalf("err = %v, want ErrBinary", err)
	}
}

func TestPermissionDeniedReportsMode(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses file modes")
	}
	r, root := fakeRoot(t, map[string]string{"etc/pf.conf": "block all\n"})
	os.Chmod(filepath.Join(root, "etc/pf.conf"), 0o600&^0o400)
	_, err := r.Read("/etc/pf.conf")
	if !errors.Is(err, ErrPermission) || !strings.Contains(err.Error(), "mode 0200") {
		t.Fatalf("err = %v, want ErrPermission with mode", err)
	}
	if strings.Contains(err.Error(), root) {
		t.Error("error leaks real filesystem path")
	}
}

func TestHostnameIfExpansion(t *testing.T) {
	r, _ := fakeRoot(t, map[string]string{
		"etc/hostname.em0":     "inet autoconf\n",
		"etc/hostname.wg0":     "wgkey kVd0Zr2pW5c8Mq2jQ0K0+aXyZw1PZ1cH2bD2y4ZJ6mE=\nwgport 51820\n",
		"etc/hostname.em0.bak": "x\n",
		"etc/hostname.EM1":     "x\n",
		"etc/hostname.":        "x\n",
	})
	paths := r.Paths()
	for _, want := range []string{"/etc/hostname.em0", "/etc/hostname.wg0"} {
		if !slices.Contains(paths, want) {
			t.Errorf("%s missing from allowlist %v", want, paths)
		}
	}
	for _, bad := range []string{"/etc/hostname.em0.bak", "/etc/hostname.EM1", "/etc/hostname."} {
		if slices.Contains(paths, bad) {
			t.Errorf("%s should not be allowlisted", bad)
		}
	}
	f, err := r.Read("/etc/hostname.wg0")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.Content, "kVd0") || !strings.Contains(f.Content, "wgport 51820") {
		t.Errorf("content = %q", f.Content)
	}
}

func TestFixedAllowlistIsBaseAndNotDenied(t *testing.T) {
	for _, p := range Fixed {
		if err := validate(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
		if denied(p) {
			t.Errorf("%s is both allowlisted and denylisted", p)
		}
		if !strings.HasPrefix(p, "/etc/") {
			t.Errorf("%s is outside /etc", p)
		}
	}
}
