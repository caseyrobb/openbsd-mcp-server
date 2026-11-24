# obsd-mcp architecture (MVP)

Read-only MCP server for the **OpenBSD base system**. It runs over stdio as a
dedicated unprivileged user, usually started by sshd with a forced command.
It never opens a network socket.

## Language: Go

* **Builds without ports.** `GOOS=openbsd CGO_ENABLED=0 go build` on any host
  produces a binary whose only runtime dependency is base `ld.so` and libc.
  You do not need the `go` package on the target.
* **Memory safe** for the risky part, which is parsing untrusted JSON-RPC.
* **pledge/unveil are available** through `golang.org/x/sys/unix`
  (`Pledge`, `PledgePromises`, `Unveil`, `UnveilBlock`). Since 1.16, the Go
  runtime makes syscalls through libc, so it works with OpenBSD syscall pinning.
* C would be the most native choice, but a hand-written JSON-RPC/MCP parser
  in C is the largest attack surface in the design. Rust is also a good fit,
  but it would need the Rust toolchain from ports to build on OpenBSD, and it
  gains nothing here.
* Cost: the official SDK (`github.com/modelcontextprotocol/go-sdk`) brings in
  transitive dependencies (jsonschema, oauth2 for HTTP auth that we don't use).
  The SDK is confined to `internal/mcpserver`, so it can be swapped for a
  small hand-written stdio JSON-RPC layer later without touching collectors.

## Layout

```
cmd/obsd-mcp/          main: flags, policy build, sandbox.Apply, serve stdio
internal/basecmd/      allowlist of {ID -> absolute base path + fixed argv}
internal/execx/        Runner: no shell, scrubbed env, timeout, bounded output
internal/sandbox/      portable Policy + Apply (openbsd) / ErrUnsupported (other)
internal/collect/      collectors (system, network); plain structs, no MCP
internal/confread/     config allowlist, path validation, safe open
internal/redact/       secret redaction shared by confread and network_summary
internal/mcpserver/    the only MCP-aware package; tools -> collectors
docs/                  this file, deployment notes
```

Dependency direction: `mcpserver -> collect -> execx -> basecmd` and
`mcpserver -> confread -> redact`. `main` builds the sandbox policy from
`basecmd.Binaries(enabled)` and `confread.Paths()`. Collectors cannot
construct argv; they can only pass a `basecmd.ID`.

## MVP tools

| Tool | Status | Source |
|---|---|---|
| `system_overview` | **implemented** | `uname -a`, `uptime`, `sysctl <12 fixed MIBs>`, `df -h`, `vmstat` |
| `network_summary` | **implemented** | `ifconfig`, `netstat -rn`, opt-in `doas -n pfctl -s info` |
| `config_read` | **implemented** | allowlisted `/etc` files, path-validated and redacted |

All tools carry `readOnlyHint: true, destructiveHint: false`. A failing command
fills only its own section's `error` and adds it to `errors[]`. Partial
results are still returned. A cancelled context fails the whole call.

### `network_summary`

| ID | argv | Unprivileged? |
|---|---|---|
| ifconfig | `/sbin/ifconfig` | yes. Wireless/WireGuard keys are not shown to non-root. |
| routes | `/usr/bin/netstat -rn` | yes (routing sysctl) |
| pf_info | `/sbin/pfctl -s info` | **no**. `/dev/pf` is `crw------- root`. |

For `pf_info`, the default is to return `"unavailable: requires root"` without
running anything. With the opt-in `-pf-doas` flag, the server runs
`/usr/bin/doas -n /sbin/pfctl -s info` with this exact-args rule:

```
# /etc/doas.conf
permit nopass obsdmcp as root cmd /sbin/pfctl args -s info
```

`args` with a fixed list means doas rejects any other arguments. `/usr/bin/doas`
is unveiled `x` only when the flag is set. Without the flag, `pf_info` is also
refused by `basecmd.Lookup` and `execx`. ifconfig output is passed through
`redact` in case a key is ever shown.

### `config_read`

The input `path` must match one entry of a fixed allowlist exactly. The JSON
schema exposes the list as an `enum`, so the SDK rejects anything else before
the handler runs. The handler validates again anyway, in this order:

1. Reject NUL/control/invalid-UTF-8 characters, a relative path, any `.` or
   `..` component, and any input where `path.Clean(p) != p`. Bad input is
   rejected, never normalised. Then reject denylisted names, even if they were
   allowlisted by mistake.
2. Look `p` up exactly in the allowlist. `/etc/hostname.*` is expanded once at
   startup against `^hostname\.[a-z]+[0-9]+$`.
3. `EvalSymlinks` must return the path unchanged (no symlinked ancestors).
   `Lstat` the file. It must be a regular file (no symlink) owned by uid 0.
4. Open with `O_RDONLY|O_NOFOLLOW|O_NONBLOCK`, then `Fstat`. The dev/inode must
   match step 3, which closes the TOCTOU window. Content over 64 KiB is
   truncated and flagged. Content containing NUL is refused as binary.
   OS errors are mapped to fixed messages, and permission errors report the
   file mode.
5. Redact line by line. Keep the keyword and replace the value with
   `<redacted>` for the whole-word keywords `wpakey nwkey wgkey wgpsk psk
   password passwd secret auth-key authkey auth-md5 private-key privkey`, and
   for `NAME=value` where NAME contains password/passwd/secret/token/apikey/psk.
   Collapse any `-----BEGIN ... PRIVATE KEY-----` block (redacted to end of
   input if unterminated). `PasswordAuthentication no` is deliberately left
   alone. A keyword in a comment also redacts the next word, which is
   acceptable over-redaction.

MVP allowlist: `/etc/rc.conf.local /etc/pf.conf /etc/sysctl.conf /etc/hosts
/etc/resolv.conf /etc/myname /etc/mygate /etc/ntpd.conf /etc/syslog.conf
/etc/fstab /etc/ssh/sshd_config /etc/httpd.conf /etc/hostname.*`. The
`hostname.*` names are expanded at startup and must match
`^hostname\.[a-z]+[0-9]+$`, so `hostname.em0.bak` is excluded.

The confread denylist refuses these even if they are allowlisted:
`master.passwd spwd.db pwd.db doas.conf iked.conf ipsec.conf authorized_keys
.env skeykeys ssh_host_* *.key *.pem id_* *.secret *.db` and anything under
`/usr/local /etc/pkg /var/db/pkg /etc/ssl/private /etc/iked /etc/isakmpd /root
/home`. `sandbox.NewPolicy` separately refuses to unveil the same secret
stores and package trees.

## unveil / pledge

Order in `main`: validate registry → build policy → build server →
**unveil each rule → `unveil(NULL, NULL)` → `pledge(promises, NULL)`** → read
the first byte of stdin.

Current policy (`obsd-mcp -print-policy -pf-doas`; without `-pf-doas` the
doas line is absent):

```c
unveil("/bin/df", "x");
unveil("/dev/null", "r");           /* os/exec opens it for child stdin */
unveil("/etc/fstab", "r");          /* one "r" rule per allowlisted config */
unveil("/etc/hosts", "r");
unveil("/etc/httpd.conf", "r");
unveil("/etc/mygate", "r");
unveil("/etc/myname", "r");
unveil("/etc/ntpd.conf", "r");
unveil("/etc/pf.conf", "r");
unveil("/etc/rc.conf.local", "r");
unveil("/etc/resolv.conf", "r");
unveil("/etc/ssh/sshd_config", "r");
unveil("/etc/sysctl.conf", "r");
unveil("/etc/syslog.conf", "r");
                                    /* + /etc/hostname.<if> present at startup */
unveil("/sbin/ifconfig", "x");
unveil("/sbin/sysctl", "x");
unveil("/usr/bin/doas", "x");       /* only with -pf-doas */
unveil("/usr/bin/netstat", "x");
unveil("/usr/bin/uname", "x");
unveil("/usr/bin/uptime", "x");
unveil("/usr/bin/vmstat", "x");
unveil(NULL, NULL);
pledge("stdio rpath proc exec", NULL);
```

Files are unveiled one at a time, never `/etc`, so a path-validation bug still
cannot reach `/etc/master.passwd`. A missing file (ENOENT) is skipped and
logged.

What each promise is for:

* `stdio`: MCP over stdin/stdout, pipes to children, memory, clocks.
* `rpath`: reading unveiled config files and `/dev/null`.
* `proc`: `fork` for `os/exec`, and `kill` of our own timed-out children.
* `exec`: `execve` of unveiled binaries.

Deliberately absent: `wpath cpath dpath fattr chown` (no writes), `inet unix
dns` (stdio only), `unveil` (locked), `id settime tty ps vminfo` (the
children make those queries, not us).

**Caveat: sandbox inheritance.** unveil restrictions are not inherited across
`execve`, and with `execpromises = NULL` the children are not pledged by us.
They are fixed-argv base programs, and most of them pledge themselves. Setting
`execpromises` would apply one union set to every child (`ifconfig`, `sysctl`,
`netstat` and `doas` need different groups). That weakens the benefit, so it
is postponed until there is a measured per-tool promise set.

## Privilege notes (non-root, not in wheel)

Check modes on your host with `ls -l`. The defaults below come from base
installs and `/etc/newsyslog.conf`.

| Resource | Default | Readable unprivileged? |
|---|---|---|
| `sysctl` kern/hw/vm MIBs used | n/a | yes |
| `ifconfig`, `netstat -rn`, `df`, `vmstat`, `uptime` | n/a | yes |
| `/dev/pf` (`pfctl -s *`) | 0600 root | **no**. Use the exact-args doas rule or omit. |
| `/etc/pf.conf` | 0600 root:wheel | **no**. Either the admin sets `chgrp obsdmcp; chmod 0640` (check that security(8) output doesn't flag it), or the tool reports EACCES clearly. |
| `/etc/hostname.*` | 0640 root:wheel | **no** (they may hold wpakey/wgkey) |
| `/etc/rc.conf.local`, `hosts`, `resolv.conf`, `sshd_config` | 0644 | yes |
| `/var/log/messages` | 0644 | yes (out of MVP scope) |
| `/var/log/authlog`, `daemon`, `maillog` | 0640 root:wheel | no. Never add the user to wheel. |
| `/var/log/secure`, `pflog` | 0600 | no |

## Deployment sketch

```
useradd -m -s /bin/ksh -c "read-only MCP" obsdmcp     # NOT in wheel
# ~obsdmcp/.ssh/authorized_keys:
restrict,command="/usr/local/libexec/obsd-mcp" ssh-ed25519 AAAA... agent
```

The server binary can live anywhere root-owned. It is our artifact and not a
dependency, and it never reads or executes anything under `/usr/local`. The
login shell must be a real shell, because sshd runs forced commands via
`$SHELL -c`.

## Tests

`go test ./...` runs on any OS. The unit tests cover the registry invariants,
output bounds, the sandbox policy (rules, promises, forbidden paths), redaction,
every confread rejection path, and MCP round trips through an in-memory
transport. `mcpserver` depends on a small `ConfigReader` interface
(`Paths`, `Read`). Its tests use a fake, so they cover only the MCP glue:
the schema enum, schema rejection before the reader is called, and error
mapping. All security behaviour of the reader is tested in `internal/confread`
against temp-dir fixtures, through the unexported constructor, so no test-only
constructor is exported.

`internal/sandbox/sandbox_openbsd_test.go` (build tag `openbsd`) checks the
**real** policy. Each scenario re-execs the test binary as a child that applies
the production policy and then probes it:

* **allowed**: `confread.Read("/etc/hosts")` and `sysctl` through the real
  runner succeed. Opening `master.passwd`, `spwd.db`, `passwd`, `doas.conf`,
  ssh host keys, `/usr/local`, `/etc/rc` and `/var/log/messages` fails.
  Listing `/etc` fails. Executing `sh`, `ksh`, `doas`, `pfctl` and `cat` fails.
* **write / socket / unveil**: creating a file, opening a TCP socket, or
  calling `unveil` again must kill the child with SIGABRT (pledge violation)
  or fail cleanly. Success is a test failure.

Run it on an OpenBSD host as an unprivileged user:

```
go test ./internal/sandbox -run Sandbox -v
# or cross-compile the test binary and copy it over:
GOOS=openbsd GOARCH=amd64 go test -c -o sandbox.test ./internal/sandbox
./sandbox.test -test.run Sandbox -test.v
```
