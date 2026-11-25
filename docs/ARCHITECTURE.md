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

ifconfig output is passed through `redact` in case a key is ever shown.

### Always-available views: `system_status`, `network_status`

Unprivileged commands, each a single fixed argv. They must be ELF
binaries: `execve(2)` of a script repeats the exec check on its
interpreter under the same unveil (`exec_script.c` calls `check_exec`
again with the caller's `nameidata`, which has `ni_unveil = UNVEIL_EXEC`),
so a script would need `/bin/ksh` unveiled `x`. That is why `rcctl`
(a ksh script) only runs through doas: doas execs it after our unveil is
gone.

| Tool | Views |
|---|---|
| `system_status` | `sensors` (`sysctl hw.sensors`), `mounts` (`mount`), `swap` (`swapctl -l`), `processes_cpu` / `processes_memory` (`ps -axr` / `-axm -o pid,ppid,user,stat,pcpu,pmem,rss,start,time,comm`) |
| `network_status` | `protocols` (`netstat -s`), `interfaces` (`netstat -in`), `mbufs` (`netstat -m`), `sockets_inet` / `sockets_inet6` (`netstat -an -f inet[6]`), `arp` (`arp -an`), `ndp` (`ndp -an`) |

`ps` uses `comm` (the program name) and never `args`/`command`: other
users' full command lines can carry passwords. A registry test enforces it.

### Opt-in subsystems

Enabled with `-enable pf,unbound,bgp,ntp,services,confcheck`. Each feature gates a group of registry
entries (`basecmd.Spec.Feature`). A disabled feature's commands are refused by
`basecmd.Lookup`, so by `execx` too. Its programs are not unveiled, and its
tool is not registered. Each tool takes one `view` from a fixed enum
(`collect.PF`, `collect.Unbound`, `collect.BGP`). Every view maps to exactly
one registry ID, and its output is redacted.

| Feature | Access path | Why |
|---|---|---|
| `pf` | `doas -n /sbin/pfctl -s <modifier>` | `/dev/pf` is 0600 root. |
| `unbound` | `doas -n /usr/sbin/unbound-control <verb>` | The default `/etc/unbound.conf` enables `/var/run/unbound.sock`, which unbound chmods to 0660. That socket accepts **every** command (reload, flush, stop), so giving the server user socket access would allow changes. doas pins one read-only verb per rule instead. |
| `bgp` | `/usr/sbin/bgpctl -s /var/run/bgpd.rsock show ...` (no doas) | `socket "path" restricted` in bgpd.conf makes bgpd create a 0666 socket. `control.c` accepts only `IMSG_CTL_SHOW_*` messages on it, so it is read-only in the daemon itself. |
| `ntp` | `doas -n /usr/sbin/ntpctl -s <status\|peers\|Sensors\|all>` | ntpd's `control.c` only implements show requests, but chmods the socket 0660, so an unprivileged user cannot connect. |
| `services` | `doas -n /usr/sbin/rcctl ls <on\|started\|failed>` | rcctl is a ksh script (see above), and `ls started\|failed` call `needs_root`. `ls failed` exits 1 when it lists anything; `collect` treats that as a result, not an error. rcctl runs an rc.d check per service, so these commands get a 30 s limit instead of the default 5 s (5 s timed out on the emulated arm64 CI VM). |
| `confcheck` | `doas -n <daemon> -n` (`sshd -t`, `pfctl -n -f /etc/pf.conf`, `unbound-checkconf`) | Every daemon's man page documents the flag as "Configtest mode. Only check the configuration file for validity." The configs are mostly 0600 root. The `config_check` tool returns `valid=false` plus the checker's messages as a normal result; only a check that cannot run (doas refusal, exec failure) is a tool error. |

Registry tests enforce the read-only argument shape:

* pfctl must be exactly `-s <modifier>`, from a fixed safe set.
* unbound-control must be a single verb: `status`, `stats_noreset` or
  `list_*`. Plain `stats` resets counters, and the test rejects it.
* bgpctl must start with `-s /var/run/bgpd.rsock show`.
* ntpctl must be `-s <modifier>`; rcctl must be `ls <on|started|failed>`.
* Every confcheck entry must be exactly `-n`, `sshd -t`,
  `pfctl -n -f /etc/pf.conf` or no arguments (`unbound-checkconf`), so no
  entry can drift into loading a configuration.
* Commands without a feature never use doas.
* Arguments may not contain whitespace, so every argument stays one doas.conf
  token.
* An absolute-path argument must name a base program, a socket under
  `/var/run` or an allowlisted config file (`/etc/pf.conf`).

`Spec.Path` is always the real program. `Spec.Doas` adds the
`/usr/bin/doas -n` wrapper in `Spec.Argv()`, which is used both for exec and
for `-print-doas`. So the doas rules the operator installs are generated
from the same table the server runs:

```
$ obsd-mcp -enable pf -print-doas obsdmcp
permit nopass obsdmcp as root cmd /sbin/pfctl args -s Interfaces
permit nopass obsdmcp as root cmd /sbin/pfctl args -s Tables
permit nopass obsdmcp as root cmd /sbin/pfctl args -s info
...
```

`args` with a fixed list means doas rejects any other arguments. If a
command fails, the tool returns an error with the first stderr line
(redacted) and a setup hint.

The children still run outside our sandbox. `unveil` is not inherited across
`execve`, and doas is setuid. The safety argument for these features is
therefore the fixed argv, the exact-args doas rules, and, for bgpd, the
daemon-enforced restricted socket. It is not our pledge.

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
3. At startup, before the sandbox, any allowlisted path whose
   `EvalSymlinks` result differs from itself (the file or an ancestor is a
   symlink) is dropped from the allowlist. It is never unveiled, never put in
   the enum, and logged by `main`. Per request, `Lstat` the file: it must be a
   regular file (no symlink) owned by uid 0.

   The realpath check can't run per request. Under unveil, `lstat("/etc")`
   returns ENOENT, because `unveil_check_final()` only lets through
   directories that were explicitly unveiled, and `/etc` is not. Unveiling
   individual files does not make their parent directories visible. After
   `Apply`, unveil is bound to vnodes, so swapping an ancestor for a symlink
   cannot reach a file that was not unveiled.
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

## Audit log and limits

Every `tools/call` (and `initialize`, for clients that send it) produces one
syslog line, tag `obsd-mcp[pid]`, facility `daemon`:

```
obsd-mcp[4242]: event=session_start version="0.2.0" uid=1001 features="pf,confcheck" ssh_client="192.0.2.7 50000"
obsd-mcp[4242]: event=tool_call tool="pf_status" args={"view"="rules"} client="claude-code" ms=31 result=ok bytes=2210 redactions=0 truncated=false
obsd-mcp[4242]: event=tool_call tool="config_check" args={"daemon"="bgpd"} client="claude-code" ms=80 result=ok bytes=190 redactions=0 truncated=false valid=false
obsd-mcp[4242]: event=tool_call tool="pf_status" args={"view"="flush"} client="claude-code" ms=0 result=tool_error error="validating \"arguments\": ..."
obsd-mcp[4242]: event=session_end seconds=95
```

* It is an SDK receiving middleware (`mcpserver/audit.go`), so it also sees
  calls rejected before a handler runs (unknown tool, schema violation).
* Tool output is never logged, only its size and the redaction and
  truncation counts.
* Every client-supplied string (tool name, argument keys and values, client
  name) goes through `audit.Sanitize`: it is ASCII-quoted with
  `strconv.QuoteToASCII` and length-capped, so it cannot inject newlines or
  fake `key=value` pairs. At most 4 argument keys are logged.
* The client name is taken from the session on every line, because clients
  on the sessionless protocol (2026-07-28) never send `initialize`.
* Lines go to syslogd through `sendsyslog(2)`, which `kern_pledge.c` marks
  `PLEDGE_ALWAYS`. Auditing therefore needs no pledge promise, no unveil
  path and no socket; Go's `log/syslog` would need `unix` and `/dev/log`.
  Neither `syscall` nor x/sys wraps it, so `internal/audit` calls libc's
  `sendsyslog` with the same trampoline pattern x/sys uses for every libc
  call on OpenBSD (amd64 and arm64). If syslogd is down, the server says
  so once on stderr and keeps serving.
* Off OpenBSD (`-unsafe-dev`), audit lines go to stderr.

`execx` runs at most 4 commands at once (`execx.Limiter`). A call waits up
to 2 s for a slot, then fails with "too many commands running"; the command
timeout starts only once the slot is held.

## unveil / pledge

Order in `main`: validate registry → build policy → build server →
**unveil each rule → `unveil(NULL, NULL)` → `pledge(promises, NULL)`** → read
the first byte of stdin.

Current policy (`obsd-mcp -enable pf,unbound,bgp -print-policy`; the doas line
appears only with `pf` or `unbound`, and the bgpctl line only with `bgp`):

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
unveil("/usr/bin/doas", "x");       /* only with -enable pf or unbound */
unveil("/usr/bin/netstat", "x");
unveil("/usr/bin/uname", "x");
unveil("/usr/bin/uptime", "x");
unveil("/usr/bin/vmstat", "x");
unveil("/usr/sbin/bgpctl", "x");    /* only with -enable bgp */
unveil(NULL, NULL);
pledge("stdio rpath proc exec", NULL);
```

**Child working directory.** `Apply` calls `chdir("/")` before the first
`unveil`, and `execx` leaves `cmd.Dir` empty. A non-empty `Dir` makes the
forked child `chdir` before `execve` while it still has the parent's unveil
restrictions, and `/` isn't visible then (seen on hardware as
`chdir /: no such file or directory`). `execx.TestNewCmdDoesNotChdir` guards
this.

**Child stdio and `/dev/null`.** Child stdin is left nil, so os/exec opens
`/dev/null` read-only, which `rpath` plus the unveil `"r"` rule allow.
Stdout and stderr are always bounded in-memory buffers (pipes). If either
were nil, os/exec would open `/dev/null` `O_WRONLY`. The kernel's `/dev/null`
exemption in `pledge_namei()` applies only to libc's private
`__pledge_open()`, and Go calls `open(2)` directly, so that open needs
`wpath` and pledge kills the process. This was seen on real hardware
(`pledge "wpath", syscall 5`). The fix is to keep the buffers, not to add
`wpath`. `execx.TestNewCmdNeverWritesDevNull` and the `devnull-write`
sandbox scenario guard it.

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

* **allowed**: `confread.Read` of `/etc/hosts` and `/etc/ssh/sshd_config`
  succeeds, every non-opt-in command (`sysctl uname uptime df vmstat
  ifconfig netstat`) runs through the real runner, and `pf_info`,
  `unbound_status` and `bgp_summary` are refused with no features enabled.
  Opening `master.passwd`, `spwd.db`, `passwd`, `doas.conf`, ssh host keys,
  `/usr/local`, `/etc/rc` and `/var/log/messages` fails. Listing `/etc` fails.
  Executing `sh`, `ksh`, `doas`, `pfctl`, `cat`, `unbound-control` and
  `bgpctl` fails.
* **features** (only with `OBSDMCP_TEST_FEATURES=pf,unbound,bgp`, after host
  setup): applies the policy for those features, runs **every view** of each
  enabled subsystem through the real runner and collector, and checks that
  `pfctl` and `unbound-control` still cannot be executed directly, only
  through doas.
* **write / devnull-write / socket / unveil**: creating a file, opening
  `/dev/null` for writing, opening a TCP socket, or calling `unveil` again
  must kill the child with SIGABRT (pledge violation) or fail cleanly.
  Success is a test failure.
* Each probe prints `step: ...` before it runs. If the child is killed, the
  last step line in the failure output names the probe that did it.

Requires Go 1.26 or later (the MCP SDK's minimum). Run it on an OpenBSD host
as an unprivileged user:

```
go test ./internal/sandbox -run Sandbox -v
# or cross-compile the test binary and copy it over:
GOOS=openbsd GOARCH=amd64 go test -c -o sandbox.test ./internal/sandbox
./sandbox.test -test.run Sandbox -test.v
```
