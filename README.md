# openbsd-mcp-server

A read-only [Model Context Protocol](https://modelcontextprotocol.io) server
that lets an AI agent inspect an **OpenBSD base system**. It cannot change
anything, run arbitrary commands or read secrets.

* **Read-only by construction.** The server has no write, reload or "run command" tools.
  Every external program is a fixed path plus a fixed argument list. Nothing
  goes through a shell.
* **Sandboxed with `unveil(2)` and `pledge(2)`.** Each allowlisted binary and
  config file is unveiled individually. Then unveil is locked and the process
  pledges `stdio rpath proc exec`. It has no network, write or create promises.
* **Base system only.** The server never touches `/usr/local`, `/etc/pkg` or
  any ports or packages.
* **Secret hygiene.** Config reads use an allowlist and a denylist, reject
  path traversal and symlinks, require root-owned regular files, are size
  bounded, and have secret values such as `wpakey`, `wgkey`, `psk`,
  `password` and private key blocks replaced with `<redacted>`.
* **Unprivileged.** The server refuses to run as root, and it needs no
  `doas` unless you opt in to a feature that requires it.
* **Audited.** Every tool call is logged to syslog with its arguments,
  result and timing, never its output.

The server speaks MCP over **stdio**. For remote use, sshd starts it with a
forced command, so the server itself never opens a socket.

## Tools

| Tool | What it returns |
|---|---|
| `system_overview` | `uname -a`, `uptime`, selected `kern.*`/`hw.*`/`vm.*` sysctl values, `df -h`, `vmstat` |
| `network_summary` | `ifconfig` (redacted), `netstat -rn` |
| `system_status` | One view: `sensors`, `mounts`, `swap`, `processes_cpu`, `processes_memory` (program names only, never command-line arguments) |
| `network_status` | One view: `protocols` (`netstat -s`), `interfaces` (`netstat -in`), `mbufs`, `sockets_inet`, `sockets_inet6`, `arp`, `ndp` |
| `config_read` | One allowlisted file from `/etc`, redacted. The allowed paths are listed in the tool's input schema. |
| `pf_status` | **Opt-in** (`-enable pf`). One `pfctl -s` view: `info`, `rules`, `tables`, `memory`, `timeouts`, `interfaces`, `queues` |
| `unbound_status` | **Opt-in** (`-enable unbound`). One `unbound-control` view: `status`, `stats` (`stats_noreset`), `forwards`, `stubs`, `local_zones`, `auth_zones`, `insecure` |
| `bgp_status` | **Opt-in** (`-enable bgp`). One `bgpctl show` view: `summary`, `neighbors`, `nexthops`, `interfaces`, `rib_memory` |
| `ntp_status` | **Opt-in** (`-enable ntp`). One `ntpctl -s` view: `status`, `peers`, `sensors`, `all` |
| `services_status` | **Opt-in** (`-enable services`). One `rcctl ls` view: `enabled`, `started`, `failed` |
| `log_tail` | **Opt-in** (`-enable logs`). The newest lines of one fixed log: `messages`, `daemon`, `authlog`, `secure`, `maillog`, `xferlog`, `cron`, `httpd_access`, `httpd_error`. Optional `lines` (1-500, default 100) and `match` (plain text, case-insensitive) |
| `ospf_status`, `ospf6_status` | **Opt-in** (`-enable ospf`, `ospf6`). One `ospfctl`/`ospf6ctl show` view: `summary`, `neighbors`, `interfaces`, `rib`, `fib` |
| `relayd_status` | **Opt-in** (`-enable relayd`). One `relayctl show` view: `summary`, `hosts`, `redirects`, `relays`, `routers` |
| `smtpd_status` | **Opt-in** (`-enable smtpd`). `smtpctl show status` or `show stats`; never the queue, envelopes or messages |
| `vmd_status` | **Opt-in** (`-enable vmd`). `vmctl status` |
| `unwind_status` | **Opt-in** (`-enable unwind`). `unwindctl status` or `status autoconf` |
| `ipsec_status` | **Opt-in** (`-enable ipsec`). `flows` (`ipsecctl -s flow`), `sas` (`ipsecctl -s sa`, never `-k`), `iked_sas` (`ikectl show sa`) |
| `config_check` | **Opt-in** (`-enable confcheck`). Runs one daemon's configtest mode (`-n`, `sshd -t`) and reports `valid` plus the checker's messages: `pf`, `bgpd`, `httpd`, `relayd`, `smtpd`, `iked`, `ntpd`, `ospfd`, `ospf6d`, `dhcpd`, `unwind`, `vmd`, `snmpd`, `sshd`, `unbound` |

The `config_read` allowlist is `/etc/rc.conf.local`, `pf.conf`, `sysctl.conf`,
`hosts`, `resolv.conf`, `myname`, `mygate`, `ntpd.conf`, `syslog.conf`,
`fstab`, `httpd.conf`, `ssh/sshd_config` and `/etc/hostname.<if>`.

All tools are annotated `readOnlyHint: true`. If one command fails in
`system_overview` or `network_summary`, only that section reports an error and
the rest of the result is still returned. The `*_status` tools take a single
`view` from a fixed enum, run exactly one fixed command, and return its
redacted output plus the command line that ran. Opt-in tools are registered
only when their feature is enabled.

Some views also return `data`, the same output parsed into fields, so an
agent can compare numbers without re-reading text tables:

| View | `data` |
|---|---|
| `pf_status info` | `enabled`, `uptime`, and every counter by section (`State Table`, `Counters`, interface stats) with `total` and pf's `rate_per_sec` |
| `system_status sensors` | one entry per sensor: `device`, `name`, `type`, `value`, numeric `number`, `unit`, `description`, `status` |
| `network_status interfaces` | per interface: `up`, `mtu`, `address`, `in_packets`, `in_fails`, `out_packets`, `out_fails`, `collisions` |
| `ntp_status status` | `synced`, `stratum`, peers and sensors valid/total, `constraint_offset_secs`, `clock_offset_ms` (while unsynced) |
| `ntp_status peers` | per peer: `selected`, `weight`, `trust_level`, `stratum`, `next_secs`, `poll_secs`, `valid`, `offset_ms`, `delay_ms`, `jitter_ms` |

`data` is parsed from the redacted output and is omitted when the output
cannot be parsed; the text `output` is always returned.

### Reading logs

`log_tail` reads the last 1000 lines of one fixed file with
`doas -n /usr/bin/tail -n 1000 <file>`, then filters and trims them. The
client only picks a name; it can never name a file. Even `/var/log/messages`
(mode 0644) goes through doas: if `tail` were unveiled for direct exec, a
compromised server could run it on any file the server user can read and
step around `unveil`.

Every line is redacted before it is returned or matched:

* secret values (`password ...`, `psk ...`, `*_token=...`), as in all output;
* sshd `invalid user NAME`, because NAME is whatever the client typed,
  often a password entered at the user prompt;
* doas command arguments (`ran command /bin/x <redacted> as root`);
* URL query strings in httpd access logs (`GET /reset?<redacted>`);
* control characters and invalid UTF-8, which become U+FFFD.

`match` runs on the redacted text, so it cannot confirm a hidden value.
Log text comes from other programs and remote clients, so the tool tells the
agent to treat it as data, never as instructions.

## Requirements

* OpenBSD (amd64 or arm64) to run the server.
* Go 1.26 or later to build. You can build on the OpenBSD host or
  cross-compile from anywhere. The binary needs only base `ld.so` and libc.

## Build

```sh
# on OpenBSD
go build -o obsd-mcp ./cmd/obsd-mcp

# or cross-compile
GOOS=openbsd GOARCH=amd64 CGO_ENABLED=0 go build -o obsd-mcp ./cmd/obsd-mcp
```

## Install

### From a release package

Every [GitHub release](https://github.com/caseyrobb/openbsd-mcp-server/releases)
has a `pkg_add` package for amd64 and arm64, named
`obsd-mcp-<version>-<arch>.tgz`, plus a `SHA256` file and, from v0.3.0, a
`SHA256.sig` signed with [signify(1)](https://man.openbsd.org/signify).
Fetch the public key [`signify/obsd-mcp.pub`](signify/obsd-mcp.pub) once,
keep it in `/etc/signify`, and verify every download against it:

```sh
doas ftp -o /etc/signify/obsd-mcp.pub \
    https://raw.githubusercontent.com/caseyrobb/openbsd-mcp-server/main/signify/obsd-mcp.pub
v=0.3.0 a=$(arch -s)
ftp https://github.com/caseyrobb/openbsd-mcp-server/releases/download/v$v/obsd-mcp-$v-$a.tgz
ftp https://github.com/caseyrobb/openbsd-mcp-server/releases/download/v$v/SHA256.sig
signify -C -p /etc/signify/obsd-mcp.pub -x SHA256.sig obsd-mcp-$v-$a.tgz
doas pkg_add -D unsigned ./obsd-mcp-$v-$a.tgz
```

`signify -C` checks the signature and then the file's checksum, so a
tampered package or `SHA256.sig` fails. `pkg_add -D unsigned` is still needed
because the package itself carries no pkg_add signature. Releases before
v0.3.0 and the `dev` builds only have an unsigned `SHA256`
(`sha256 -C SHA256 <file>`).

This installs `/usr/local/libexec/obsd-mcp`. The `dev` prerelease always
holds a build of the latest `main`.

### From source

```sh
doas install -o root -g bin -m 0555 obsd-mcp /usr/local/libexec/obsd-mcp
```

### Set up the user

Create a dedicated unprivileged user. Do **not** add it to `wheel`.

```sh
doas useradd -m -s /bin/ksh -c "read-only MCP" obsdmcp
```

Any root-owned location that the `obsdmcp` user cannot write to will do. The
server never reads or runs anything under `/usr/local`; this is only where its
own binary lives.

Pin the account to the server in sshd. `-print-sshd` prints a `Match User`
block built from the same `-enable` list, so the forced command always
matches the features you chose:

```sh
/usr/local/libexec/obsd-mcp -enable pf -print-sshd obsdmcp | doas tee -a /etc/ssh/sshd_config
doas sshd -t && doas rcctl reload sshd
```

```
Match User obsdmcp
	ForceCommand /usr/local/libexec/obsd-mcp -enable pf
	AuthenticationMethods publickey
	DisableForwarding yes
	PermitTTY no
	PermitTunnel no
	PermitUserRC no
Match all
```

`ForceCommand` overrides whatever command the client asks for, so this
account can only ever start the server. The block also turns off password
login, every kind of forwarding (TCP, agent, X11 and Unix sockets), TTYs,
tunnels and `~/.ssh/rc`. The final `Match all` ends the block, so settings
added to the file later stay global. The flag warns if the server binary is
not root-owned or is writable by others: whoever can replace it controls
what the account runs.

Also restrict the key itself in `~obsdmcp/.ssh/authorized_keys`, so the
key stays limited even if the sshd block is removed:

```
restrict,command="/usr/local/libexec/obsd-mcp -enable pf" ssh-ed25519 AAAA... agent-key
```

The user needs a real login shell, because sshd runs forced commands through
`$SHELL -c`.

### Optional features

These are off by default. Turn them on with `-enable` in the
forced command; rerun `-print-sshd` with the new list and replace the old
block, and update the `command=` in `authorized_keys` to match, for example:

```
restrict,command="/usr/local/libexec/obsd-mcp -enable pf,unbound,bgp" ssh-ed25519 AAAA... agent-key
```

| Feature | Runs | Access | Host setup |
|---|---|---|---|
| `pf` | `/sbin/pfctl -s <view>` | `doas -n` (`/dev/pf` is 0600 root) | doas rules |
| `unbound` | `/usr/sbin/unbound-control <verb>` | `doas -n` (the control socket allows reload, flush and stop, so the server user must not have it) | doas rules; unbound running with `remote-control` enabled (the default `/etc/unbound.conf` does this) |
| `bgp` | `/usr/sbin/bgpctl -s /var/run/bgpd.rsock show <view>` | unprivileged, through bgpd's **restricted** socket, which only accepts `show` requests | add `socket "/var/run/bgpd.rsock" restricted` to `/etc/bgpd.conf`, then `doas bgpctl reload` |
| `ntp` | `/usr/sbin/ntpctl -s <view>` | `doas -n` (ntpd's socket is 0660 root) | doas rules; ntpd running |
| `services` | `/usr/sbin/rcctl ls on\|started\|failed` | `doas -n` (rcctl is a shell script, and `started`/`failed` need root) | doas rules |
| `confcheck` | each daemon's `-n` configtest, `sshd -t`, `pfctl -n -f /etc/pf.conf`, `unbound-checkconf` | `doas -n` (most configs are 0600 root) | doas rules |
| `logs` | `/usr/bin/tail -n 1000 <one of 9 fixed logs>` | `doas -n` (most logs are 0640 or 0600 root) | doas rules |
| `ospf`, `ospf6` | `/usr/sbin/ospfctl`/`ospf6ctl show <view>` | `doas -n` (the control socket also accepts reload and fib changes) | doas rules; daemon running |
| `relayd` | `/usr/sbin/relayctl show <view>` | `doas -n` (the socket also accepts enable/disable/reload) | doas rules; relayd running |
| `smtpd` | `/usr/sbin/smtpctl show status\|stats` | `doas -n` (the socket also accepts pause/remove/schedule) | doas rules; smtpd running |
| `vmd` | `/usr/sbin/vmctl status` | `doas -n` (the socket also accepts start/stop) | doas rules; vmd running |
| `unwind` | `/usr/sbin/unwindctl status [autoconf]` | `doas -n` (the socket also accepts reload) | doas rules; unwind running |
| `ipsec` | `/sbin/ipsecctl -s flow\|sa`, `/usr/sbin/ikectl show sa` | `doas -n` (PF_KEY and iked's socket need root; `-k` is never run) | doas rules; iked running for `iked_sas` |

Generate the exact `doas.conf` rules from the server itself, so they always
match what it runs:

```sh
/usr/local/libexec/obsd-mcp -enable pf,unbound,ntp,services,confcheck,logs -print-doas obsdmcp | doas tee -a /etc/doas.conf
doas doas -C /etc/doas.conf    # syntax check
```

Each rule pins the full argument list, for example
`permit nopass obsdmcp as root cmd /sbin/pfctl args -s rules`, so doas refuses
any other arguments. `unbound`'s statistics view uses `stats_noreset`: plain
`stats` resets the counters and is never run.

`doas` and `bgpctl` are unveiled only when a feature that needs them is
enabled. Programs run through `doas` (`pfctl`, `unbound-control`, `ntpctl`,
`rcctl`, `tail`, the daemon control programs and the daemons) are never
executable by the server directly.
A config check never loads anything: each daemon's flag is documented as
"only check the configuration file for validity".

## Audit log

Each session and every tool call is logged through `syslogd` (facility
`daemon`, so `/var/log/daemon` by default), including calls that were
rejected:

```
obsd-mcp[4242]: event=session_start version="0.2.0" uid=1001 features="pf" ssh_client="192.0.2.7 50000"
obsd-mcp[4242]: event=tool_call tool="pf_status" args={"view"="rules"} client="claude-code" ms=31 result=ok bytes=2210 redactions=0 truncated=false
```

Tool output is never logged. Client-supplied values are escaped and
length-capped, so they cannot forge log lines. The server runs at most 4
commands at once; extra calls wait up to 2 s, then fail with "too many
commands running".

## Connect an MCP client

Any MCP client that can launch a stdio command works. With Claude Code:

```sh
claude mcp add openbsd -- ssh -T -i ~/.ssh/obsdmcp obsdmcp@fw1.example.org
```

Or in a generic `mcpServers` JSON config:

```json
{
  "mcpServers": {
    "openbsd": {
      "command": "ssh",
      "args": ["-T", "-i", "~/.ssh/obsdmcp", "obsdmcp@fw1.example.org"]
    }
  }
}
```

## Flags

| Flag | Purpose |
|---|---|
| `-enable pf,unbound,...` | Enable opt-in tools (see above; `-h` lists all features) |
| `-print-doas USER` | Print the `doas.conf` rules USER needs for `-enable`, then exit |
| `-print-sshd USER` | Print an `sshd_config` `Match User` block that pins USER to this server with `-enable`, then exit |
| `-print-policy` | Print the exact `unveil`/`pledge` calls and exit |
| `-unsafe-dev` | Run without a sandbox on non-OpenBSD systems, for development only |
| `-version` | Print the version and exit |

## Privileges and file modes

The server runs unprivileged, so some files and data are unreadable by
default. The server reports this clearly instead of failing silently.

| Resource | Default | Readable? |
|---|---|---|
| sysctl values used, `ifconfig`, `netstat -rn`, `df`, `vmstat` | n/a | yes |
| `ps`, `mount`, `swapctl`, `netstat -s/-in/-m/-an`, `arp`, `ndp`, `sysctl hw.sensors` | n/a | yes |
| `pfctl` (`/dev/pf`) | 0600 root | only with `-enable pf` + doas rules |
| ntpd control socket | 0660 root | only with `-enable ntp` + doas rules |
| unbound control socket | 0660, full control | only with `-enable unbound` + doas rules |
| bgpd restricted socket | 0666, show-only | with `-enable bgp`, once bgpd.conf creates it |
| `/var/log/*`, `/var/cron/log`, `/var/www/logs/*` | 0600-0644 | only with `-enable logs` + doas rules |
| ospfd, ospf6d, relayd, smtpd, vmd, unwind, iked sockets; PF_KEY | root / full control | only with the daemon's feature + doas rules |
| `/etc/pf.conf` | 0600 | no, unless you grant group read |
| `/etc/hostname.*` | 0640 | no (may contain keys) |
| `/etc/rc.conf.local`, `hosts`, `resolv.conf`, `sshd_config` | 0644 | yes |

`docs/ARCHITECTURE.md` has the full design, the sandbox policy and the
privilege notes.

## Development

```sh
go test ./...                          # unit tests, any OS
go run ./cmd/obsd-mcp -print-policy    # inspect the sandbox policy
```

The OpenBSD-only integration test applies the real sandbox in a child process.
It checks that allowed operations work, that reads of secret files and execs
of non-allowlisted binaries fail, and that writes, sockets and further
`unveil` calls are killed by `pledge`:

```sh
go test ./internal/sandbox -run Sandbox -v    # on OpenBSD, as a non-root user

# after host setup, also run every opt-in view inside the sandbox:
OBSDMCP_TEST_FEATURES=pf,unbound,bgp,ntp,services,confcheck,logs go test ./internal/sandbox -run Sandbox -v
```

### Releases and versioning

`.github/workflows/release.yml` runs on every push to `main`, on pull
requests and on version tags. It runs the Linux tests, cross-compiles the
server and its test binaries for amd64 and arm64, then boots an OpenBSD VM
for each architecture. In the VM it runs every test, including the real
`pledge`/`unveil` sandbox tests. It then installs the `-print-doas` rules
for `pf`, `confcheck`, `logs`, `ntp` and `smtpd` (when running) and, on
amd64, `services`. It also starts unwind, iked, ospfd, ospf6d and relayd
with minimal configs and adds each feature whose daemon came up. It then
runs every view of those features inside the sandbox through doas. It
appends the `-print-sshd` block to a copy of `sshd_config`, checks it with
`sshd -t` and confirms with `sshd -T` that only the server user is pinned.
Finally it builds the package with `pkg_create`. The Linux job also runs
`govulncheck` for Linux and both OpenBSD targets, and Dependabot opens
weekly PRs for the Go module and the pinned actions.

Versions follow [semantic versioning](https://semver.org) and come from git
tags (`scripts/version.sh`):

| Build | Version | Package | Published as |
|---|---|---|---|
| tag `v1.2.0` | `1.2.0` | `obsd-mcp-1.2.0-<arch>.tgz` | release `v1.2.0` |
| tag `v1.3.0-rc.1` (also `-alpha.N`, `-beta.N`) | `1.3.0-rc.1` | `obsd-mcp-1.3.0rc1-<arch>.tgz` | prerelease `v1.3.0-rc.1` |
| push to `main`, 4 commits after `v1.2.0` | `1.2.1-dev.4+g<sha>` | `obsd-mcp-1.2.1pre4-<arch>.tgz` | the rolling `dev` prerelease, replaced on each push |
| pull request | as for `main` | built, not published | nothing |

To cut a release, tag a commit that is on `main` and push the tag:

```sh
git tag -a v0.1.0 -m "obsd-mcp 0.1.0"
git push origin v0.1.0
```

Tags that are not `vMAJOR.MINOR.PATCH[-(alpha|beta|rc).N]`, or that point
outside `main`, fail the workflow. OpenBSD sorts `pre` and `rc` versions
before the plain version, so `pkg_add -u` upgrades from a dev or rc build to
the final release.

### Release signing

Tag builds sign `SHA256` with signify. The secret key lives only in the
`release` GitHub environment, which is limited to `v*` tags, so pull
requests and `main` builds cannot read it. The release job checks the new
signature against the committed `signify/obsd-mcp.pub` and fails if the two
keys do not match, or if either is missing.

One-time setup, on an OpenBSD host in a private directory. signify cannot
read a passphrase in CI, so the key is created without one (`-n`):

```sh
signify -G -n -c "obsd-mcp release key" -p obsd-mcp.pub -s obsd-mcp.sec

r=repos/caseyrobb/openbsd-mcp-server
echo '{"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}' |
    gh api -X PUT $r/environments/release --input -
gh api -X POST $r/environments/release/deployment-branch-policies -f name='v*' -f type=tag
gh secret set SIGNIFY_SECRET_KEY --env release < obsd-mcp.sec
```

Commit `obsd-mcp.pub` as `signify/obsd-mcp.pub`, then move `obsd-mcp.sec`
to offline storage. Rotating the key means a new key pair, a new secret and
a new committed public key; say so in the release notes.

### Layout

```
.github/workflows/   CI: test, govulncheck, OpenBSD VM tests, pkg_create packages, signed releases
.github/dependabot.yml  weekly Go module and action update PRs
signify/             release signing public key
scripts/             version.sh (tags -> semver), build.sh, vmtest.sh, mkpkg.sh
pkg/DESCR            package description
cmd/obsd-mcp/        entry point: refuse root, build policy, sandbox, serve stdio
internal/basecmd/    allowlist of runnable base binaries and their fixed argv
internal/execx/      no-shell runner: scrubbed env, timeout, bounded output
internal/sandbox/    unveil/pledge policy (portable) and Apply (OpenBSD only)
internal/collect/    system and network collectors (no MCP dependency)
internal/confread/   allowlisted config reader with path and file checks
internal/redact/     secret redaction
internal/audit/      syslog audit lines via sendsyslog(2), input sanitizing
internal/deploy/     -print-sshd: sshd_config Match block (text only, writes nothing)
internal/mcpserver/  MCP tool definitions (the only package using the SDK)
docs/                architecture and security notes
```

Contributions must keep to the rules in [`CLAUDE.md`](CLAUDE.md): read-only
only, base system only, no shell execution, and no widening of
`pledge`/`unveil` to make a feature work.

## License

[MIT](LICENSE)
