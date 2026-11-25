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
  `doas` unless you opt in to PF status.

The server speaks MCP over **stdio**. For remote use, sshd starts it with a
forced command, so the server itself never opens a socket.

## Tools

| Tool | What it returns |
|---|---|
| `system_overview` | `uname -a`, `uptime`, selected `kern.*`/`hw.*`/`vm.*` sysctl values, `df -h`, `vmstat` |
| `network_summary` | `ifconfig` (redacted), `netstat -rn` |
| `config_read` | One allowlisted file from `/etc`, redacted. The allowed paths are listed in the tool's input schema. |
| `pf_status` | **Opt-in** (`-enable pf`). One `pfctl -s` view: `info`, `rules`, `tables`, `memory`, `timeouts`, `interfaces`, `queues` |
| `unbound_status` | **Opt-in** (`-enable unbound`). One `unbound-control` view: `status`, `stats` (`stats_noreset`), `forwards`, `stubs`, `local_zones`, `auth_zones`, `insecure` |
| `bgp_status` | **Opt-in** (`-enable bgp`). One `bgpctl show` view: `summary`, `neighbors`, `nexthops`, `interfaces`, `rib_memory` |

The `config_read` allowlist is `/etc/rc.conf.local`, `pf.conf`, `sysctl.conf`,
`hosts`, `resolv.conf`, `myname`, `mygate`, `ntpd.conf`, `syslog.conf`,
`fstab`, `httpd.conf`, `ssh/sshd_config` and `/etc/hostname.<if>`.

All tools are annotated `readOnlyHint: true`. If one command fails in
`system_overview` or `network_summary`, only that section reports an error and
the rest of the result is still returned. The `*_status` tools take a single
`view` from a fixed enum, run exactly one fixed command, and return its
redacted output plus the command line that ran. Opt-in tools are registered
only when their feature is enabled.

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

Create a dedicated unprivileged user. Do **not** add it to `wheel`.

```sh
doas useradd -m -s /bin/ksh -c "read-only MCP" obsdmcp
doas install -o root -g bin -m 0555 obsd-mcp /usr/local/libexec/obsd-mcp
```

Any root-owned location that the `obsdmcp` user cannot write to will do. The
server never reads or runs anything under `/usr/local`; this is only where its
own binary lives.

Restrict the user's SSH key to the server in `~obsdmcp/.ssh/authorized_keys`:

```
restrict,command="/usr/local/libexec/obsd-mcp" ssh-ed25519 AAAA... agent-key
```

The user needs a real login shell, because sshd runs forced commands through
`$SHELL -c`.

### Optional: pf, unbound and bgpd

These subsystems are off by default. Turn them on with `-enable` in the
forced command, for example:

```
restrict,command="/usr/local/libexec/obsd-mcp -enable pf,unbound,bgp" ssh-ed25519 AAAA... agent-key
```

| Feature | Runs | Access | Host setup |
|---|---|---|---|
| `pf` | `/sbin/pfctl -s <view>` | `doas -n` (`/dev/pf` is 0600 root) | doas rules |
| `unbound` | `/usr/sbin/unbound-control <verb>` | `doas -n` (the control socket allows reload, flush and stop, so the server user must not have it) | doas rules; unbound running with `remote-control` enabled (the default `/etc/unbound.conf` does this) |
| `bgp` | `/usr/sbin/bgpctl -s /var/run/bgpd.rsock show <view>` | unprivileged, through bgpd's **restricted** socket, which only accepts `show` requests | add `socket "/var/run/bgpd.rsock" restricted` to `/etc/bgpd.conf`, then `doas bgpctl reload` |

Generate the exact `doas.conf` rules from the server itself, so they always
match what it runs:

```sh
/usr/local/libexec/obsd-mcp -enable pf,unbound -print-doas obsdmcp | doas tee -a /etc/doas.conf
doas doas -C /etc/doas.conf    # syntax check
```

Each rule pins the full argument list, for example
`permit nopass obsdmcp as root cmd /sbin/pfctl args -s rules`, so doas refuses
any other arguments. `unbound`'s statistics view uses `stats_noreset`: plain
`stats` resets the counters and is never run.

`doas` and `bgpctl` are unveiled only when a feature that needs them is
enabled. `pfctl` and `unbound-control` are never executable by the server
directly, only through `doas`.

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
| `-enable pf,unbound,bgp` | Enable the opt-in `*_status` tools (see above) |
| `-print-doas USER` | Print the `doas.conf` rules USER needs for `-enable`, then exit |
| `-print-policy` | Print the exact `unveil`/`pledge` calls and exit |
| `-unsafe-dev` | Run without a sandbox on non-OpenBSD systems, for development only |

## Privileges and file modes

The server runs unprivileged, so some files and data are unreadable by
default. The server reports this clearly instead of failing silently.

| Resource | Default | Readable? |
|---|---|---|
| sysctl values used, `ifconfig`, `netstat -rn`, `df`, `vmstat` | n/a | yes |
| `pfctl` (`/dev/pf`) | 0600 root | only with `-enable pf` + doas rules |
| unbound control socket | 0660, full control | only with `-enable unbound` + doas rules |
| bgpd restricted socket | 0666, show-only | with `-enable bgp`, once bgpd.conf creates it |
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

# after host setup, also run every pf/unbound/bgp view inside the sandbox:
OBSDMCP_TEST_FEATURES=pf,unbound,bgp go test ./internal/sandbox -run Sandbox -v
```

### Layout

```
cmd/obsd-mcp/        entry point: refuse root, build policy, sandbox, serve stdio
internal/basecmd/    allowlist of runnable base binaries and their fixed argv
internal/execx/      no-shell runner: scrubbed env, timeout, bounded output
internal/sandbox/    unveil/pledge policy (portable) and Apply (OpenBSD only)
internal/collect/    system and network collectors (no MCP dependency)
internal/confread/   allowlisted config reader with path and file checks
internal/redact/     secret redaction
internal/mcpserver/  MCP tool definitions (the only package using the SDK)
docs/                architecture and security notes
```

Contributions must keep to the rules in [`CLAUDE.md`](CLAUDE.md): read-only
only, base system only, no shell execution, and no widening of
`pledge`/`unveil` to make a feature work.

## License

[MIT](LICENSE)
