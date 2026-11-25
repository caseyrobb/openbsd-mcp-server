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
| `network_summary` | `ifconfig` (redacted), `netstat -rn`, and `pfctl -s info` if enabled with `-pf-doas` |
| `config_read` | One allowlisted file from `/etc`, redacted. The allowed paths are listed in the tool's input schema. |

The `config_read` allowlist is `/etc/rc.conf.local`, `pf.conf`, `sysctl.conf`,
`hosts`, `resolv.conf`, `myname`, `mygate`, `ntpd.conf`, `syslog.conf`,
`fstab`, `httpd.conf`, `ssh/sshd_config` and `/etc/hostname.<if>`.

All tools are annotated `readOnlyHint: true`. If one command fails, only that
section reports an error and the rest of the result is still returned.

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

### Optional: PF status

`/dev/pf` is root-only, so `pfctl -s info` needs `doas`. Add this
exact-arguments rule to `/etc/doas.conf`:

```
permit nopass obsdmcp as root cmd /sbin/pfctl args -s info
```

Then change the forced command to `/usr/local/libexec/obsd-mcp -pf-doas`.
Without the flag, `doas` is not unveiled and `pfctl` is never run.

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
| `-pf-doas` | Enable `pfctl -s info` via `doas -n` (requires the rule above) |
| `-print-policy` | Print the exact `unveil`/`pledge` calls and exit |
| `-unsafe-dev` | Run without a sandbox on non-OpenBSD systems, for development only |

## Privileges and file modes

The server runs unprivileged, so some files and data are unreadable by
default. The server reports this clearly instead of failing silently.

| Resource | Default | Readable? |
|---|---|---|
| sysctl values used, `ifconfig`, `netstat -rn`, `df`, `vmstat` | n/a | yes |
| `pfctl` (`/dev/pf`) | 0600 root | only with `-pf-doas` |
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
