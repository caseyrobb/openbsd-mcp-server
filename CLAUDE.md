# CLAUDE.md — OpenBSD Read-Only MCP Server

## Project Purpose

Build a read-only Model Context Protocol (MCP) server for OpenBSD that exposes sanitized system state, configuration summaries, and diagnostic data from the **OpenBSD base system** to an AI agent without allowing system mutation, arbitrary shell execution, or secret leakage.

## Core Security & Design Principles

1. **Read-Only by Construction:** Every tool and resource must be strictly read-only. Never implement endpoints or tools that write files, modify firewall/network/service state, reload daemons, or execute arbitrary shell strings (`sh -c`, `eval`, or unvalidated command arguments).
2. **OpenBSD Base System Scope Only:** Scope all tools, collectors, binaries, and configuration readers strictly to utilities and files shipped in the **OpenBSD base system** (for example `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, and base `/etc` files). Do **not** target or depend on OpenBSD ports/packages (`/usr/local`, `/etc/pkg`, third-party daemons, or external package utilities).
3. **Least Privilege & Sandboxing:**
   - Designed to run as a dedicated non-privileged user (not `root`, not in `wheel`), with minimal or no `doas` privileges.
   - Use OpenBSD `unveil(2)` to restrict filesystem visibility strictly to allowed base paths/binaries, and lock it down (`unveil(NULL, NULL)`) before serving requests.
   - Use OpenBSD `pledge(2)` to drop unneeded syscall groups (`stdio`, `rpath`, `exec`, `inet`, etc. as narrowly as possible) once startup/initialization finishes.
4. **Secret & Sensitive Data Hygiene:**
   - Never expose private keys, TLS keys, password hashes (`/etc/master.passwd`), `.env` files, tokens, or credentials.
   - Canonicalize and validate all file paths (`realpath` / clean path checks) against an explicit allowlist before reading; reject path traversal (`..`), symlinks escaping allowed roots, and denylisted filenames/patterns.
   - Redact or exclude sensitive fields/lines in configuration or status outputs.
5. **Deterministic Command Execution:**
   - If invoking base-system read utilities (e.g., `sysctl`, `vmstat`, `df`, `ifconfig`, `netstat`, `pfctl`), use fixed argument arrays (`execve` style—no shell) with strict timeouts, bounded output sizes, and non-zero exit handling.

## Architecture & Conventions

- Keep MCP protocol handling cleanly separated from OpenBSD base-system collectors and path/secret sanitization logic.
- Follow current MCP specification conventions (tools, resources, clear schemas, explicit error responses rather than panics/crashes).
- Gate OpenBSD-specific `pledge` / `unveil` calls cleanly behind build tags or OS checks so unit tests can still run cleanly during development.
- Write unit tests for path allowlisting, traversal blocking, secret redaction, and output bounds—and include boundary tests verifying disallowed paths/commands are rejected.

## What Not to Do

- Do not add support, paths, or commands for **OpenBSD ports or packages** (`/usr/local`, third-party tools, or non-base services).
- Do not add "run arbitrary command" or "write config" tools, even as optional flags.
- Do not silence errors or widen `pledge` / `unveil` permissions just to make a feature work; diagnose the exact syscall or path needed.
- Do not log raw secrets, full sensitive config dumps, or untrusted inputs without sanitization.
