# Security Policy

## Supported Versions

Only the latest release is supported with security fixes.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities privately via [GitHub's private vulnerability reporting](https://github.com/ianchesal/unifi-power-tools/security/advisories/new).

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce
- Any suggested remediation, if you have one

I'll acknowledge receipt within 7 days and aim to release a fix within 30 days for confirmed issues.

## Scope

This project runs on a private homelab network and is not intended for
public internet exposure. Never expose ports 3002 (HTTP) or 5514/10514 (UDP
syslog) to the internet.

- **Dashboard and REST API:** one shared password (`DASHBOARD_PASSWORD`), a
  signed `HttpOnly`, `SameSite=Strict` session cookie, a rate limit on failed
  logins, and JSON-only writes. It is a single-user LAN gate, not
  multi-user access control.
- **`/mcp`:** `Authorization: Bearer <MCP_SECRET>`, compared in constant
  time. Protect `MCP_SECRET`: with `UNIFI_ALLOW_WRITES=true` it gates changes
  to your network's firewall, clients and port forwards.
- **UniFi write tools** are off by default, because triage sessions read
  attacker-influenced event text (prompt-injection risk).
- **Syslog** is unauthenticated UDP, as UniFi sends it: anything that can
  reach the port can inject events. Keep it on your LAN.
- The server binds to `127.0.0.1` by default (the Docker image binds
  `0.0.0.0`; control exposure with how ports are published). Only widen it
  deliberately.
