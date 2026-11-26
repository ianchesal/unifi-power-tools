# unifi-power-tools: merging the sink, the MCP server and lens

**Date:** 2026-11-26
**Status:** design, awaiting approval

## Intent

Three repos — `unifi-siem-sink` (syslog/CEF ingest into `events.db`, 4
read-only MCP tools), `unifi-mcp-server` (UniFi Network API as MCP tools,
reads and writes) and `unifi-siem-lens` (this repo: analysis, triage queue,
playbook, dashboard) — now change and ship in lockstep. Keeping them apart
costs code and process that exists only to cope with the split:

- lens opens the sink's DB read-only through a borrowed Docker volume
  (`volumes_from: container:unifi-siem-sink-unifi-siem-sink-1:ro`), checks
  its columns at boot (`EXPECTED_COLUMNS`/`verifySchema`), boots degraded when
  it's missing, and keeps an "old-sink isolation rule" so it survives a
  pre-v1.0.3 sink;
- lens enriches findings by calling `unifi-mcp-server` over MCP
  (`enrichment/unifiMcpClient.ts`, `UNIFI_MCP_SERVER_URL`/`_TOKEN`) with
  null-on-failure handling for when that hop is down;
- three versions, three images, three release runs, three `/mcp` endpoints
  and secrets in every Claude Code config.

Fold all three into this repo as one service, renamed **unifi-power-tools**.
Archive the other two repos with a pointer here.

## Goals

- One repo, one version, one image, **one process**, one `/mcp` endpoint
  carrying every tool.
- Remove the code that exists only because of the split (list above).
- Add password authentication to the dashboard and REST API, because the
  UniFi API key now lives in the same process.
- UniFi **write** tools are off unless explicitly enabled.
- Existing deployments keep their data: `events.db` and `lens.db` are reused
  as they are.

## Non-goals

- No change to analysis behaviour: heuristics, rules, findings lifecycle,
  playbook and verdict guardrails stay as they are, apart from wiring.
- No new UniFi API coverage, no new sink parsing.
- No git history from the other two repos. Their code moves in as ordinary
  new files ("normalized"), no `vendor/` or subtree.
- No multi-user auth, roles, SSO or forward-auth integration. One password,
  can grow later.
- No merging of `events.db` and `lens.db` into one file.

## Anti-goals (failure even if it works)

- The service reachable from the public internet. It's a LAN tool behind the
  operator's NPM reverse proxy; the README says so in plain words.
- A triage session able to change the network by default. Triage reads
  attacker-influenced text (IPS signatures, hostnames, payload fields); with
  one `/mcp`, write tools would sit next to it. Off by default is the guard.
- Analysis work able to crash ingest. One process means a throw in an
  analysis job kills syslog capture; every scheduled job keeps its own
  try/catch (as `runCheck`/`runChecksSafely` already do), and the syslog
  listener's per-message handling never throws out of its handler.
- Lens's existing tests weakened to make the move pass.

## Constraints

- Node ≥ 24 (the MCP server's floor; Docker base is already `node:24-alpine`).
  Raise `engines` in the server package.
- `node:sqlite` only, no native SQLite dependency.
- Same stack as today: Express 5, MCP SDK, zod, biome (server), oxlint (web),
  vitest. All three already use these.
- Public repo: no real addresses, hostnames or site data in code, tests or
  docs (existing RFC 5737 test rule applies to everything moved in).
- `/mcp` keeps `Authorization: Bearer <MCP_SECRET>`.

## Approaches considered

1. **Fold into lens's existing `server/` + `web/` layout** — chosen. Moved
   code becomes folders under `server/src`. Boundaries are kept by folder,
   not enforced; fine at ~8k lines, and it actually removes the "separate
   things" structure the merge is for.
2. **Per-component workspaces** (`packages/ingest`, `packages/unifi`,
   `packages/lens`, `web`, plus an app package). Enforced boundaries, easy to
   split again, but four package/tsconfig sets to keep in step and much of
   the separation the merge is meant to remove. Rejected.

Databases: **keep `events.db` and `lens.db` as two files** — chosen. Existing
volumes work with no data migration, the sink's retention purge and write
volume stay away from findings, and lens state can be wiped without losing
events. One merged file was rejected: a one-time, restart-safe copy on first
boot for little gain.

Process layout: one process was chosen over one image running two processes
(ingest separate). **Known shortcoming, documented in the README:** syslog is
UDP and the UDM doesn't retry, so events sent while the service restarts
(deploys, crashes) are lost. High-fidelity capture isn't required.

## Design

### Layout

```
server/src/
  index.ts            one entrypoint: config, DBs, syslog listener, timers, HTTP
  server.ts           Express app: auth, /api, /mcp, /health, /ready, static
  config.ts           one loadConfig for every env var below
  logger.ts           one logger (lens's)
  ingest/             from sink: syslog/listener.ts, parser/{cef,envelope,normalize,index}.ts
  db/
    eventsDb.ts       from sink storage/db.ts: migrations, WAL, purgeOldEvents,
                      reparseClientEvents (migration 3 helper)
    eventQueries.ts   sink storage/queries.ts and lens sinkQueries.ts, deduplicated
    lensDb.ts, *Store.ts   unchanged
  unifi/
    client.ts         from mcp-server unifi/client.ts
    tools/            from mcp-server tools/*
  analysis/           unchanged apart from imports
  enrichment/         unifiMcpClient.ts replaced by a direct-call enricher over unifi/client.ts
  mcp/
    server.ts         builds the one McpServer per request
    eventTools.ts     from sink tools/events.ts
    tools.ts, playbookTools.ts, context.ts, playbook/   unchanged apart from wiring
  api/                unchanged routers + new auth.ts
```

Two CIDR helpers exist (sink `storage/cidr.ts`, lens `analysis/cidr.ts`):
keep one. The sink's `logger.ts` and the MCP server's go away. Tests move to
the mirrored paths under `server/tests/` (sink fixtures into
`server/tests/fixtures/`), adjusted only for imports and the renamed modules.

### Databases

- `events.db` (`EVENTS_DB_PATH`) is opened **read-write** by `db/eventsDb.ts`
  with the sink's migration array, applied at boot exactly as the sink does
  today (WAL, `schema_migrations`). Existing sink DBs are already at
  migration 4, so nothing re-runs.
- The read-only `openSinkDb`, `verifySchema`, `EXPECTED_COLUMNS`, the
  `sinkDb: 'available' | 'unavailable'` health fields, every `sinkDb | null`
  and `runnerDeps | null` degraded-mode branch, and the "old-sink isolation
  rule" in `sinkQueries.ts` are deleted. The events DB is created if absent,
  so "missing sink DB" can't happen; if it fails to open, the process exits.
- Analysis keeps reading events through the same query functions; use a
  single shared `DatabaseSync` connection for events (ingest writes, analysis
  and API read; `node:sqlite` is synchronous so there is no interleaving
  inside a query).
- `lens.db` (`LENS_DB_PATH`) unchanged. The table/variable naming "sink" in
  lens code becomes "events" (`SinkDb` → `EventsDb`, `sinkQueries` →
  `eventQueries`); the `lens` names for findings/playbook stay — "lens" is now
  the analysis layer's name inside unifi-power-tools.
- The hourly retention purge (`RETENTION_DAYS`, default 90) moves into
  `index.ts` alongside the other timers, in its own try/catch.

### MCP: one `/mcp`

One `McpServer` per request (stateless, as all three do now), name
`unifi-power-tools`, registering:

| Group | Tools | Notes |
|---|---|---|
| Events (from sink) | `list_events`, `get_event`, `get_categories`, `get_event_stats` | read-only |
| UniFi reads | `list_*`, `get_*` from mcp-server (clients, firewall, policies, networks, ports, traffic, monitoring, security) | registered only when UniFi is configured |
| UniFi writes | every `create_*`, `update_*`, `delete_*`, `block_client`, `unblock_client`, `set_client_fixed_ip`, `remove_client_fixed_ip` | registered only when UniFi is configured **and** `UNIFI_ALLOW_WRITES=true` |
| Analysis | `get_pending_analyses`, `get_analysis_context`, `submit_analysis`, `get_feedback`, `mark_feedback_considered` | unchanged |
| Playbook | `get_playbook`, `list_playbook_proposals`, `propose_playbook_change`, `import_knowledge` prompt, `triage` prompt | unchanged |

- Writes off means the tools are **not registered**, so a session never sees
  them (better than registered-and-refusing). Each UniFi tool module declares
  which of its tools are writes; registration filters on that, not on name
  prefixes. A test asserts that with writes off, no write tool is listed, and
  that the write list covers every non-read tool in `unifi/tools/`.
- The `instructions` string and the playbook core (`mcp/playbook/core.ts`)
  gain one generic line: triage never calls UniFi write tools, even when they
  are present; recommendations go in `recommended_action` for the operator.
- The existing "playbook names an unregistered tool" test must pass with
  writes off and UniFi unconfigured (the playbook may name only always-on
  tools).
- A test asserts tool names are unique across groups (none collide today).
- The triage prompt's slash command becomes
  `/mcp__unifi-power-tools__triage` (follows from the server name; README and
  the `triage` skill text updated).

### Enrichment

`enrichment/unifiMcpClient.ts` (an MCP client to a second server) is replaced
by an enricher calling `unifi/client.ts` directly, doing what the MCP calls
did (`get_client` by IP → name/network; `list_firewall_rules`). Keep the
existing contract: if UniFi isn't configured it's a no-op, and any API error
resolves to `null` rather than throwing, so enrichment never blocks building
an analysis context.

### UniFi configuration

`UNIFI_HOST` and `UNIFI_API_KEY` become **optional** (they're required today
in the MCP server). Both set → UniFi client created, read tools registered,
enrichment on. Neither set → no UniFi tools, no enrichment, `/ready` reports
UniFi as `not_configured`. Only one set → fail fast at startup.

### Dashboard authentication

- `DASHBOARD_PASSWORD` env var, **required** (startup fails without it, like
  `MCP_SECRET`). It must differ from `MCP_SECRET`; startup fails if equal.
- `POST /api/auth/login` with JSON `{ password }`: constant-time comparison
  (`crypto.timingSafeEqual` over SHA-256 digests, so lengths match). Success
  sets a session cookie; failure is a 401 with no detail. A dedicated rate
  limit on this route (e.g. 10 attempts per 15 minutes per IP) on top of the
  global limiter.
- Session cookie: `HttpOnly`, `SameSite=Strict`, `Path=/`, a 30-day expiry,
  `Secure` when the request arrived over HTTPS (Express `trust proxy` set so
  NPM's `X-Forwarded-Proto` counts). Value is a stateless signed token
  (expiry + HMAC-SHA256), keyed from a secret derived from
  `DASHBOARD_PASSWORD`, so sessions survive restarts and changing the
  password logs everyone out. No session table.
- `POST /api/auth/logout` clears the cookie. `GET /api/auth/session` returns
  200/401 so the SPA can decide what to render.
- An auth middleware guards **all of `/api/*`** except `/api/auth/*`.
  `/mcp` keeps its bearer check and ignores cookies. `/health` stays open
  (Docker healthcheck) and reveals only status fields, no data. `/ready` is
  open too and reports component state only. The static SPA bundle is served
  without auth (it holds no data); every data call goes through `/api`.
- Cross-site requests: `SameSite=Strict` keeps the cookie off cross-site
  requests; additionally every state-changing `/api` route requires
  `Content-Type: application/json` (the playbook routes already require a
  JSON body; extend that to `POST /api/analysis/run`,
  `/api/admin/backfill-rule-triage` and the findings/analysis routes), so a
  plain HTML form can't trigger one.
- Web: a login screen (one password field, submit, error message) shown when
  `GET /api/auth/session` or any API call returns 401; a "Sign out" control
  in the header. `api.ts` handles 401 centrally.

### Health and readiness

- `GET /health` (liveness, no network calls): `{ status, syslog: { bound,
  droppedMessages }, eventsDb: 'ok' }`.
- `GET /ready`: adds UniFi reachability (`stat/sysinfo`, as the MCP server's
  `/ready` does today): `ok | unavailable | not_configured`. UniFi being down
  doesn't make the service unready for ingest; report it, return 200 unless
  the events DB or listener is down.

### Configuration (every env var)

| Variable | Default | From | Notes |
|---|---|---|---|
| `PORT` | `3002` | lens | HTTP: dashboard, `/api`, `/mcp`, `/health` |
| `HOST` | `127.0.0.1` (image sets `0.0.0.0`) | lens | |
| `LOG_LEVEL` | `info` | all | |
| `MCP_SECRET` | required | all | one secret now |
| `DASHBOARD_PASSWORD` | required | new | |
| `EVENTS_DB_PATH` | `./data/events.db` | sink `DB_PATH`, lens `SINK_DB_PATH` | |
| `LENS_DB_PATH` | `./data/lens.db` | lens | |
| `RETENTION_DAYS` | `90` | sink | |
| `SYSLOG_UDP_PORT` | `10514` | sink | |
| `SYSLOG_BIND_ADDRESS` | `0.0.0.0` | sink | |
| `MAX_MESSAGE_BYTES` | `16384` | sink | |
| `UNIFI_HOST`, `UNIFI_API_KEY` | unset | mcp-server | optional, both or neither |
| `UNIFI_SITE` | `default` | mcp-server | |
| `UNIFI_VERIFY_TLS` | `false` | mcp-server | |
| `UNIFI_REQUEST_TIMEOUT_MS` | `10000` | mcp-server | |
| `UNIFI_ALLOW_WRITES` | `false` | new | only the literal `true` enables |
| `LAN_CIDRS`, `TRUSTED_ADMIN_NAMES`, `SAFE_SIGNATURE_PREFIXES`, `HOMELAB_SERVICES_PATH` | as today | lens | |

Removed: `SINK_DB_PATH`, `DB_PATH`, `MCP_PORT`, `MCP_HOST`,
`UNIFI_MCP_SERVER_URL`, `UNIFI_MCP_SERVER_TOKEN`. Startup fails with a clear
message naming the replacement if any removed variable is set, so a stale
`.env` can't silently half-work. Add a `.env.example` (this repo has none).

### Rename

- npm packages: `unifi-power-tools` (root), `unifi-power-tools-server`,
  `unifi-power-tools-web`. Image `ghcr.io/ianchesal/unifi-power-tools`.
  Logger/startup banner, MCP server name, enrichment client name, dashboard
  title, Docker user/group names.
- Version **2.0.0**: env vars, MCP server name, ports and compose all change.
- GitHub repo renamed `unifi-siem-lens` → `unifi-power-tools` (GitHub keeps
  redirects). Done by Ian in the GitHub UI or with `gh repo rename`, after the
  merge PR lands.
- CLAUDE.md, README, docs/specs references updated; older specs keep their
  content but get a one-line note at the top pointing to this one where they
  describe the split (read-only sink DB, enrichment over MCP).

### Docker and deploy

- One `Dockerfile` (lens's, extended): exposes `3002/tcp` and `10514/udp`,
  one data dir `/data` holding `events.db` and `lens.db`, env defaults
  `EVENTS_DB_PATH=/data/events.db`, `LENS_DB_PATH=/data/lens.db`,
  `HOST=0.0.0.0`.
- `docker-compose.yml`: one service `unifi-power-tools`, ports
  `3002:3002` and `5514:10514/udp` (the sink's current host port, so the UDM
  SIEM setting doesn't change), one volume `data:/data`, `proxy` network
  kept, no `volumes_from`, watchtower label kept.
- **Migration from the three containers**, documented in the README as a
  one-time procedure: stop the sink cleanly (so WAL is checkpointed), copy
  `events.db` (plus any `-wal`/`-shm` left behind) from the sink's volume and
  `lens.db` from lens's volume into the new `data` volume, start the new
  service, verify `/health` and that events arrive, then remove the old
  containers. Re-point the NPM proxy host at the new container and the Claude
  Code MCP config at the one `/mcp`. The exact `docker run --rm -v …` copy
  commands are the builder's to write and test.

### Archiving the old repos

For each of `unifi-siem-sink` and `unifi-mcp-server`, after the merged
service is released: a final commit replacing the README with a short notice
("merged into unifi-power-tools", full URL to the new repo, the version it
was merged at), then archive the repo on GitHub. Existing ghcr images stay
published, untouched. These steps are outward-facing and done only with
Ian's go-ahead at that point.

### CI and release

One `ci.yml` (build, lint, test for both workspaces) and one `release.yml`
(the existing lens release flow, image name changed). The release process
in memory still applies: bump PR, Ian merges, tag; never `npm version`.

## Left to the builder

- Order of the moves and how to split them into PRs (a sensible order:
  move ingest + events DB and delete degraded mode → move UniFi client/tools
  and the write gate → replace enrichment → auth → rename/Docker/docs).
- Exact module boundaries inside `server/src/unifi/` and `ingest/`, and how
  the two query modules are deduplicated.
- Login screen look (match the dashboard's existing style).
- The migration commands, tested against copies of real volumes.

## Calls I made (for Ian to check)

- `DASHBOARD_PASSWORD` required, and must differ from `MCP_SECRET`.
- Stateless signed session cookie (30 days, survives restarts) rather than
  server-side sessions.
- `/health` and `/ready` unauthenticated; SPA bundle unauthenticated, all
  data behind `/api` auth.
- UniFi optional (both vars or neither); write tools unregistered, not just
  refused.
- Keep port `3002` for HTTP and host port `5514/udp` for syslog, so NPM and
  the UDM settings need the least change.
- Version jumps to 2.0.0; one `/data` volume holding both DB files.
- Old env vars rejected at startup with a pointer to the new name.
