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
  try/catch (as `runCheck`/`runChecksSafely` already do), the syslog
  listener's per-message handling never throws out of its handler, and
  `index.ts` installs a logging `process.on('unhandledRejection')` handler
  that does not exit (async `/mcp` and UniFi paths must not kill ingest).
- Lens's existing tests weakened to make the move pass. Tests deleted along
  with the code they cover are not weakening (listed under "Tests" below).

## Constraints

- Node ≥ 24 (the MCP server's floor; Docker base is already `node:24-alpine`).
  Raise `engines` in the server package.
- `node:sqlite` only, no native SQLite dependency.
- Same stack as today: Express 5, MCP SDK, zod, biome (server), oxlint (web),
  vitest. All three already use these. One added server dependency:
  `undici`, which `unifi/client.ts` uses for its TLS-skip `Agent`.
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
UDP and the UDM doesn't retry, so events can be lost (a) while the service
restarts (deploys, crashes) and (b) while a long synchronous analysis run
(hourly checks, daily anomaly + recheck, a dashboard-triggered run) blocks the
event loop long enough for the kernel's UDP receive buffer to fill. Loss of
kind (b) is not counted by `droppedMessages` (that counts only oversized
messages). High-fidelity capture isn't required. Cheap mitigations that are
in scope: bind the syslog listener **before** the boot-time
`runChecksSafely()` / `runDailyCheckSafely()` calls (today they run before
anything listens), and set a larger `recvBufferSize` on the dgram socket.
The builder measures hourly and daily run times against a real-sized
`events.db` and puts the numbers in the README next to the shortcoming.

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
  today (WAL, `schema_migrations`). A DB from an older sink catches up at
  first boot (migration 3, `reparseClientEvents`, is safe to re-run).
- The read-only `openSinkDb`, `verifySchema`, `EXPECTED_COLUMNS`, the
  `sinkDb: 'available' | 'unavailable'` health fields, every `sinkDb | null`
  and `runnerDeps | null` degraded-mode branch, and the "old-sink isolation
  rule" in `sinkQueries.ts` are deleted. The events DB is created if absent,
  so "missing sink DB" can't happen; if it fails to open, the process exits.
- Two connections to `events.db`: one **read-write** used only by ingest
  and the retention purge, and one **read-only**
  (`new DatabaseSync(path, { readOnly: true })`, opened after migrations)
  for analysis, `/api` and `/mcp`. This keeps today's guarantee that code
  handling attacker-influenced text can't write events; in WAL mode the
  reader costs almost nothing and sees committed writes.
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
  them (better than registered-and-refusing). Every UniFi tool declares
  `readOnly: true | false` explicitly, emitted as the MCP `readOnlyHint` /
  `destructiveHint` annotations so clients see it too; registration filters
  on that declaration. Tests: (1) every UniFi tool has an explicit
  declaration; (2) backstop — every tool whose name matches
  `create_|update_|delete_|block_|unblock_|set_|remove_` (22 of 37 today) is
  declared a write; (3) with writes off, no write tool is listed.
- The `instructions` string and the playbook core (`mcp/playbook/core.ts`)
  gain one generic line: triage never calls UniFi write tools, even when they
  are present; recommendations go in `recommended_action` for the operator.
- Playbook tool names: core step 2.2 today says "the `unifi` MCP server's
  `list_clients`", and the test exempts it by hand
  (`named.delete('list_clients')` in `tests/mcp/server.test.ts`). Reword the
  step to "this server's `list_clients`, available when UniFi is
  configured". Replace the hand exemption with a named constant of tools that
  exist only when UniFi is configured. Run the test twice: UniFi off (every
  named always-on tool must be registered) and UniFi stubbed (every named
  tool must be registered).
- A test asserts tool names are unique across groups (none collide today).
- Slash command: Claude Code builds `/mcp__<key>__triage` from the server's
  key in the client config, not from the `McpServer` name. Rename the key in
  `.mcp.json.example` to `unifi-power-tools`, and the README's migration
  step tells the operator to rename their own config entry, which makes the
  command `/mcp__unifi-power-tools__triage`.

### Enrichment

`enrichment/unifiMcpClient.ts` (an MCP client to a second server) is replaced
by an enricher calling `unifi/client.ts` directly.

**The old client-name lookup never worked:** it called `get_client` with
`{ ip }`, but that tool takes `{ mac }` and searches only online clients
(`stat/sta`), so argument validation failed, the parse threw, the catch
returned null, and `knownClient` has always been null. Don't port it; define
it:

- `resolveClient(ip)`: fetch `stat/alluser` (online and offline clients),
  find the client whose `ip` or `last_ip` equals `ip`, return
  `{ name: name ?? hostname, network: network ?? 'unknown' }`, or null if
  none matches or neither name nor hostname is set.
- `getFirewallSummary()`: the `list_firewall_rules` result as JSON text,
  capped at 8 KB (truncated with a marker), since it goes into an LLM
  context bundle.
- Contract kept: no UniFi configured → no-op returning null; any API error
  resolves to null rather than throwing, so enrichment never blocks building
  an analysis context.
- Tests with a stubbed `IUnifiClient` prove a name actually comes back
  (match on `ip`, match on `last_ip`, hostname fallback, no match, API error).

### UniFi configuration

`UNIFI_HOST` and `UNIFI_API_KEY` become **optional** (they're required today
in the MCP server). Both set → UniFi client created, read tools registered,
enrichment on. Neither set → no UniFi tools, no enrichment, `/ready` reports
UniFi as `not_configured`. Only one set → fail fast at startup.

### Dashboard authentication

Why: the UniFi API key now lives in this process, and independently, an
unauthenticated LAN user can already accept playbook proposals, which make
`close` verdicts operator-backed. **No release is cut between moving the
UniFi client in and auth landing.**

- `DASHBOARD_PASSWORD` env var, **required** (startup fails without it, like
  `MCP_SECRET`). It must differ from `MCP_SECRET`; startup fails if equal.
- `POST /api/auth/login` with JSON `{ password }`: constant-time comparison
  (`crypto.timingSafeEqual` over both inputs padded to equal length, lengths compared separately; no hashing, which CodeQL flags as weak password hashing). Success
  sets a session cookie; failure is a 401 with no detail. A dedicated rate
  limit on this route (e.g. 10 attempts per 15 minutes per IP) on top of the
  global limiter.
- Session cookie: `HttpOnly`, `SameSite=Strict`, `Path=/`, a 30-day expiry,
  `Secure` when `req.secure` is true. Value is a stateless signed token
  (expiry + HMAC-SHA256). The HMAC key is
  `scrypt(DASHBOARD_PASSWORD, sessionSecret)` (originally HMAC over SHA-256; changed to scrypt after CodeQL review so lens.db plus a cookie can't be brute-forced at hash speed), where `sessionSecret`
  is 32 random bytes generated on first boot and stored in `lens.db` (a new
  migration adding a small `meta` key/value table). Sessions survive
  restarts, changing the password logs everyone out, and a captured cookie
  can't be used to guess the password offline (the key isn't derivable from
  the password alone). No session table.
- `trust proxy`: **off by default.** A new optional `TRUST_PROXY` env var is
  passed to Express's `trust proxy` setting verbatim (e.g. NPM's address on
  the `proxy` network). Never `true`: port 3002 stays published on the host,
  so a client bypassing NPM could forge `X-Forwarded-For` to dodge the
  per-IP login limit (express-rate-limit v8 also rejects `true` as
  `ERR_ERL_PERMISSIVE_TRUST_PROXY`). With it unset, the login limit keys on
  the immediate peer (all NPM traffic shares one bucket, acceptable for a
  single user) and `Secure` is off (LAN HTTP). The README says to set it to
  NPM's address when NPM terminates TLS.
- `POST /api/auth/logout` clears the cookie. `GET /api/auth/session` returns
  200/401 so the SPA can decide what to render.
- An auth middleware guards **all of `/api/*`** except `/api/auth/*`.
  `/mcp` keeps its bearer check and ignores cookies. The bearer comparison
  moves to the same constant-time helper as the password (padded
  `timingSafeEqual`); with `UNIFI_ALLOW_WRITES=true` that secret
  gates firewall changes. `/health` stays open
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

- Startup: a syslog bind failure (port in use) or an events DB open failure
  exits the process with a clear log line. Both are fatal by design.
- The listener exposes `bound()`: true once bound, false after a socket
  `error` or `close` event (the post-bind error handler still swallows, but
  records the state and logs once).
- `GET /health` (liveness, no network calls): `{ status, syslog: { bound,
  droppedMessages }, eventsDb: 'ok' | 'error' }`, where `eventsDb` is a real
  `SELECT 1` on the read-only connection. `status` is `ok` only if both are.
  The Docker HEALTHCHECK stays on `/health`.
- `GET /ready`: the same, plus UniFi reachability (`stat/sysinfo`, as the MCP
  server's `/ready` does today): `ok | unavailable | not_configured`. UniFi
  being down doesn't make the service unready for ingest: report it, and
  return 200 unless the listener isn't bound or `eventsDb` is `error`.

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
| `TRUST_PROXY` | unset | new | passed to Express `trust proxy`; never `true` (rejected at startup) |
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
  redirects). Order matters: **merge, then rename the repo, then tag
  v2.0.0**. `release.yml` derives the image from
  `IMAGE_NAME: ${{ github.repository }}`, so after the rename it publishes
  to `ghcr.io/ianchesal/unifi-power-tools` with no edit; tagging before the
  rename would publish 2.0.0 under the old name. The rename is outward-facing:
  done by Ian, or by Claude with his go-ahead.
- `.mcp.json.example` key renamed to `unifi-power-tools`.
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
  one-time procedure: stop **both** the sink and lens cleanly (so WAL is
  checkpointed), copy `events.db` and `lens.db` plus any `-wal`/`-shm` files
  left behind for either, from their old volumes into the new `data` volume,
  and `chown` them to the new image's user in the same step (the old images'
  `adduser -S` users got arbitrary UIDs, and the new image renames the user).
  Start the new service, verify `/health` and that events arrive, then
  remove the old containers. Re-point the NPM proxy host at the new container and the Claude
  Code MCP config at the one `/mcp`. The exact `docker run --rm -v …` copy
  commands are the builder's to write and test.

### Archiving the old repos

For each of `unifi-siem-sink` and `unifi-mcp-server`, after the merged
service is released: a final commit replacing the README with a short notice
("merged into unifi-power-tools", full URL to the new repo, the version it
was merged at), then archive the repo on GitHub. Existing ghcr images stay
published, untouched. These steps are outward-facing and done only with
Ian's go-ahead at that point.

### Tests

- Moved suites (sink parser/storage/syslog/tools, mcp-server tools/client)
  keep their assertions; only imports and module names change.
- Deleted with the code they cover: `tests/db/sinkDb.test.ts`,
  `tests/enrichment/unifiMcpClient.test.ts`, every `sinkDb: null` /
  `runnerDeps: null` degraded-mode case, `/health` schema-mismatch cases,
  and the sink's and mcp-server's own `server.test.ts`/`config.test.ts`
  /`logger.test.ts` (replaced by the merged ones).
- API tests authenticate through a `loginAgent(app)` test helper that posts
  to `/api/auth/login` with supertest's agent (cookie jar), so they exercise
  the real middleware. New tests cover: unauthenticated `/api` → 401, login
  success/failure, rate limit, expired/tampered cookie, password change
  invalidates sessions, `/mcp` ignores cookies, `/health` open.

### CI and release

One `ci.yml` (build, lint, test for both workspaces) and one `release.yml`
(the existing lens release flow; the image name follows the repo rename, see
"Rename"). The release process
in memory still applies: bump PR, Ian merges, tag; never `npm version`.

## Left to the builder

- Order of the moves and how to split them into PRs (a sensible order:
  move ingest + events DB and delete degraded mode → move UniFi client/tools
  and the write gate → replace enrichment → auth → rename/Docker/docs). No
  release is tagged until auth has landed.
- Exact module boundaries inside `server/src/unifi/` and `ingest/`, and how
  the two query modules are deduplicated.
- Login screen look (match the dashboard's existing style).
- The migration commands, tested against copies of real volumes.

## Calls I made (for Ian to check)

- `DASHBOARD_PASSWORD` required, and must differ from `MCP_SECRET`.
- Stateless signed session cookie (30 days, survives restarts) rather than
  server-side sessions, keyed by a random per-install secret in `lens.db`
  mixed with the password hash.
- `TRUST_PROXY` off by default; port 3002 stays published on the host.
- Client-name enrichment redefined (`stat/alluser`, match `ip`/`last_ip`),
  since the old lookup never worked; firewall summary capped at 8 KB.
- Two `events.db` connections: read-write for ingest/purge, read-only for
  everything else.
- `/health` and `/ready` unauthenticated; SPA bundle unauthenticated, all
  data behind `/api` auth.
- UniFi optional (both vars or neither); write tools unregistered, not just
  refused.
- Keep port `3002` for HTTP and host port `5514/udp` for syslog, so NPM and
  the UDM settings need the least change.
- Version jumps to 2.0.0; one `/data` volume holding both DB files.
- Old env vars rejected at startup with a pointer to the new name.
