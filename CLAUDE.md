# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**unifi-power-tools**: one service (one process, one image, one `/mcp`) that
does three jobs for a UniFi network. It was three repos until v2.0.0
(`unifi-siem-sink`, `unifi-mcp-server`, `unifi-siem-lens`); see
`docs/superpowers/specs/2026-11-26-unifi-power-tools-merge-design.md`.

1. **Syslog ingest** (`server/src/ingest/`): a UDP listener parses the
   gateway's CEF export into `events.db`.
2. **UniFi Network API tools** (`server/src/unifi/`): firewall, policies,
   networks, clients, traffic rules, port forwards, monitoring, as MCP tools.
   Write tools are registered only with `UNIFI_ALLOW_WRITES=true`.
3. **Analysis and triage**: scheduled heuristics
   (new-signature/new-source-IP detection, internal-source flagging,
   repeat-offender tracking, z-score anomaly detection) produce *findings*,
   served in a React dashboard and over MCP. The service has no LLM access of
   its own (no API key), so a finding the rules can't close is auto-queued as
   a request: a Claude Code session (subscription-authenticated, configured
   with this project's `/mcp` endpoint) fetches pending requests, reasons
   about them with real event context, and posts a verdict (`close` or
   `attention`) back via `submit_analysis`. Inside the code this layer is
   still called "lens" (`lens.db`, `LensDb`).

A second, purely code-driven layer runs first: a set of rules (trusted-admin
console logins, WAN/operational noise, blocked reputation-blocklist IDS hits,
...) close a finding the moment it's detected, with no Claude Code session
ever involved, for the cases where the verdict is mechanical rather than
something worth an LLM's attention.

See `docs/superpowers/specs/2026-08-31-lens-design.md` for the full design
spec (architecture rationale, trigger/finding lifecycle rules, and the
decisions behind the analysis heuristics), and
`docs/superpowers/specs/2026-09-01-rule-based-triage-design.md` for the
rule-based auto-triage layer specifically — both are not gitignored from
the published repo the way `docs/superpowers/` normally would be, since
they're the primary architecture reference for this project going forward.

## Commands

```bash
npm install                 # installs both workspaces (npm workspaces: server, web)
npm run dev                  # concurrently: server dev + web (Vite) dev, proxied together
npm run build                 # builds web then server
npm start                     # runs the built server (serves API + MCP + built dashboard)
npm test                      # server test suite (vitest)
npm run lint                  # biome (server) + oxlint (web)
```

Run a single server test file: `cd server && npx vitest run tests/analysis/findings.test.ts`
Run tests matching a name: `cd server && npx vitest run -t "some test name"`

`npm run dev -w server` (`node --watch --experimental-strip-types src/index.ts`)
is currently broken on Node 24.x/25.x (`--experimental-strip-types` doesn't
resolve `.js`-suffixed relative imports against sibling `.ts` files). Use
`npm run build -w server && npm run start -w server` instead, alongside
`npm run dev -w web` for the frontend.

Node >= 24 is required (uses `node:sqlite`, built in — no better-sqlite3 or
other native SQLite dependency). `undici` is the one HTTP dependency, for the
UniFi client's TLS-skip `Agent`.

## Architecture

Two npm workspaces: `server/` (Node/TS, Express, MCP SDK) and `web/`
(React/Vite/Recharts). In production the server serves the built dashboard
(`web/dist`) statically alongside its own API and MCP endpoint — one
process, `server/src/server.ts`'s static/SPA-fallback middleware is
registered *after* the `/api`, `/mcp`, `/health` and `/ready` routes so it
can never shadow them. `server/src/index.ts` only loads config, installs a
logging (non-exiting) `unhandledRejection` handler and calls `start()`
(`server/src/start.ts`), which opens both DBs, seeds the playbook, **binds the
syslog listener before the boot-time analysis runs** (they're synchronous and
block the event loop), starts the hourly purge/analysis and daily timers, and
listens. A failure to open the events DB or bind the syslog port is fatal.

### Two SQLite databases

- **`events.db`** (path via `EVENTS_DB_PATH`) — the syslog event store,
  migrated by `server/src/db/eventsDb.ts` (WAL, `auto_vacuum`, its own
  numbered migrations; migration 3 re-parses client events and is safe to
  re-run). `openEventsDb` returns **two connections**: a read-write
  `writer` used only by ingest (`insertEvent`) and the hourly retention purge
  (`purgeOldEvents`, `RETENTION_DAYS`), and a **read-only** `reader` for
  analysis, `/api` and `/mcp`, so code handling attacker-influenced event text
  can't write events. (For `:memory:` the reader shares the writer's
  connection.) Analysis queries live in `db/eventQueries.ts`; the MCP event
  tools' filter/stat queries in `db/eventSearch.ts`.
- **`lens.db`** (path via `LENS_DB_PATH`) — this project's own store,
  migrated the same numbered-`MIGRATIONS`-array way `eventsDb.ts` migrates its
  own DB (`server/src/db/lensDb.ts`). Holds `baselines` (rolling per-
  signature daily counts for anomaly detection), `seen_signatures` /
  `seen_source_ips` (first-seen tracking), `findings`, and
  `analysis_requests` (the Claude Code handoff queue), plus `seen_clients`
  (first-seen tracking for client findings, below), `finding_history`
  (the per-finding audit trail, written by `pipeline.ts`), `meta` (the
  session-signing secret) and the playbook
  tables `playbook_entries`, `playbook_proposals` and `playbook_defaults_seen`.

### Analysis engine (`server/src/analysis/`)

Pure-function heuristic modules (`cidr.ts`, `newEntity.ts`,
`repeatOffender.ts`, `baseline.ts`) with zero I/O, orchestrated by
`runner.ts`'s `runHourlyChecks`/`runDailyAnomalyCheck`, scheduled from
`index.ts`. Each check runs in its own try/catch (`runCheck` helper in
`runner.ts`) — one broken heuristic must never block the others for that
run, mirroring the sink's "never stop listening" philosophy.

`IGNORED_SIGNATURE_KEYS` (in `newEntity.ts`) lists exact `category|signature`
pairs excluded from analysis entirely — filtered out of the runner's hourly
event scan and the daily anomaly baselines, so they never become findings
at all (unlike the rule-triage layer below, which closes findings after
creation). Currently just `siteactivity|2154`, the UniFi Protect doorbell ring.
Findings that predate a key's addition to the list are cleaned up by the
admin backfill, via an `ignored_signature` rule checked first in
`matchRules`'s signature branch (no completeness counts — the key alone
pins it).

**Client findings** (`entity_type: 'client'`, keyed by `source_client_mac`
exactly as ingest stores it — lowercase, never re-normalised, never a
name) cover LAN hosts UniFi identified only by name/MAC, which ingest stores
with `source_ip` NULL. Only *client-only Security events* back them:
`source_ip IS NULL AND source_client_mac IS NOT NULL AND category IN
CLIENT_SECURITY_CATEGORIES` (`newEntity.ts`), ignored signatures excluded.
`runner.ts`'s `client` check computes new clients as `allClientMacs` (all
event history) minus `seen_clients`, so the first run after deploy seeds
findings for historical client-only alerts; each gets `new_client` +
`internal_source` (always — LAN by definition; it's there so clients rank
with internal IPs). `repeat-offender-client` mirrors the IP repeat-offender
pass in its own `runCheck`. Client findings never get rule triage:
`matchRules` returns null for them and the backfill skips them, so they are
always queued for AI — without that guard a client finding would fall into
the signature branch with its MAC parsed as a signature key.
Client and IP findings for the same host are deliberately not merged (see
`docs/superpowers/specs/2026-11-25-client-entities-design.md`).

`isAnomalous` (in `baseline.ts`) is deliberately one-sided: only a spike
above the trailing baseline registers, never a drop. A drop in alert volume
is more likely a collection/operational problem than a security one for an
IDS/IPS use case.

**Findings lifecycle** (`server/src/analysis/findings.ts`, `pipeline.ts`) is
the most spec-critical area — read both, and
`docs/superpowers/specs/2026-11-25-findings-triage-redesign-design.md`, before
touching it. A finding is `triaging` (waiting on rules/AI), `attention` (the
operator should do or verify something in UniFi) or `closed` (with `closed_by`
`rule | ai | human | system`, the last for migrated legacy rows). A finding
accumulates `triggers`; `anomaly` and `repeat_offender` are "standing"
(`reevaluateTrigger` flips `active`) but triggers **never change status** —
the one exception is `applyTrigger` sending a rule-closed finding that gains
`internal_source` back to `triaging`. Status changes only through
`pipeline.ts`, the single transition module (`closeByRule`, `applyAiVerdict`,
`humanClose`/`humanReopen`, `reanalyze`, `recheckStillClosed`/`recheckRequeue`):
each asserts the transition is legal (`assertTransition`), cancels any pending
analysis request when the finding leaves `triaging`, and writes
`finding_history` rows, all in one transaction (re-entrant via `atomically`).
`last_activity_at` is maintained by the hourly run; `last_triaged_at` is the
last decision, and `decisionWindowStart` (that, else `closed_at`, else
`first_seen - 14d`) is where "activity since the last decision" starts.

**Recheck** (`runDailyRecheck` in `runner.ts`, run after the daily anomaly
check): a `closed` finding with `last_activity_at` past its last decision (and
no recheck in 24h, `isRecheckDue`) is re-run through `matchRules` over the
decision window; a match keeps it closed, anything else is re-queued for AI
with `is_recheck` set, and the verdict must then supply `why_now`.

### MCP handoff (`server/src/mcp/`, `server/src/db/analysisRequestsStore.ts`)

`mcp/server.ts`'s `createMcpServer` builds the per-request `McpServer`
(name `unifi-power-tools`)
(stateless transport, one per `/mcp` request) with `instructions` pointing at
the playbook, the event tools (`mcp/eventTools.ts`: `list_events`,
`get_event`, `get_categories`, `get_event_stats`), the analysis tools below,
the playbook tools (`playbookTools.ts`), the UniFi tools when UniFi is
configured, the `triage` prompt and the `get_playbook` tool. The triage slash
command comes from the client's config key, not the server name, so it is
`/mcp__unifi-power-tools__triage` only if the entry is named that
(`.mcp.json.example` does). Both serve `assemblePlaybook({ trustedAdminNames, entries })`
(`mcp/playbook/`): the code-owned core (`core.ts`), a "Configured trusted
admins" section built from `TRUSTED_ADMIN_NAMES`, and a "Site knowledge"
section built from the active playbook entries. Both site sections are assembled
on each call (site data never goes in the repo). The core is public, so it must
stay generic: no real addresses, hostnames, port forwards or VPN endpoints. A
test rejects IPv4 literals outside RFC 5737, and another fails if the playbook
names a tool that isn't registered: always-on tools with UniFi off, every tool
with UniFi stubbed (`UNIFI_ONLY_TOOLS` in `core.ts` lists the UniFi-only
ones). The core also tells triage never to call UniFi write tools.

There is no "Analyze this" click: the pipeline queues an `analysis_requests`
row (`queueForAnalysis`, at most one `pending` per finding) for every finding
the rules don't close, including client findings, and for rechecks
(`is_recheck`). The context bundle is **not stored at queue time** — it is
built when a session fetches it (`mcp/context.ts`, `buildAnalysisContext`):
the finding, `finding_history`, prior analyses, recent matching events (LIMIT
20), baseline history, `since_last_decision` counts (total and unblocked IPS
alerts), a `recheck` before/after summary, and optional UniFi / homelab
enrichment. Tools: `get_pending_analyses {limit?}`,
`get_analysis_context {id}`, and `submit_analysis {id, verdict: 'close' |
'attention', risk_level, summary, reasoning, recommended_action?, why_now?,
cited_entries?}`. `submit_analysis` goes through `applyAiVerdict`, which runs
the guardrails in `analysis/verdict.ts` before any write (a rejected verdict
leaves the request pending): non-blank summary/reasoning, `attention` needs
`recommended_action`, a recheck needs `why_now`, every `cited_entries` id must
be an active playbook entry (`activeEntryIds`), and a `close` made while
unblocked IPS alerts exist since the last decision, or while the sink can't be
checked (fails closed), must cite at least one operator-backed entry
(`operatorBackedEntryIds`, below). It also throws on an already-answered,
cancelled or nonexistent request.

`analysis_requests.source` (`'ai' | 'rule'`) distinguishes a Claude Code
verdict from one the rule engine wrote directly (`closeByRule`); rule rows are
inserted already `answered`, never pass through `pending`, and the dashboard
shows which produced a decision.

### Playbook (site knowledge)

Operator-approved entries about this network, learned through proposals.

- **One writer, every change a proposal.** `db/playbookStore.ts` is the only code
  that writes `playbook_entries` and `playbook_proposals`. An entry's text and
  status change only when a proposal is accepted (`add`, `edit`, `retire`;
  nothing is deleted, and an edit reactivates a retired entry). The store owns a retire's
  text: it copies the entry's title and body at creation and again at accept,
  ignoring the caller's text and edits. Retiring an already retired entry is
  rejected, as is an `ai` edit whose text matches the entry: accepting that would
  make default text operator-backed while the page shows two identical columns.
  `humanChange` records a dashboard change as a proposal and accepts it at once,
  so the proposal table is the change log. MCP can only create pending `ai`
  proposals. Outside seeding (which accepts a new default's `add` and rejects a
  superseded default update), only REST (`api/playbook.ts`) accepts or rejects:
  every write there requires a JSON body so a cross-site request can't make one,
  and the accept body is strict, so a misspelled field is a 400.
- **Operator-backed** (`operatorBackedEntryIds`): active entries whose latest
  accepted proposal isn't `proposed_by: 'default'`, or has `edited_on_accept`
  (the accepted title or body differs from what was proposed). So a default
  update accepted as proposed makes or leaves the entry a default. Shipped default text
  can't by itself justify closing unblocked traffic; the playbook marks it
  ` (default)`. The API's `is_default` is the negation, so it is also true for
  every retired entry: only label active ones. The check covers who stands behind
  a cited entry, not whether it applies.
- **Seeding** (`mcp/playbook/defaults.ts`, `seed.ts`, run at startup): a
  never-seen `key` becomes an active entry; a higher `version` becomes a pending
  `edit` proposal, superseding an undecided `default` one for that entry, even if
  the entry is retired; a default removed from code leaves its entry alone.
  `playbook_defaults_seen` (written by `seed.ts`) tracks the handled version.
  `key` is stable forever; raise `version` when changing the text.
- **Learning loop:** `get_feedback` returns unreviewed
  `human_closed_handled` / `human_closed_not_concern` / `human_reopened` history
  rows. A reopen carries `reopened_from`: the close it undid, whose summary names
  the rule when a rule closed it, or null when no close is on record.
  `mark_feedback_considered` sets `feedback_considered_at`. The
  run procedure in `core.ts` drives both.
- **Import prompt:** `import_knowledge` has a session split its own notes into a
  `homelab-services.json` fragment (mechanical host/port facts), `ai` proposals
  (judgment calls) and a stale list. It writes no files.
- **Site data never goes in the repo.** Entries live in `lens.db`; `core.ts` and
  `defaults.ts` are public and stay generic (tests reject non-RFC 5737 IPv4
  literals; GitHub's published SSH range is the one exemption, in the defaults).

### Rule-based auto-triage (`analysis/ruleTriage.ts`, `matchRules.ts`, `runner.ts`)

`ruleTriage.ts` is a pure, zero-I/O module (matching `cidr.ts`/`newEntity.ts`/
`baseline.ts`'s pattern) of rule functions — `tryAdminAuditLoginRule`,
`tryOperationalNoiseRule`, `tryLowSignalCategoryRule`,
`tryReputationBlocklistRule`, `tryHomelabServiceRule`, `tryExposedHostScanRule`,
`tryIgnoredSignatureRule` (`RuleName`: `admin_login`, `operational_noise`,
`low_signal_category`, `reputation_blocklist`, `homelab_service_egress`,
`exposed_host_scan`, `ignored_signature`) — each taking already-computed data
and returning a `TriageVerdict` (`risk_level` always `'low'`) or `null`. A rule
matches only when **every** event backing the finding satisfies it —
completeness is checked via paired `COUNT(*)` SQL queries in `eventQueries.ts`
(`sourceIpEventCounts`/`signatureEventCounts`/`auditCandidateEvents`),
deliberately *not* the `eventsFor*` fetchers (`LIMIT 20`, sized for LLM prompt
context) — a burst of more than 20 events could otherwise let the most recent
20 silently stand in for "every event."

`matchRules(deps, finding, sinceIso, untilIso?, allowedRules?)` in
`matchRules.ts` is the query-only evaluator: first match wins, never writes,
returns `{ rule, verdict }` or null. Callers decide what a match means: the
runner's creation pass and the backfill call `closeByRule`, the daily recheck
calls `recheckStillClosed`. Every new finding is offered to the rules; a miss
leaves it `triaging` with a queued request.

**Internal-source restriction (every pass):** a finding carrying
`internal_source` can only be closed by `operational_noise` — enforced inside
`matchRules` itself, so the hourly path, the recheck and the backfill all obey
it. An internal host tripping `admin_login`/`reputation_blocklist`/etc. is the
"possible compromised host talking out" case and must reach the AI (the "same-
pass reopen" test in `runner.test.ts` covers it).

`runRuleTriageBackfill` (`runner.ts`, `POST /api/admin/backfill-rule-triage`,
the `/admin` page; returns `{ checked, closed, byRule }`) re-checks only
`triaging`, non-client findings that were never decided (`last_triaged_at`
NULL) — a finding requeued by a recheck, reopened by `internal_source` or
re-analyzed is waiting because of events after its last decision, so its
creation window is stale. The window comes from the creating trigger
(`backfillWindow`: `repeat_offender` → 14d before `first_seen`; `anomaly` →
the anomaly day; otherwise 24h before `first_seen`), always ending at
`first_seen`: it is stamped with the *detection run time*, at the end of the
live path's scan, so the evidence is *before* it. Getting this window backwards
is a documented past bug — see the `runner.ts` comment above `backfillWindow`
before changing it.

### UniFi tools (`server/src/unifi/`)

`unifi/client.ts` is the UniFi Network API client (`IUnifiClient`). Each
module in `unifi/tools/` registers its tools into a collecting `ToolSink` and
declares a hand-written `<MODULE>_TOOLS_READ_ONLY` map; `allUnifiTools`
collects them (throwing on a tool with no declaration) and
`registerUnifiTools` skips every `readOnly: false` tool unless
`allowWrites`, emitting `readOnlyHint`/`destructiveHint` annotations. Writes
are unregistered rather than refused so a triage session (which reads
attacker-influenced text) never sees them. Tests pin the counts (37 tools, 22
writes) and check every `create_|update_|delete_|block_|unblock_|set_|remove_`
tool is declared a write.

### Optional enrichment (`server/src/enrichment/unifiEnricher.ts`)

`createUnifiEnricher(client)` is a no-op when UniFi isn't configured and
resolves to `null` on any API error rather than throwing — enrichment must
never block the analysis-request flow. `resolveClient(ip)` searches
`stat/alluser` (online and offline) for a matching `ip` or `last_ip` and
returns `{ name: name ?? hostname, network }`; `getFirewallSummary()` is the
firewall rule list as JSON, capped at 8 KB. (The pre-merge MCP-based lookup
never worked: it called `get_client` with an IP, but that tool takes a MAC.)

## Config

All runtime config is env-driven, loaded once in `server/src/config.ts`
(`loadConfig`) — fails fast if `MCP_SECRET` or `DASHBOARD_PASSWORD` is unset,
if they're equal, if `TRUST_PROXY` is `true`, if only one of
`UNIFI_HOST`/`UNIFI_API_KEY` is set, if `LOG_LEVEL` is invalid, or if any
pre-merge variable in `REMOVED_ENV_VARS` is still set (the error names the
replacement). `HOST` defaults to `127.0.0.1` (not `0.0.0.0`) — widen it
deliberately, never as an accident; this is a LAN tool, never internet-facing.

Auth (`server/src/auth/`, `server/src/api/auth.ts`):
- **Dashboard/REST:** `POST /api/auth/login` checks `DASHBOARD_PASSWORD`
  (constant time) and sets `upt_session`, a stateless signed cookie
  (`<expiryMs>.<HMAC>`, 30 days, `HttpOnly`, `SameSite=Strict`, `Secure` when
  `req.secure`). The HMAC key is `HMAC(sessionSecret, SHA-256(password))`
  with `sessionSecret` 32 random bytes in `lens.db`'s `meta` table: sessions
  survive restarts, a password change logs everyone out, and a captured cookie
  can't be used to guess the password offline. Everything under `/api` except
  `/api/auth/*` requires the cookie (`requireSession`), and every write there
  must be `application/json` (`requireJsonOnWrites`, 415 otherwise). Failed
  logins are rate-limited (10 per 15 minutes; successes don't count).
- **`trust proxy`** is off unless `TRUST_PROXY` names the proxy; never `true`,
  because port 3002 is reachable directly and `X-Forwarded-For` could be forged.
- **`/mcp`:** `Authorization: Bearer <MCP_SECRET>` via `secretEquals`
  (constant time); it ignores the cookie. `/health` and `/ready` are open.
- Router-level tests mount routers on a bare `express()` and skip auth; tests
  through `createApp` sign in with `loginAgent` from `tests/helpers.ts`.

See the README's Environment Variables table for the full list and defaults.
