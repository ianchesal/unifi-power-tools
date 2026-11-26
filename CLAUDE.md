# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A visualization dashboard and code-driven (no-LLM) analysis layer on top of
the sibling project `unifi-siem-sink`'s event store. It reads
`unifi-siem-sink`'s `events.db` read-only, runs scheduled heuristics
(new-signature/new-source-IP detection, internal-source flagging,
repeat-offender tracking, z-score anomaly detection) to produce *findings*,
and serves both a React dashboard and an MCP server. The MCP server is the
key mechanism: this project has no LLM access of its own (no API key), so
a finding the rules can't close is auto-queued as a request — a Claude Code
session (subscription-authenticated, configured with this project's `/mcp`
endpoint) fetches pending requests, reasons about them with real event
context, and posts a verdict (`close` or `attention`) back via
`submit_analysis`. It pairs
with `unifi-mcp-server` (rest of the UniFi Network API) and
`unifi-siem-sink` (the event source); this project adds no new UniFi API
coverage, only analysis on top of what the sink already collects.

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
is currently broken on Node 24.x/25.x — the same known issue documented in
`unifi-siem-sink`'s CLAUDE.md (`--experimental-strip-types` doesn't resolve
`.js`-suffixed relative imports against sibling `.ts` files). Use
`npm run build -w server && npm run start -w server` instead, alongside
`npm run dev -w web` for the frontend.

Node >= 22.5.0 is required (uses `node:sqlite`, built in — no
better-sqlite3 or other native SQLite dependency).

## Architecture

Two npm workspaces: `server/` (Node/TS, Express, MCP SDK) and `web/`
(React/Vite/Recharts). In production the server serves the built dashboard
(`web/dist`) statically alongside its own API and MCP endpoint — one
process, `server/src/server.ts`'s static/SPA-fallback middleware is
registered *after* the `/api`, `/mcp`, and `/health` routes so it can never
shadow them.

### Two SQLite databases

- **`events.db`** (path via `SINK_DB_PATH`) — the sink's database, opened
  strictly **read-only** (`server/src/db/sinkDb.ts`). Never written to.
  Tolerates being empty; a missing file is caught at startup and the server
  boots in a degraded mode (schema check skipped, scheduled jobs skipped,
  API routes return empty results / 503) rather than crashing — see
  `index.ts`'s try/catch around `openSinkDb`. A schema-contract check
  (`verifySchema`, `PRAGMA table_info`) runs at startup and is reflected in
  `/health`, so a sink schema change surfaces loudly instead of causing
  silent wrong-data queries.
- **`lens.db`** (path via `LENS_DB_PATH`) — this project's own store,
  migrated the same numbered-`MIGRATIONS`-array way the sink migrates its
  own DB (`server/src/db/lensDb.ts`). Holds `baselines` (rolling per-
  signature daily counts for anomaly detection), `seen_signatures` /
  `seen_source_ips` (first-seen tracking), `findings`, and
  `analysis_requests` (the Claude Code handoff queue), plus `seen_clients`
  (first-seen tracking for client findings, below) and `finding_history`
  (the per-finding audit trail, written by `pipeline.ts`).

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
exactly as the sink stores it — lowercase, never re-normalised, never a
name) cover LAN hosts UniFi identified only by name/MAC, which sink >= v1.0.3
stores with `source_ip` NULL. Only *client-only Security events* back them:
`source_ip IS NULL AND source_client_mac IS NOT NULL AND category IN
CLIENT_SECURITY_CATEGORIES` (`newEntity.ts`), ignored signatures excluded.
`runner.ts`'s `client` check computes new clients as `allClientMacs` (all
sink history) minus `seen_clients`, so the first run after deploy seeds
findings for historical client-only alerts; each gets `new_client` +
`internal_source` (always — LAN by definition; it's there so clients rank
with internal IPs). `repeat-offender-client` mirrors the IP repeat-offender
pass in its own `runCheck`. Client findings never get rule triage:
`matchRules` returns null for them and the backfill skips them, so they are
always queued for AI — without that guard a client finding would fall into
the signature branch with its MAC parsed as a signature key.
**Old-sink isolation rule:** only the client-only helpers at the bottom of
`sinkQueries.ts` may reference the `source_client_*` / `dest_client_*`
columns; `recentEvents` and every other existing query must not, so a
pre-v1.0.3 sink loses only client features.
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

`mcp/server.ts`'s `createLensMcpServer` builds the per-request `McpServer`
(stateless transport, one per `/mcp` request) with `instructions` pointing at
the playbook, the analysis tools below, the `triage` prompt
(`/mcp__unifi-siem-lens__triage`) and the `get_playbook` tool. Both serve
`assemblePlaybook()` (`mcp/playbook/`): the code-owned core (`core.ts`) plus a
site-knowledge section, which stays empty until phase C adds `playbook_entries`.
The core is public, so it must stay generic: no real addresses, hostnames,
port forwards or VPN endpoints. A test rejects IPv4 literals outside RFC 5737,
and another fails if the playbook names a lens tool that isn't registered.

There is no "Analyze this" click: the pipeline queues an `analysis_requests`
row (`queueForAnalysis`, at most one `pending` per finding) for every finding
the rules don't close, including client findings, and for rechecks
(`is_recheck`). The context bundle is **not stored at queue time** — it is
built when a session fetches it (`mcp/context.ts`, `buildAnalysisContext`):
the finding, `finding_history`, prior analyses, recent matching events (LIMIT
20), baseline history, `since_last_decision` counts (total and unblocked IPS
alerts), a `recheck` before/after summary, and optional `unifi-mcp-server` /
homelab enrichment. Tools: `get_pending_analyses {limit?}`,
`get_analysis_context {id}`, and `submit_analysis {id, verdict: 'close' |
'attention', risk_level, summary, reasoning, recommended_action?, why_now?,
cited_entries?}`. `submit_analysis` goes through `applyAiVerdict`, which runs
the guardrails in `analysis/verdict.ts` before any write (a rejected verdict
leaves the request pending): non-blank summary/reasoning, `attention` needs
`recommended_action`, a recheck needs `why_now`, and a `close` with no cited
entry is rejected when unblocked IPS alerts exist since the last decision or
when the sink can't be checked (fails closed). Phase A has no playbook, so
`PHASE_A_ACTIVE_ENTRY_IDS` is empty and any cited id is rejected. It also
throws on an already-answered, cancelled or nonexistent request.

`analysis_requests.source` (`'ai' | 'rule'`) distinguishes a Claude Code
verdict from one the rule engine wrote directly (`closeByRule`); rule rows are
inserted already `answered`, never pass through `pending`, and the dashboard
shows which produced a decision.

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
completeness is checked via paired `COUNT(*)` SQL queries in `sinkQueries.ts`
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

### Optional enrichment (`server/src/enrichment/unifiMcpClient.ts`)

`createUnifiMcpClient(url)` is a genuine no-op when `url` is `null`
(no `Client`/transport constructed at all) and resolves to `null` on any
connection failure rather than throwing — enrichment must never block the
core analysis-request flow. Not required for anything else in this
project; it's purely additive context for the Claude Code handoff.

## Config

All runtime config is env-driven, loaded once in `server/src/config.ts`
(`loadConfig`) — fails fast if `SINK_DB_PATH` or `MCP_SECRET` is unset or
`LOG_LEVEL` is invalid. `HOST` defaults to `127.0.0.1` (not `0.0.0.0`)
since the dashboard/REST API have no authentication of their own by design
(a single-user LAN tool) — widen it deliberately, never as an accident.
The `/mcp` endpoint is the one exception: it requires
`Authorization: Bearer <MCP_SECRET>` (checked in `server/src/server.ts`'s
`mcpAuthMiddleware`, applied only to the `/mcp` route), mirroring
`unifi-mcp-server`'s auth so a Claude Code session configured against a
LAN-exposed lens instance still needs the shared secret. See the README's
Environment Variables table for the full list and defaults.
