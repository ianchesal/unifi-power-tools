> Note (2026-11-26): the sink and UniFi MCP server have since been merged into this service; see 2026-11-26-unifi-power-tools-merge-design.md. References here to a read-only sink DB or enrichment over MCP describe the old split.

# Findings triage redesign: attention queue + learning playbook

Date: 2026-11-25

## Why

The findings page is noise. On the live instance every one of 748 findings
is `dismissed`: 508 are bare "never-seen source IP" findings and 199 are
"never-seen signature" findings, and the IPS alerts behind them are almost
all already **blocked** by the gateway (a week sample: 48/48 blocked, 34 of
them CINS poor-reputation hits). The operator dismisses everything, and
dismissed findings come back: `applyTrigger` reopens any finding to `new`
when it gains a trigger type it didn't have, so a dismissed scanner IP
returns when it turns into a `repeat_offender`, and a dismissed signature
returns on a one-day `anomaly` spike.

The status set (`new / acknowledged / dismissed / resolved`) describes a
finding's bookkeeping, not whether the operator needs to do anything. What
the operator wants is a short list of things worth acting on **in the UniFi
console** to protect the network: the Plex2Shell campaign that led to a new
firewall block policy is the reference example. Everything else should be
handled without them and kept, with its reason, for audit.

The second half of the problem: AI analysis today gets no instructions from
the lens at all. The three MCP tools are bare; all site knowledge (which
hosts run P2P clients, which VPN endpoints are benign, which false positives
the operator has chosen to tolerate) lives in whatever Claude session's
memory happens to be running. The lens should own that knowledge as a
playbook it serves to Claude, and the playbook should get better as the
lens sees more events and the operator corrects it.

## Goals

- One default view, **Needs attention**, holding only findings a rule or the
  AI couldn't close. Each says what to do in UniFi and why.
- Pipeline: finding → static rules → (auto-queued) AI analysis → closed, or
  needs attention. No "Analyze this" click required.
- A closed finding with new activity reopens and goes back through the
  pipeline with its full history. If it lands in front of the operator it
  must explain *why it's back and why that's concerning*, with the history
  visible.
- The lens serves Claude a comprehensive analysis playbook: a code-owned
  core method plus learned, site-specific knowledge stored in `lens.db`.
- The site knowledge improves over time: Claude proposes changes, backed by
  evidence (operator corrections, recurring patterns), and the operator
  approves or rejects each one on the dashboard.
- Works with infrequent, operator-run analysis: manual, or a cron'd
  `claude -p` on the operator's Linux workstation, **at most once a day**.

## Non-goals

- Grouping findings into cases/campaigns. One finding is still one source IP
  or one signature; an attack seen as both is two items. Revisit only if
  that duplication is still annoying once the noise is gone.
- Any LLM access from the lens itself. The lens still has no API key; Claude
  Code drives the analysis over MCP, as today.
- Push notifications, email, or digests.
- New UniFi API coverage. Recommended actions are text for the operator to
  carry out; the lens never changes UniFi config.
- Changing the detection heuristics themselves (new-entity, internal-source,
  repeat-offender, anomaly). They keep producing findings; what changes is
  what happens to a finding afterwards.

## Anti-goals (would make this a failure even if it works)

- A dismissed thing reappearing with no explanation of what changed.
- The playbook silently learning a lesson broad enough to auto-close a real
  attack. Every site-knowledge change is operator-approved, and the core
  playbook carries guardrails site entries cannot override (below).
- A finding *looking* handled when it's actually sitting unanalyzed. The
  queue's size and age are always visible.
- Private network details (internal IPs, hostnames, port forwards, VPN
  endpoints) ending up in the public repo. Site knowledge lives only in
  `lens.db`.

## Approaches considered

1. **Rework findings in place (chosen).** Keep the `findings` table and the
   runner; replace the status model, auto-queue AI requests, add playbook
   tables and MCP tools, rebuild the findings UI around the attention view.
   Smallest change that delivers the pipeline; keeps rule triage, backfill
   and the analysis-request audit trail.
2. **Cases layer on top of findings.** Findings become invisible raw
   detections; a `cases` table groups related findings and is the only
   human-facing object. Less duplication, but a second lifecycle, grouping
   logic and a full dashboard rewrite. Deferred (see non-goals).
3. **Playbook as markdown in the repo, edits as commits/PRs.** Easy to diff
   and review, but the repo is public and the playbook's value is exactly
   the private site facts. Dropped.

## Design

### Status model

`findings.status` becomes one of:

| status      | meaning |
|-------------|---------|
| `triaging`  | Waiting on the pipeline: rules didn't close it and an AI analysis request is pending. |
| `attention` | AI (or the operator) decided the operator needs to look at it. |
| `closed`    | Handled. `closed_by` says who: `rule`, `ai`, `human`, or `system` (legacy migration only). |

New columns on `findings`:

- `closed_by TEXT NULL`, `closed_reason TEXT NULL`, `closed_at TEXT NULL`
- `last_activity_at TEXT NOT NULL` — latest sink event received for this
  entity that the runner has observed (maintained by the hourly run).
- `last_triaged_at TEXT NULL` — when the pipeline last made a decision on it.
- `reopen_count INTEGER NOT NULL DEFAULT 0`

`acknowledged`, `dismissed` and `resolved` go away. Standing triggers
(`anomaly`, `repeat_offender`) no longer auto-resolve anything: a trigger
lifting or reactivating is recorded on the trigger (it stays useful context
for the AI and the severity score) but **never changes status**. Status only
changes through the pipeline or the operator.

`applyTrigger` therefore simplifies: a brand-new finding starts `triaging`
(and is immediately offered to the rules); an existing finding's status is
untouched by trigger changes, **with one exception**: gaining an
`internal_source` trigger sends a `closed` finding with `closed_by: rule`
back to `triaging` (queued, history `trigger_added`). New activity on a
closed finding is otherwise handled by the daily recheck below, not by
trigger bookkeeping.

**Internal-source restriction (preserved from today).** Any finding carrying
an `internal_source` trigger may only be rule-closed by
`operational_noise` — never `admin_login`, `reputation_blocklist`,
`exposed_host_scan` or `homelab_service_egress` — in every rule pass: the
hourly creation path, the daily recheck and the backfill. An internal host
tripping a security rule is the "possible compromised host talking out"
case (see `runner.ts` above `tryRuleTriage`) and must reach the AI. The
existing "same-pass reopen" test in `runner.test.ts` is kept and restated:
a source IP first seen and rule-closed in the same pass that also trips
internal-source ends the pass `triaging` with a pending request.

`severity_score` stays as the sort key within the attention view and queue.

### Finding history

New table `finding_history` — the timeline shown on every card and the raw
material for learning:

```
id, finding_id, at, kind, actor ('rule'|'ai'|'human'|'system'),
summary TEXT, note TEXT NULL, analysis_request_id NULL,
feedback_considered_at TEXT NULL
```

`kind` is one of `created`, `trigger_added`, `rule_closed`, `queued`,
`ai_closed`, `ai_attention`, `human_closed_handled`,
`human_closed_not_concern`, `human_reopened`, `human_reanalyze`,
`recheck_rule_still_closed`, `recheck_queued`, `request_cancelled`. The runner, API and MCP handlers write a row for every
status transition.

### Pipeline

**Rule matching is split from acting on it.** `tryRuleTriage` becomes a
pure-ish `matchRules(deps, finding, sinceIso, untilIso?, allowedRules?) →
{ rule, verdict } | null` (queries only, no writes), and each caller decides
what to do with a match. Creation and backfill matches write the answered
rule `analysis_requests` row and close the finding; recheck matches write
only a history row (no daily analysis-row churn for persistent scanners).

**Hourly (`runHourlyChecks`).** Detection is unchanged. **Every** finding
creation, in any loop (new-signature, new-source-ip, internal-source,
repeat-offender, and the daily anomaly check), goes through rules → queue.
Window: the creating run's own scan window (24h for the hourly loops; the
anomaly day for anomaly; the 14-day repeat-offender window for
repeat-offender). If the window has no events for the entity, no rule can
match (`isComplete` needs `total > 0`) and it simply queues. For a newly
created finding: Match → `closed`,
`closed_by: rule`, `closed_reason` = the rule's recommendation, history row.
No match → create a pending `analysis_requests` row and leave it
`triaging`. The hourly run also updates `last_activity_at` (to the entity's
`MAX(received_at)`; `recentEvents` must select `received_at`) for every
finding whose entity appears in the scanned window.

The internal-source loop's per-hour rule pass only runs on findings it just
created or just sent back to `triaging`; it doesn't re-run on every
`triaging` finding each hour.

The internal-source loop keeps its narrower `allowedRules:
['operational_noise']` exception; findings it doesn't close go to the AI
queue like any other.

**Daily recheck (new, runs alongside `runDailyAnomalyCheck`).** For every
`closed` finding with `last_activity_at > coalesce(last_triaged_at,
closed_at)` **and** `coalesce(last_triaged_at, closed_at) < now - 24h` (the
daily job also fires on every restart, so the 24h guard is in the
predicate, not just the timer — unit-tested):

1. Re-run the rules over the new activity window
   `[coalesce(last_triaged_at, closed_at), now)` with the same completeness
   checks. If a rule still fully explains it: stays `closed`, update
   `last_triaged_at`, write `recheck_rule_still_closed`. This applies to all
   closers, so a scanner IP the AI closed whose new hits are pure
   reputation-blocklist noise doesn't go back to Claude.
2. Otherwise: status → `triaging`, `reopen_count += 1`, queue an analysis
   request flagged `is_recheck`, write `recheck_queued`.

Rechecks happen at most once a day per finding, batching a day's activity,
so a persistent scanner can't requeue itself every hour. This is the
"reopen on any new activity" behavior the operator chose, routed through
rules and AI rather than straight to the attention view; it's the AI that
writes the "why it's back" explanation.

`attention` and `triaging` findings aren't rechecked; new activity on them
just shows up in their context next time they're viewed or analyzed.

**Pending requests and stale verdicts.** `analysis_requests.status` gains
`cancelled`. Whenever a finding leaves `triaging` by any path other than
`submit_analysis` (operator close/reopen, backfill rule close), its pending
request is set `cancelled`. `submit_analysis` rejects a request that is
cancelled or whose finding isn't `triaging`, with a clear error so Claude
moves on. At most one pending request per finding, as today.

**Allowed transitions** (anything else returns 409):

| action | from | to |
|---|---|---|
| rule close (creation/backfill) | `triaging` | `closed` (rule) |
| `submit_analysis` | `triaging` | `closed` (ai) / `attention` |
| daily recheck | `closed` | `closed` / `triaging` |
| internal_source gained | `closed` by rule | `triaging` |
| `POST /close` | `attention` | `closed` (human) |
| `POST /reopen` ("This was wrong") | `closed` | `attention` |
| `POST /reanalyze` | `closed`, `attention` | `triaging` |

The admin backfill runs over `triaging` findings only, so it can't re-close
something the operator moved to `attention`.

### Analysis requests

`analysis_requests` gains:

- `verdict TEXT NULL` — `'close' | 'attention'` (null for legacy rows)
- `summary TEXT NULL` — one-line headline for the card
- `recommended_action TEXT NULL` — what to do in UniFi (required for
  `attention`; e.g. "Add a firewall policy blocking X inbound to WAN",
  "Remove port forward Y", "Block client Z")
- `why_now TEXT NULL` — required when the request `is_recheck`: what changed
  since the last decision and why that matters
- `cited_entries TEXT NULL` — JSON array of playbook entry ids the verdict
  relied on, shown on the card so a wrong close points at the entry to fix
- `is_recheck INTEGER NOT NULL DEFAULT 0`

`recommendation` stays as the full reasoning text. `risk_level` stays.

**Context is assembled when Claude fetches it** (`get_analysis_context`),
not when the request is queued. With daily-at-best runs a queue-time
snapshot would be up to a day stale. The bundle is today's (finding, recent
events, baselines, optional unifi-mcp-server enrichment, homelab
annotations) plus: the finding's full `finding_history`, every prior
analysis on it (rule and AI, with verdicts and operator notes), event
counts since the last decision, and, for rechecks, a before/after summary
(e.g. destinations/ports/actions seen before closure vs since). Requests are
queued with `context = '{}'`; every `get_analysis_context` call rebuilds the
bundle and overwrites the stored copy until the request is answered, so the
row ends up holding what Claude saw when it decided.

`submit_analysis` with `verdict: 'close'` → finding `closed`, `closed_by:
ai`, `closed_reason` = `summary`; with `'attention'` → `attention`. Either
writes history.

**Code-enforced guardrails.** `submit_analysis` rejects:

- `close` when the finding's events since its last decision include an
  `ips_alert` with `action != 'blocked'` and `cited_entries` is empty;
- `cited_entries` ids that don't exist or aren't `active`.

These are unit-tested; the rest of the guardrails below are prompt-level.

`get_pending_analyses` returns requests ordered by severity then age, with
an optional `limit`, so a big backlog doesn't swamp one daily run.

The manual "Analyze this" / "Analyze page" buttons go away for open
findings. Closed findings get a "Re-analyze" action (queues a request,
status → `triaging`) for when the operator wants a second look.

### The playbook

Two layers, assembled into one document served to Claude:

**Core (code-owned, public, versioned with the app)** — in
`server/src/mcp/playbook/core.md` (or a TS string module; builder's call).
Covers: the analysis procedure; what `close` vs `attention` mean (attention
= the operator should *do or verify something in UniFi*; already-blocked
noise with no new risk is `close`); a catalog of UniFi actions to recommend
and when; how to write `why_now` for rechecks; how to use history and
operator notes; how and when to propose playbook changes; and **guardrails
site entries cannot override**. Starting guardrail set (builder may refine,
mark as such):

- Threat traffic that was *not* blocked (`action` other than `blocked`) is
  `attention` unless a site entry names that exact host/port/signature.
- An internal host as the source of a malware/C2 signature is `attention`
  unless a site entry names that exact host *and* the specific
  port/peer pattern that explains it.
- Admin/console logins by an identity not in the configured trusted admins
  are `attention`.
- Site entries must be specific (named hosts, ports, signatures, CIDRs) —
  Claude must not apply an entry beyond what it literally covers, and must
  not propose broad ones.

**Site knowledge (lens.db, learned, operator-approved)** — table
`playbook_entries`:

```
id, title, body, status ('active'|'retired'), created_at, updated_at,
source_proposal_id NULL, default_key NULL
```

Short, specific entries: "VPN client containers on host A tunnel to
endpoints E1–E3; exploit-signature hits on those flows are false positives",
"Operator chose not to suppress SID X; treat as known noise, don't
recommend suppression", and so on.

**Relationship to the homelab services registry.** The existing private
registry (`HOMELAB_SERVICES_PATH`, `enrichment/homelabServices.ts`) stays
the home for facts a **rule** can match mechanically (host + service port,
WAN-exposed hosts), feeding `homelab_service_egress` and
`exposed_host_scan`. The playbook holds **judgment calls** the AI applies.
The Playbook page shows registry entries read-only so the operator sees all
site knowledge in one place, and Claude's proposal guidance says: if a
lesson is "host H, port P, always benign," recommend adding it to the
registry rather than proposing a playbook entry.

Table `playbook_proposals`:

```
id, op ('add'|'edit'|'retire'), entry_id NULL, title, body,
rationale, evidence (JSON: finding ids, history ids),
status ('pending'|'accepted'|'rejected'), proposed_by ('ai'|'human'|'default'),
created_at, decided_at NULL, decision_note NULL
```

**Default entries.** The app ships a starter set of site-knowledge entries
so a fresh install triages sensibly from day one. They live in code
(`server/src/mcp/playbook/defaults.ts`), each with a stable `default_key`,
and must be generic — no addresses or hostnames from any real network.
Defaults only cover ground the rules don't (reputation-blocklist and
operational/WAN-health noise are already rule-closed before the AI sees
them, so they get no default entry). Starting set (builder writes the
wording):

- Blocked inbound scanner fingerprints (ET SCAN Zmap, masscan, etc.) with
  no allowed traffic: close.
- Git-over-SSH from an internal workstation to GitHub's published SSH
  ranges tripping "ET SCAN Potential SSH Scan OUTBOUND": close.
- Outbound traffic to commercial VPN/WireGuard endpoints from a host known
  to run a VPN client tripping generic exploit signatures: close only if a
  site entry names that host (shows the pattern for operator-written
  entries).
- Device-status events that reach the AI (not rule-closed): attention only
  for a device going offline repeatedly or an unexpected WAN IP change.
- Repeated blocked exploit attempts against a port-forwarded service:
  close while blocked; attention if any attempt was allowed, or if the
  campaign is sustained and no firewall policy blocks the source (recommend
  a block policy).

Seeding: each default in `defaults.ts` has a `default_key` and an explicit
integer `version`. On startup, a default whose key has never been seeded is
inserted as an active entry (`playbook_entries.default_key`, `proposed_by:
'default'` in the change log). Defaults are never overwritten after that.
When a default's `version` goes up, the new text arrives as a pending
`edit` proposal (`proposed_by: 'default'`) showing the operator's current
text against the new default — the operator decides, so their edits always
win. A newer default version replaces a still-pending older proposal for
the same key. A retired default still gets the proposal (the operator may
want the improved version back). A default removed from code leaves its
entry alone. Table `playbook_defaults_seen(default_key, version)` tracks
this.

Accepting applies the op to `playbook_entries`. The operator can edit a
proposal's text before accepting. Direct operator edits on the dashboard are
recorded as `proposed_by: human`, auto-accepted, so the proposal table is
the full change log of the site playbook.

### Learning loop

Signals that feed proposals:

- Operator reopens a finding the AI or a rule closed ("this was wrong",
  note required) → `human_reopened`.
- Operator closes an attention item as **Not a concern** (note optional but
  prompted) → `human_closed_not_concern`. A false alarm: the playbook was
  missing something.
- Operator closes as **Handled** → `human_closed_handled`. Confirms the
  attention call was right; also tells Claude what action was taken
  (e.g. "added block policy"), which is context for future rechecks.
- Recurring patterns Claude notices across the findings it analyzes in a run.

Rules run before the AI, so a playbook entry can't undo a wrong
**rule** close. When the operator reopens a rule-closed finding, Claude's
proposal should say so in its rationale ("rule X closed this; consider
narrowing it") so the operator can fix the rule in code. The playbook only
governs AI verdicts.

At the end of each run, the triage procedure has Claude call
`get_feedback` (history rows of the three human kinds with
`feedback_considered_at IS NULL`), propose entries/edits/retirements where
warranted via `propose_playbook_change`, then `mark_feedback_considered`
for the rows it reviewed (whether or not it proposed anything).

### MCP surface

- Server `instructions`: one paragraph — this is a triage queue; start with
  the `triage` prompt or `get_playbook` and follow it.
- **Prompt `triage`**: returns the full assembled playbook plus the run
  procedure (fetch pending → for each, get context → decide → submit → then
  feedback/proposals). In Claude Code this is
  `/mcp__unifi-siem-lens__triage`.
- `get_playbook` — the same assembled playbook as a tool result, for clients
  or `claude -p` invocations where MCP prompts aren't usable.
- `get_pending_analyses` — pending requests with a one-line finding summary
  each, recheck flag, severity; oldest first.
- `get_analysis_context(id)` — as above.
- `submit_analysis(id, verdict, risk_level, summary, reasoning,
  recommended_action?, why_now?, cited_entries?)` — validates the
  conditional requirements (`recommended_action` for attention, `why_now`
  for rechecks); still throws on already-answered/nonexistent ids.
- `get_feedback`, `mark_feedback_considered(ids)`,
  `propose_playbook_change(op, entry_id?, title, body, rationale,
  evidence)`, `list_playbook_proposals(status?)` (so Claude doesn't
  re-propose something pending or rejected).

**Running it.** README documents both: interactive
(`/mcp__unifi-siem-lens__triage`) and a cron line on the workstation using
`claude -p` with `--allowedTools` scoped to the lens's MCP tools (plus
`unifi-siem` / `unifi` read-only tools if wanted). The builder must verify
whether `claude -p` can invoke an MCP prompt as a slash command; if not, the
cron prompt is plain text: "Call the unifi-siem-lens get_playbook tool and
follow it."

### Dashboard

- **Needs attention** (default view, sorted by severity): each card shows
  the AI's summary, risk, **recommended UniFi action**, `why_now` (with a
  "back after you closed it" marker when `reopen_count > 0`), cited playbook
  entries, a collapsible history timeline, and actions: **Handled** /
  **Not a concern** (each with a note box), **View raw events**.
- **Queue strip** above it, always visible: "N findings waiting for AI
  analysis · oldest Xh · run `/mcp__unifi-siem-lens__triage`" — expandable
  to list them. Empty queue says when the last analysis was submitted.
- **Closed**: searchable/filterable by `closed_by` and text; each row shows
  the reason, and has **This was wrong** (note required → `attention`) and
  **Re-analyze**.
- **Playbook** page: pending proposals (diff-style for edits, with
  rationale and evidence links to findings; accept / edit+accept / reject
  with note), active entries (edit/retire inline), and the change log.
- KPI tiles: replace status-based counts with attention count, queue size
  and age, closed in the last 7 days split by rule/AI/human.

### API changes

- `GET /api/findings?view=attention|triaging|closed|all` (replaces
  `status=`), plus `closed_by=` and `q=` for the closed view. No `view`
  means `attention` + `triaging` (open work); `KpiStats` moves to dedicated
  counts from `/api/queue` and a closed-in-7-days summary.
- `POST /api/findings/:id/close {kind: 'handled'|'not_concern', note?}`
- `POST /api/findings/:id/reopen {note}` — closed → `attention`.
- `POST /api/findings/:id/reanalyze` — closed → `triaging` + queued.
- `GET /api/findings/:id/history`
- `GET /api/queue` — `{ count, oldest_created_at, last_answered_at }`, where
  `last_answered_at` = `MAX(answered_at) WHERE source = 'ai'` (rule rows are
  answered constantly and would hide when Claude last ran).
- Playbook: `GET /api/playbook`, `GET/POST /api/playbook/proposals`,
  `POST /api/playbook/proposals/:id/accept {edited_title?, edited_body?}`,
  `POST /api/playbook/proposals/:id/reject {note?}`,
  `PUT /api/playbook/entries/:id`, `POST /api/playbook/entries/:id/retire`.
- Remove `POST /findings/:id/status` and the old `analyze` endpoint
  (replaced by `reanalyze`).

### Migration (lens.db migration 3)

New `NOT NULL` columns are added with defaults (`last_activity_at TEXT NOT
NULL DEFAULT ''`, `reopen_count ... DEFAULT 0`) since `ALTER TABLE ADD
COLUMN` can't add a non-null column without one; the SQL below then fills
them.

- `dismissed` → `closed`; `closed_by` = `rule` if the latest answered
  analysis is rule-sourced, `ai` if AI-sourced, else `human`;
  `closed_reason` = that analysis's recommendation, else
  "Dismissed before triage redesign". `closed_at` = latest `answered_at` or
  `last_seen`.
- `resolved` → `closed`, `closed_by: system`, reason "Condition cleared
  (pre-redesign auto-resolve)".
- `acknowledged` → `attention`. `new` → `triaging`, with a pending request
  created if it has none.
- `last_activity_at` = `last_triaged_at` = `closed_at` (for open findings:
  `last_seen`). Deliberately **not** `last_seen` for closed ones: `last_seen`
  is the last trigger-application run time, often later than the
  dismissal, which would make hundreds of findings look like they have new
  activity and flood the first recheck. Only activity after the migration
  counts toward reopening.
- One `finding_history` row per finding (`kind: 'created'`, summary noting
  migration) so timelines aren't empty.

Live instance today: all 748 are `dismissed`, so the attention view starts
empty and the first daily recheck decides which ones have meaningful new
activity.

### Rollout

1. Ship the code; migration runs at startup.
2. Default entries seed automatically. Then add this site's own knowledge:
   run a Claude session that has the existing triage
   knowledge (the operator's per-project Claude memory notes) and have it
   split it: mechanical host/port facts go into the `HOMELAB_SERVICES_PATH`
   registry, judgment calls go in as `propose_playbook_change` proposals
   the operator approves on the Playbook page. Not in code, since the
   content is private.
3. Set up the workstation cron (optional).

### Existing pieces that stay

Rule triage (`ruleTriage.ts`, `tryRuleTriage`), its admin backfill (now over
`triaging` findings only), `IGNORED_SIGNATURE_KEYS`, the read-only
sink DB, enrichment, and MCP auth. `CLAUDE.md` (including its out-of-date
three-rule list; `ruleTriage.ts` has seven) and the lifecycle section of
`2026-08-31-lens-design.md` are updated to point here.

### Delivery phases

Each phase ships and is useful on its own:

- **A — Pipeline and attention view.** Status model, history, `matchRules`
  split, auto-queue, daily recheck, cancellation and transitions, the
  `submit_analysis` changes and code guardrails, migration, Needs
  attention / Closed / queue strip UI. Delivers the main value: noise off
  the default page.
- **B — Core playbook.** `core.md`, the `triage` prompt, `get_playbook`,
  server `instructions`, README run instructions (manual + cron).
- **C — Learning.** Site entries, proposals, default seeding, feedback
  tools, Playbook page, registry read-only view. Until C lands,
  `get_playbook` serves the core alone.

## Left to the builder

- Exact core playbook wording (within the structure and guardrails above).
- Visual design of the cards, timeline and playbook diff view, consistent
  with the current dashboard.
- Whether the daily recheck shares a scheduler slot with the anomaly check
  or gets its own.
- Shape of the recheck before/after summary in the context bundle.
- Test layout, following the existing vitest structure (findings lifecycle
  and recheck logic as pure functions with unit tests, as `findings.ts` is
  today).
