# UniFi SIEM Lens

Visualization dashboard and code-driven analysis layer for UniFi IDS/IPS
security events — trend charts, anomaly/repeat-offender detection, and a
automatic triage pipeline that ends in either a closed finding or a short
"needs attention" list, with a Claude Code session doing the AI step over
MCP, without this service needing any API key of its own.

![UniFi SIEM Lens dashboard: triage KPI tiles (needs attention, AI queue, closed in 7 days, 24h events), trend charts, the AI queue strip with its copy-prompt button, and a Needs attention card with Claude Code's recommended action. Demo data only.](docs/images/dashboard.png)

## Why this exists

This is the third of three companion projects for running an LLM against a
UDM Pro:

- [`unifi-mcp-server`](https://github.com/ianchesal/unifi-mcp-server) —
  exposes the UniFi Network API (firewall rules, networks, clients, traffic
  rules, port forwarding, monitoring) as MCP tools.
- [`unifi-siem-sink`](https://github.com/ianchesal/unifi-siem-sink) —
  listens for UniFi's SIEM/syslog export and stores IPS/IDS and
  Security-category events (the one thing the Network API doesn't expose)
  in SQLite, queryable over MCP.
- **`unifi-siem-lens`** (this project) — sits on top of `unifi-siem-sink`'s
  event store. Where the other two projects hand raw data to an LLM one
  query at a time, lens does the first pass itself: it runs scheduled,
  code-driven heuristics (new signature/source-IP detection, internal-source
  flagging, repeat-offender tracking, statistical anomaly detection) against
  the sink's event history, turns anything interesting into a *finding*, and
  renders trends and findings on a dashboard. Every new finding goes
  through a triage pipeline: first a handful of code-driven rules (a trusted
  admin's own console login, WAN/operational noise, a blocked reputation/
  blocklist IDS hit, ...) close it on the spot — see
  [Rule-based auto-triage](#rule-based-auto-triage) — and anything they
  don't fully explain is queued automatically for a Claude Code session
  (running on your Claude subscription, no separate API key). It checks in
  over MCP, reasons about the finding with the real events as context, and
  either closes it or flags it as **needs attention** with what to do in the
  UniFi console. Closed findings that see new activity are rechecked daily.

Run all three and an LLM gets full visibility into the network (via
`unifi-mcp-server`), full visibility into the security event stream (via
`unifi-siem-sink`), and a standing analyst that's already triaged the noise
before you ever open a chat (via `unifi-siem-lens`).

## Quick Start (Docker)

Requires `unifi-siem-sink` **v1.0.3 or later** already running as a
container — lens reads its event database read-only via `--volumes-from`.
Against an older sink, `/health` reports a schema mismatch (the
`source_client_*` / `dest_client_*` columns) and client findings are
disabled; IP and signature analysis keeps working.

### 1. Create a `.env` file

```bash
SINK_DB_PATH=/data/events.db
LAN_CIDRS=10.0.0.0/8,192.168.0.0/16,172.16.0.0/12
MCP_SECRET=<choose-a-strong-secret>
```

`SINK_DB_PATH=/data/events.db` matches the mount point `unifi-siem-sink`
uses internally — see step 2.

### 2. Run the container

```bash
docker run -d \
  --name unifi-siem-lens \
  --env-file .env \
  -p 3002:3002 \
  -v unifi-siem-lens-data:/lens-data \
  --volumes-from unifi-siem-sink:ro \
  ghcr.io/ianchesal/unifi-siem-lens:latest
```

`--volumes-from unifi-siem-sink:ro` mounts the sink container's `/data`
volume (containing `events.db`) into this container read-only, at the same
path. If your sink container has a different name (check with
`docker ps`), or you're running it via `docker compose` under a different
project name, adjust `unifi-siem-sink` above to match.

### 3. Open the dashboard

`http://<homelab-ip>:3002`

### 4. Add to Claude Code for the analysis handoff

```json
{
  "mcpServers": {
    "unifi-siem-lens": {
      "type": "http",
      "url": "http://<homelab-ip>:3002/mcp",
      "headers": { "Authorization": "Bearer <your-MCP_SECRET>" }
    }
  }
}
```

Then, in a Claude Code session with this configured, run
`/mcp__unifi-siem-lens__triage`. In general the command is
`/mcp__<server name>__triage`, where the server name is the key you used under
`mcpServers`. Findings the rules couldn't close are queued automatically; the
session loads the lens's triage playbook, fetches the queue, reasons about each
finding with the actual event context, and posts a verdict (close, or needs
attention) back, which then shows up next to the finding. See
[Running triage](#running-triage) for running it on a schedule.

## Dashboard & MCP tools

| Surface | What it gives you |
|---|---|
| Dashboard (`/`) | Triage KPI tiles (needs attention, AI queue, closed in 7 days, 24h events), a queue strip (with a button that copies the `/mcp__unifi-siem-lens__triage` command), events-over-time / top signatures / top source IPs / severity charts, and two findings views: **Needs attention** (default; each card says what to do in UniFi and why, with the finding's history, and offers Handled / Not a concern; a card with no current AI recommendation, such as one you reopened, also offers Re-analyze) and **Closed** (searchable, filterable by who closed it: rule, AI, human, system; each row has its history and offers **This was wrong** (reopen, with a note) or Re-analyze). A verdict that cited playbook entries shows them as **Relied on**, linked to the Playbook page. The header's **Playbook** link shows how many proposals are pending. |
| Playbook (`/playbook`) | The site knowledge triage relies on: pending proposals, entries, the change log and your homelab registry (see [Playbook](#playbook)). |
| Admin (`/admin`) | One-off maintenance actions — currently just the rule-triage backfill (see below). |
| `GET /health` | Liveness + sink DB / schema-contract status. |
| `GET /api/findings` | List findings. `view=open\|attention\|triaging\|closed\|all` (default `open`), optional `closed_by`, `q`, and `limit`/`offset` (paginated as `{ items, total }`). Each item carries its latest answered analysis and the note of its latest reopen (`latest_reopen_note`). |
| `GET /api/findings-summary` | Counts for the KPI tiles: `{ attention, triaging, closed_last_7d }`. |
| `GET /api/findings/:id/history` | A finding's audit trail (created, rule/AI/human decisions, rechecks, reopens). |
| `GET /api/findings/:id/activity` | The raw sink events behind a finding. |
| `POST /api/findings/:id/close` | Operator closes an `attention` finding: `{ kind: "handled" \| "not_concern", note? }`. |
| `POST /api/findings/:id/reopen` | Operator reopens a `closed` finding back to needs attention: `{ note }` (required). |
| `POST /api/findings/:id/reanalyze` | Re-queue a `closed` or `attention` finding for AI analysis. |
| `GET /api/analysis-requests` | Pending requests, or all of a finding's with `?findingId=`. |
| `GET /api/queue` | AI queue stats for the queue strip. |
| `POST /api/admin/backfill-rule-triage` | Re-checks every never-decided `triaging` finding against the auto-triage rules; returns `{ checked, closed, byRule }`. |
| `GET /api/playbook` | `{ entries, registry }`: active entries first, then retired, plus the homelab registry. `is_default` marks an active entry that is still shipped default text; it is also true for every retired entry, so only active ones should be labelled. |
| `GET /api/playbook/proposals` | Proposals, newest first (`status=pending\|accepted\|rejected`, optional), each with the findings cited as evidence (`missing_evidence_count` counts cited findings that no longer exist) and the entry it would change. |
| `POST /api/playbook/proposals` | Add an entry yourself: `{ title, body }`. |
| `POST /api/playbook/proposals/:id/accept` | Apply a pending proposal, optionally with your own text: `{ edited_title?, edited_body? }`. |
| `POST /api/playbook/proposals/:id/reject` | Reject a pending proposal: `{ note? }`. |
| `PUT /api/playbook/entries/:id` | Edit an entry (reactivates a retired one): `{ title, body }`. |
| `POST /api/playbook/entries/:id/retire` | Retire an entry: `{ note? }`. |
| `triage` (MCP prompt) | The triage playbook plus run procedure. In Claude Code: `/mcp__unifi-siem-lens__triage`. |
| `get_playbook` (MCP) | The same playbook as a tool result, for clients that can't use MCP prompts. |
| `import_knowledge` (MCP prompt) | Moves triage knowledge from a session's notes into proposals and a registry fragment. In Claude Code: `/mcp__unifi-siem-lens__import_knowledge`. |
| `get_pending_analyses` (MCP) | List queued analysis requests, highest severity first (`limit?`). |
| `get_analysis_context` (MCP) | Full context for one request, built when you fetch it: the finding, its history, prior analyses, recent events, activity since the last decision, and (for rechecks) before/after activity summaries. |
| `submit_analysis` (MCP) | Post a verdict (`close` or `attention`) with risk level, summary, reasoning and the ids of any playbook entries it relies on (`cited_entries`); see [Verdict guardrails](#verdict-guardrails). |
| `get_feedback` (MCP) | Your Handled / Not a concern / This was wrong decisions that no run has reviewed yet, oldest first (`limit?`, 1–100, default 50). A reopen also says what it undid. |
| `mark_feedback_considered` (MCP) | Mark those rows reviewed: `{ ids }`. |
| `propose_playbook_change` (MCP) | Propose adding, editing or retiring an entry: `op`, `entry_id?`, `title`, `body`, `rationale`, `evidence`. It stays pending until you decide. |
| `list_playbook_proposals` (MCP) | List proposals (`status?`), so a run doesn't repeat a pending or rejected one. |

The playbook `POST` and `PUT` endpoints require a JSON body, even `{}`.

## Running triage

The lens has no LLM access of its own. A Claude Code session does the analysis
over MCP, guided by a **triage playbook** the lens serves: the run procedure,
when to close and when to send a finding to Needs attention, which UniFi
actions to recommend, and guardrails the playbook can't be talked out of. It
also lists your `TRUSTED_ADMIN_NAMES`, added at request time, so Claude
applies the same trusted-admin rule the rules do. The
playbook's core is code-owned (`server/src/mcp/playbook/`), so it is public and
generic. What is specific to your network is added from the entries you have
approved (see [Playbook](#playbook)). The MCP server's `instructions` point any
client at it. Each run ends by reviewing your recent decisions and proposing
changes to those entries, even when the queue is empty.

**Interactively:** run `/mcp__unifi-siem-lens__triage` in a Claude Code
session that has the lens configured. The dashboard's queue strip has a button
that copies the command.

**On a schedule:** run it non-interactively from cron on the machine where you
use Claude Code, at most once a day. The run handles up to 25 queued findings
and says so if more remain. For example, every morning at 07:00:

```cron
0 7 * * * cd "$HOME" && "$HOME/.local/bin/claude" -p "/mcp__unifi-siem-lens__triage" --allowedTools "mcp__unifi-siem-lens" >> "$HOME/lens-triage.log" 2>&1
```

cron runs with a minimal `PATH`, so give `claude` by its absolute path. Use
whatever `command -v claude` prints in your shell; `$HOME/.local/bin/claude`
is the native installer's default.

`--allowedTools "mcp__unifi-siem-lens"` pre-approves every tool on the lens's
MCP server and nothing else. That includes proposing playbook changes, which
still wait for your approval. Add `mcp__unifi__list_clients` if you also run
`unifi-mcp-server` and want findings enriched with client names. `claude -p`
picks up the MCP server from your Claude Code config (or pass `--mcp-config`).
It expands the prompt's slash command the same way an interactive session does.
This was checked with Claude Code 2.1.332.

## Playbook

The second layer of the triage playbook is **site knowledge**: short, specific
entries about your network, such as which host runs a VPN client or which
blocked scans are expected. They live in `lens.db`, never in this repo. Active
entries are served to Claude with their ids, read fresh each time, so a change
you approve applies from the next run. A verdict that relies on an entry cites
it, and the card shows it under **Relied on**. Name the exact hosts, ports,
signatures or CIDRs: the playbook tells Claude to apply an entry only to what it
names.

### The Playbook page

`/playbook` has four parts:

- **Pending proposals:** who proposed each one (Claude, or a shipped default
  update), why, and the findings behind it with their history. An edit shows the
  current and proposed text side by side; a retire shows the text being retired.
  **Accept**, **Edit & accept** (not for a retire) or **Reject** with an optional
  note.
- **Active entries:** **Add entry**, **Edit** or **Retire**. Retired entries sit
  in a collapsed group; editing one reactivates it.
- **Change log:** every accepted and rejected proposal, with the id of the entry
  it changed (an add shows none). A retire records the retired entry's own text,
  whatever the proposal said.
- **Homelab registry:** your
  [homelab services file](#homelablocal-service-enrichment), read-only.

Every change to an entry is recorded as a proposal: your own adds, edits and
retirements are saved as proposals accepted on the spot, so the change log is
complete. No MCP tool can apply a change. Applying one goes through the
dashboard's REST API, which has no authentication, so anyone or anything that
can reach the dashboard can approve proposals (see `HOST` under
[Environment Variables](#environment-variables)).

### Default entries

Lens ships five generic entries and adds them at startup:

- blocked inbound scanner fingerprints;
- Git over SSH to GitHub flagged as an outbound SSH scan;
- generic exploit signatures on a VPN client (closes nothing until another entry
  names the host);
- device-status events;
- repeated exploit attempts against a port-forwarded service.

They are yours to edit or retire, and an upgrade never overwrites them. When a
release changes a default's text, it arrives as a pending edit proposal against
your current text, replacing any older update you haven't decided. That includes
a default you retired; accepting the proposal brings it back.

A default you haven't edited is marked **default**, and can't on its own justify
closing traffic that wasn't blocked (see
[Verdict guardrails](#verdict-guardrails)).

### The learning loop

Your decisions on findings are the input:

- **Handled:** confirms the finding needed action; your note says what you did.
- **Not a concern:** a false alarm; the playbook may be missing something.
- **This was wrong:** a close you reopened, with the reason.

At the end of each triage run Claude reads the decisions it hasn't reviewed,
proposes new entries, edits or retirements where one is warranted, and marks
those decisions reviewed. Nothing changes until you accept a proposal. Rules run
before the AI, so no entry can undo a wrong rule close: if reopening one leads to
a proposal, it should say which rule to consider narrowing in code.

### Importing existing knowledge

If you already keep triage knowledge in Claude's memory or your own notes, run
`/mcp__unifi-siem-lens__import_knowledge` in a Claude Code session that has them
and has the lens configured. It checks the current playbook and proposals first,
then sorts what it knows into three groups:

- **Host and port facts that are always benign:** printed as a
  `homelab-services.json` fragment. Check it, merge it into your file
  (`HOMELAB_SERVICES_PATH`) and restart lens.
- **Judgment calls:** one proposal each, for you to approve on the Playbook page.
- **Stale or unverifiable notes:** listed for you, not proposed.

The prompt tells Claude not to write any file itself.

## Finding lifecycle

Every finding is in one of three states:

- **`triaging`** — waiting on the pipeline: the rules didn't close it, so an
  analysis request is queued for Claude Code.
- **`attention`** — the AI decided you should do or verify something in the
  UniFi console. The card says what (`recommended_action`) and, for a
  finding that came back, why now (`why_now`).
- **`closed`** — handled, with `closed_by` (`rule`, `ai`, `human`, or
  `system` for findings migrated from the old status set) and a reason.

Each state change is written to the finding's history. A closed finding that
sees new activity is rechecked daily (at most once per 24h): if a rule still
explains everything since the last decision it stays closed, otherwise it
goes back to the AI queue as a recheck, which must explain what changed.
Gaining an `internal_source` trigger sends a rule-closed finding back to
`triaging`. Triggers no longer change status on their own.

Findings from before this model are migrated by lens.db migration 4.

### Verdict guardrails

`submit_analysis` rejects (leaving the request pending so it can be retried):

- a blank `summary` or `reasoning`;
- an `attention` verdict without `recommended_action` (what to do in the
  UniFi console);
- a recheck without `why_now`;
- a cited playbook entry id that doesn't exist or is retired;
- a `close` while unblocked IPS alerts exist since the last decision, or when
  the sink can't be checked (fails closed), unless it cites at least one entry
  you stand behind.

An entry you stand behind is an active one that you wrote or edited, or that
came from a Claude proposal you accepted. Shipped default text alone doesn't
count. Accepting a default's update proposal as proposed makes or leaves the
entry a default, even if you had edited it before; **Edit & accept** with your
own changes, or saving the entry from the Playbook page, makes it yours. The
server checks who stands behind a cited entry, not whether it
covers the traffic: applying entries literally is the playbook's rule. When
every IPS alert was blocked, a `close` needs no citation.

## Client findings

Some UniFi Security events (IPS alerts, firewall blocks, honeypot hits)
identify the LAN host only by client name/MAC, with no IP — the sink stores
those with `source_ip` NULL and the host in `source_client_name` /
`source_client_mac`. Lens turns each such MAC into a `client` finding (shown
with its latest known client name next to the MAC):

- `new_client` the first time a MAC appears, plus `internal_source` (a
  UniFi-named client is on the LAN by definition), so a new client ranks
  alongside an internal IP finding.
- `repeat_offender` when the client is active on 3+ distinct days in 14,
  counting only those client-only rows.

On the first run after upgrading, every client already in the sink's history
gets a finding, so past client-only alerts surface once for review. Client
findings are never auto-triaged by the rules below, and are tracked
separately from any IP finding for the same host (IPs change under DHCP;
MACs don't).

## Rule-based auto-triage

Most findings a live network throws off don't need an LLM at all: your own
console logins, the gateway's WAN-health blips, and routine reputation-list
scans that UniFi already auto-blocked. Rather than queuing every one of
these for a Claude Code session, lens checks each new finding against a
set of rules the moment it's detected, and closes it — with a canned,
code-generated reason, no Claude Code session involved — if every event
behind it is fully explained by one rule:

1. **Trusted admin login** — a console login from an admin name in
   `TRUSTED_ADMIN_NAMES` (see [Environment Variables](#environment-variables) below; empty by default, so this rule never fires unconfigured).
2. **Operational noise** — WAN/device-health telemetry, not a security
   signal.
3. **Low-signal category** — routine `system` / `adminactivity` / `detection` events.
4. **Reputation/blocklist scan** — a blocked hit from a known
   reputation-feed IDS signature family (`SAFE_SIGNATURE_PREFIXES`).
5. **Homelab service egress** — blocked outbound hits on a documented
   homelab service's own port (needs `HOMELAB_SERVICES_PATH`).
6. **Exposed-host scan** — blocked inbound hits on a host marked
   `wanExposed` in the homelab services file.
7. **Ignored signature** — an exact signature excluded from analysis
   (currently the Protect doorbell ring).

A finding with an `internal_source` trigger can only be closed by the
operational-noise rule: an internal host tripping any other rule is the
"possible compromised host" case and always goes to the AI.

A finding that isn't *fully* explained by a rule (mixed events, an
unrecognized signature, an untrusted admin name) is queued for Claude Code
automatically. Client findings never match a rule and are always queued.

Because the rules only run when a finding is created (and on the daily
recheck), findings still `triaging` from before you configured
`TRUSTED_ADMIN_NAMES` (or before you upgraded) never get a rule pass on
their own. Visit **`/admin`** and click **Run backfill** to sweep the
rules over never-decided `triaging` findings, using each finding's original
detection window — safe to run repeatedly; findings the AI already decided
or the operator re-queued are left alone.

## Homelab/local-service enrichment

An IDS finding pointing at `192.0.2.10:8989` means nothing to a Claude
Code session unless it also knows `192.0.2.10:8989` is your own Sonarr
instance, not a mystery host. `HOMELAB_SERVICES_PATH` points lens at a
local JSON file mapping LAN IPs to the services running on them (typically
the containers on a homelab/NAS box), so that context is attached
automatically whenever a finding involving that IP is queued for analysis.

This is deliberately **not** something you configure by pointing lens at
your Docker Compose files or infrastructure repo directly — the file is a
static, hand-maintained snapshot that lives outside git, so your homelab's
layout never ends up in this (public) repo's history or a published Docker
image.

**Setup:**

1. Copy the template: `cp server/homelab-services.example.json server/data/homelab-services.json`
   (the default `HOMELAB_SERVICES_PATH`; set the env var if you'd rather
   keep it elsewhere).
2. Fill in your own hosts and ports:

   ```json
   {
     "192.0.2.10": {
       "label": "example homelab server",
       "notes": ["Plex remote access is in use on this host"],
       "services": [
         { "port": 8989, "name": "sonarr", "description": "TV show PVR" },
         { "port": 8080, "name": "qbittorrent", "description": "torrent client WebUI" }
       ]
     }
   }
   ```

   Keys are the destination IPs as they appear in `events.db`; `services`
   is matched against each event's `dest_port`. An IP present with no
   matching port still returns the host `label`, so you get partial credit
   ("this is at least *a* known host") even for ports you haven't listed.
   `notes` is optional and free-text — use it for standing, host-wide facts
   that don't map to a single port (e.g. "Plex remote access is in use" or
   "this box is intentionally exposed to the internet via Cloudflare
   Tunnel"). Every note is attached to every event matching that host,
   regardless of which port it hit.
3. Restart lens. The file is loaded once at startup — like `SINK_DB_PATH`,
   a missing or malformed file is a silent no-op, never a startup failure.

**What it affects:** the context bundle built when a finding is fetched by a
Claude Code session (`get_analysis_context`) — each recent event in that bundle
gets a `homelab: { host, service }` field the analyzing session sees alongside
the raw event. The `homelab_service_egress` and `exposed_host_scan` auto-triage
rules read it too, and the [Playbook page](#the-playbook-page) shows it
read-only, so anyone who can reach the dashboard can read it. Lens loads the
file at startup; restart after editing it.

Put facts a rule can match mechanically (this host and port are benign, this
host is exposed to the WAN) here, and judgment calls in the
[playbook](#playbook).

`server/homelab-services.example.json` (checked in) documents the shape
with placeholder values; `server/data/homelab-services.json` (gitignored,
matching the `data/` pattern used for `lens.db`) is where your real
mapping goes — see [Environment Variables](#environment-variables) below
for `HOMELAB_SERVICES_PATH`.

## Claude Code skill: analyzing findings

If you're working in this repo with Claude Code, `server/.claude/skills/analyzing-findings/`
ships a skill (scoped to the `server` workspace) for running triage from a
development session. It loads the served playbook with `get_playbook` and
follows it, the same as `/mcp__unifi-siem-lens__triage`, then adds one
repo-only step: it flags findings that look like candidates for a new
[rule-based auto-triage](#rule-based-auto-triage) rule (a low-risk,
fully-explained pattern that has recurred and isn't already covered by a rule
in `ruleTriage.ts`), without writing the rule code itself. That stays a
deliberate, reviewed change.

Ask a Claude Code session working in this repo to "reanalyze findings", or
invoke it directly as `/server:analyzing-findings`.

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SINK_DB_PATH` | yes | — | Path to `unifi-siem-sink`'s `events.db`, opened read-only |
| `MCP_SECRET` | yes | — | Bearer token clients must send as `Authorization: Bearer <MCP_SECRET>` to call `/mcp` |
| `PORT` | no | `3002` | Port the dashboard/API/MCP server listens on |
| `HOST` | no | `127.0.0.1` | Bind address. Defaults to localhost-only — the dashboard/REST API (including playbook approvals) have no authentication of their own (only `/mcp` does, via `MCP_SECRET`), so widen this deliberately (e.g. to your LAN interface IP, or `0.0.0.0`) only if you want the dashboard reachable from other devices |
| `LENS_DB_PATH` | no | `./data/lens.db` (`/lens-data/lens.db` in Docker) | Lens's own SQLite store — findings, baselines, seen-entity tracking, analysis-request queue, playbook entries and proposals |
| `LAN_CIDRS` | no | *(none)* | Comma-separated CIDRs treated as internal/LAN for the internal-source heuristic, e.g. `10.0.0.0/8,192.168.0.0/16` |
| `TRUSTED_ADMIN_NAMES` | no | *(none)* | Comma-separated admin display names (as they appear in UniFi's own audit log, e.g. `Ian C.`) that auto-dismiss `new_source_ip` findings which are entirely explained by that admin logging into the UniFi console. Empty by default — this rule never fires until configured |
| `SAFE_SIGNATURE_PREFIXES` | no | `ET DROP,ET CINS,ET TOR,ET COMPROMISED,ET DSHIELD` | Comma-separated IDS/IPS signature prefixes (Emerging Threats' reputation/blocklist rule-family naming convention) that auto-dismiss a finding when every backing event is a blocked hit from one of these signature families. Prefixes are matched via SQL `LIKE` (case-insensitive; a configured prefix containing `%` or `_` acts as a wildcard) — keep entries specific |
| `UNIFI_MCP_SERVER_URL` | no | *(unset)* | Optional `unifi-mcp-server` MCP endpoint, e.g. `http://localhost:3000/mcp`. When set, lens resolves source IPs to known client names and pulls a firewall-rule summary into analysis context. Left unset, this enrichment is skipped entirely — never required |
| `UNIFI_MCP_SERVER_TOKEN` | no | *(unset)* | Bearer token sent as `Authorization: Bearer <token>` when calling `UNIFI_MCP_SERVER_URL`, for `unifi-mcp-server` instances that require auth. Ignored if `UNIFI_MCP_SERVER_URL` is unset |
| `HOMELAB_SERVICES_PATH` | no | `./data/homelab-services.json` | Path to a local, never-committed JSON file mapping LAN host IPs to the services running on them (e.g. a homelab server's Docker containers — see `server/homelab-services.example.json` for the shape). Analysis context labels event destinations that match an entry (e.g. `192.0.2.10:8989` → `sonarr`) instead of leaving them as bare IP:port. Missing file is a no-op — this enrichment is entirely optional |
| `LOG_LEVEL` | no | `info` | `error` \| `warn` \| `info` \| `debug` |

---

## Development (Running from a Repo Clone)

### Setup

```bash
git clone https://github.com/ianchesal/unifi-siem-lens
cd unifi-siem-lens
npm install
cp server/.env.example server/.env
# edit server/.env: set SINK_DB_PATH to your unifi-siem-sink events.db, and MCP_SECRET to a strong secret
# (docker cp unifi-siem-sink-unifi-siem-sink-1:/data/events.db ./server/data/events.db)
```

### Run with Docker Compose

```bash
docker compose up -d --build
```

Exposes `3002/tcp` for the dashboard/API/MCP endpoint. Requires
`unifi-siem-sink` running as a container named `unifi-siem-sink` (adjust
`docker-compose.yml`'s `volumes_from` if yours is named differently) —
lens's own state persists in the `lens-data` named volume.

### Run locally

```bash
npm run dev
```

Starts the server (`http://localhost:3002`) and the Vite dev server
(`http://localhost:5173`, proxying `/api` to the server) together. The
server's `/mcp` endpoint is served directly on port 3002 and is not
proxied through Vite.

> **Note:** If `npm run dev -w server` fails to boot (a known issue on
> Node 24.x/25.x — see `unifi-siem-sink`'s CLAUDE.md for details), use
> `npm run build -w server && npm run start -w server` instead, alongside
> `npm run dev -w web` for the frontend.

### Production build

```bash
npm run build
npm start
```

Builds both packages and serves the built dashboard + API + MCP endpoint
from a single process on `PORT` (default `3002`).

### Tests

```bash
npm test          # server test suite (vitest)
npm run lint       # biome (server) + oxlint (web)
```

## Cutting a release

Releases are tag-driven. Pushing a `v*` tag to GitHub triggers
`.github/workflows/release.yml`, which:
- Builds and pushes a Docker image to `ghcr.io/ianchesal/unifi-siem-lens`
  (tagged `latest`, `{major}.{minor}`, and `{version}`)
- Creates a GitHub Release with auto-generated notes

**Steps to release:**

1. Ensure all changes are merged to `main` and CI is green.
2. Decide the new version (follows semver: `MAJOR.MINOR.PATCH`).
3. Update `"version"` in `package.json` (root) to the new version.
4. Commit: `git commit -m "chore: release v{version}" package.json`
5. Tag: `git tag v{version}`
6. Push both: `git push origin main && git push origin v{version}`

The release workflow fires automatically on the tag push. No manual Docker
build or GitHub Release creation needed.

## License

[MIT](LICENSE)
