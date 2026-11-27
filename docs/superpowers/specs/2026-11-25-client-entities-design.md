> Note (2026-11-26): the sink and UniFi MCP server have since been merged into this service; see 2026-11-26-unifi-power-tools-merge-design.md. References here to a read-only sink DB or enrichment over MCP describe the old split.

# Client entities (sink v1.0.3) — design

## Intent

unifi-siem-sink v1.0.3 (https://github.com/ianchesal/unifi-siem-sink/pull/43)
stopped attributing client-only Security events to the gateway. When UniFi
identifies a LAN host only by name/MAC, `source_ip` is now NULL and the host
lives in `source_client_name` / `source_client_mac`. Lens's IP-keyed checks
(`new-source-ip`, `internal-source`, `repeat-offender`) skip NULL-IP rows, so
alerts like the VenomRAT/NanoCore C2 keepalives from tranquility only surface
as `new_signature` findings. Lens should treat such a LAN client as an entity
of its own so host-level checks fire on it.

## Goals

- A third finding entity type, `client`, keyed by `source_client_mac`, for
  *client-only Security events* (defined below).
- Host-level triggers on client findings: `new_client`, `internal_source`,
  `repeat_offender`.
- Historical client-only alerts (including the 4 re-parsed rows) surface once.
- `verifySchema` requires the 4 new sink columns.

## Non-goals

- Merging a client finding into an IP finding for the same host (no MAC→IP
  correlation). Decided: keep them separate — DHCP makes IPs unstable, MACs
  aren't.
- Rule-based auto-triage for client findings (the candidate filter restricts
  them to Security events; they stay for manual review).
- `dest_client_*` as an entity. When both ends are the same client only
  `source_client_*` is set and direction is unreliable, so the source client is
  read as "this host was one end of the flow."
- `unifi-mcp-server` enrichment for clients (`resolveClient` takes an IP).
- Supporting sink < v1.0.3 beyond what the schema check already gives.

## Anti-goals

- A client finding ever being keyed on a name alone (names change; rows with a
  name but no MAC are skipped).
- Any change in behavior for rows that do have a `source_ip`, or for
  IP/signature findings — including on a sink that fails the schema check.

## Approaches considered

1. **New `entity_type: 'client'`** (chosen). Extend `Finding['entity_type']`,
   add a client branch wherever code branches on entity type, add a
   `seen_clients` table. Touches more files but each follows an existing
   pattern and entity types stay cleanly separated.
2. Encode clients as `source_ip` findings with a `mac:` key prefix. Least code,
   but every IP-specific path (CIDR match, IP-keyed triage counts, enrichment)
   would need a guard, and a missed one is a silent wrong answer.
3. A separate client module/table/dashboard section. Most isolated, but
   duplicates the findings lifecycle, the most spec-critical code.

## Design

### Definitions

- **Client-only Security event:** an `events` row with
  `source_ip IS NULL AND source_client_mac IS NOT NULL AND category IN
  ('ips_alert', 'firewall_block', 'honeypot', 'security')`, excluding
  `IGNORED_SIGNATURE_KEYS`. The category list is what the sink maps
  `UNIFIcategory = 'Security'` to (`security` is its slug fallback for an
  unmapped Security subtype). The sink only nulls `source_ip` deliberately for
  Security events; a non-Security row could in theory also have a NULL IP and a
  MAC, and the category filter keeps those out.
- **Client key:** the MAC exactly as the sink stores it (lowercase,
  colon-separated). Lens does not re-normalise it.

### Schema

- `sinkDb.ts` `EXPECTED_COLUMNS` gains `source_client_name`,
  `source_client_mac`, `dest_client_name`, `dest_client_mac`.
- **Blast radius on an old sink stays limited to client features.** Existing
  queries are left untouched: `recentEvents`, `listEvents`,
  `eventsForSourceIp`, `eventsForSignature` and the triage count queries do
  *not* select the new columns. Only client-specific queries reference them,
  and those run inside the client `runCheck` / client API branches. So on a
  pre-v1.0.3 sink the schema check fails loudly (logged, `/health`), client
  checks fail in isolation, and everything else keeps working. (Raw events
  already carry the client fields in `raw`, so LLM context for IP/signature
  findings loses nothing.)
- `lensDb.ts` migration 3:
  `CREATE TABLE seen_clients (mac TEXT PRIMARY KEY, first_seen TEXT NOT NULL)`.
- `findings` table unchanged (already `UNIQUE(entity_type, entity_key)`).

### Analysis

- `findings.ts`: `entity_type` adds `'client'`; `TriggerType` adds
  `'new_client'` (weight 1, not standing — never auto-resolves, like
  `new_source_ip`).
- `newEntity.ts`: pure `detectNewClients(macs, seen)` mirroring
  `detectNewSourceIps`.
- New `sinkQueries.ts` helpers (client-only, so the old-sink isolation above
  holds): distinct client MACs over all history; client MACs active since a
  timestamp; distinct-day counts per client MAC since a timestamp; latest
  non-null name per MAC for a set of MACs; `eventsForClientMac(db, mac,
  limit = 20)`. All apply the client-only Security event definition.
- `runner.ts`, new `client` check in `runHourlyChecks` (own `runCheck`):
  - **New clients (seeding without a special case):** candidates = every
    distinct client MAC over *all* history minus `seen_clients`. On first run
    after deploy this surfaces every historical client (the seeding we
    agreed); after that it's equivalent to the 24h new-IP check. Same
    homelab-scale full-scan cost the repeat-offender check already accepts.
  - Each new MAC → `new_client` trigger, then `internal_source`, then
    `markSeenClient`.
  - MACs active in the trailing 24h window also get `internal_source` applied,
    matching the IP internal-source loop. Rationale for `internal_source` on
    every client: a UniFi-named client is LAN by definition (no CIDR check),
    and giving it the trigger puts client findings at the same severity as an
    internal IP finding (1 + 3 = 4) — the trigger carries no extra information
    for clients, it's there for consistent ranking.
  - No rule triage for client findings.
  - Seeded findings get `first_seen = now` (detection-run time, like every
    other finding), even when their events are weeks old. Accepted: the
    activity view shows the real event timestamps.
- `repeat-offender` check gains a parallel client pass: distinct
  `date(received_at)` per client MAC over the 14-day window, same
  `isSustained` threshold, same reevaluate / dropped-out-of-window handling
  restricted to `entity_type = 'client'`.
- `tryRuleTriage` returns `{ matched: false }` early for
  `entity_type === 'client'`, and its `else` becomes
  `else if (entity_type === 'signature')`. Without this the admin backfill
  would send a client finding down the signature branch with
  `splitSignatureKey(mac)`. The backfill also skips client findings so
  `checked` isn't inflated. Tested.

### API / MCP

- `/findings/:id/activity` and `/findings/:id/analyze` get a `client` branch
  using `eventsForClientMac`; `knownClient` is `null` for clients.
- `display_name`: computed per request, never stored. `GET /findings` attaches
  `display_name` to client findings in both response shapes (bare array and
  `{ items, total }`) via one query for the latest non-null
  `source_client_name` (by `received_at`) per MAC on the page; `null` when the
  sink is unavailable or the client has no name. Non-client findings don't get
  the field. The analyze context bundle includes it too.

### Web

- `web/src/icons.tsx`: `new_client` entries in `TRIGGER_ICONS` and
  `TRIGGER_LABELS` ("New client"); a client/device icon.
- `FindingsList.tsx`: `entityIcon` handles three types; label "client";
  `display_name?: string | null` on the `Finding` interface, shown alongside
  the MAC when present.

### Stale 192.168.1.1 data

No cleanup. The gateway still emits device-level events from 192.168.1.1, so
its finding and `seen_source_ips` entry would exist regardless. If that finding
is still open, the existing admin rule-triage backfill re-checks it against the
re-parsed rows. The 4 moved rows reach lens via client seeding.

### Tests

Because existing queries don't change, existing test `CREATE TABLE events`
schemas (`runner.test.ts`, `analysisRequests.test.ts`, `findings.test.ts`,
`sinkQueries.test.ts`) only need the 4 columns where a test exercises client
paths or `verifySchema`. `tests/fixtures/events.db` is regenerated or extended
so `verifySchema` passes against it.

## Left to the builder

- Exact client icon.
- README / CLAUDE.md updates describing client entities and the sink >= v1.0.3
  requirement.
