---
name: analyzing-findings
description: Use when asked to analyze, reanalyze, or triage pending findings in unifi-siem-lens — drains the MCP analysis_requests queue, enriches with UniFi client/hostname data, submits a close/attention verdict for each, and flags recurring low-risk findings that look like candidates for a new auto-triage rule.
---

# Analyzing Findings

Drives the `unifi-siem-lens` MCP analysis handoff loop end to end: pulls
every pending analysis request, reasons about each with full context and
UniFi enrichment, submits a verdict (`close` or `attention`), and separately
calls out any findings that look like they belong in the code-driven
auto-triage layer (`server/src/analysis/ruleTriage.ts`, `matchRules.ts`)
instead of needing an LLM every time.

Read `server/src/analysis/findings.ts`, `pipeline.ts` and
`server/src/analysis/matchRules.ts` first if you haven't seen this
codebase's finding lifecycle before. A finding is `triaging` (waiting on
you), `attention` (the operator should look), or `closed`. Requests are
queued automatically for every finding the rules couldn't close; there is no
"Analyze this" click.

## Scope

This skill only drains the **pending MCP queue**
(`get_pending_analyses`). It does not:
- analyze findings that aren't queued (an operator's Re-analyze click queues
  one; you don't self-select findings),
- trigger or replace `runRuleTriageBackfill`,
- write or edit `ruleTriage.ts` / `matchRules.ts` / `runner.ts` — noise
  candidates are reported, never auto-implemented.

## Steps

1. **Fetch the queue.** Call `mcp__unifi-siem-lens__get_pending_analyses`
   (optional `limit`; highest severity first). If it returns empty, tell the
   user there's nothing to analyze and stop.

2. **Get full context per request.** For each pending item, call
   `mcp__unifi-siem-lens__get_analysis_context` with its `id`. The bundle is
   built at fetch time, so it reflects the sink as it is now:
   - `finding` — entity, triggers, severity, status, `reopen_count`;
   - `history` — the finding's audit trail (earlier rule/AI/human decisions,
     rechecks, reopens);
   - `prior_analyses` — earlier verdicts, including any operator notes;
   - `recentEvents`, `baselineHistory`, `knownClient`, `firewallSummary`;
   - `since_last_decision` — event count and how many IPS alerts were **not
     blocked** since the last decision (or since 14 days before the finding
     first appeared, if it was never decided);
   - `recheck` (rechecks only) — `before`/`after` activity summaries around
     the last decision, so you can see what changed.

3. **Enrich with hostnames.** Collect the distinct source/dest IPs across
   `recentEvents`. Try `mcp__unifi__list_clients` (`include_offline: true`)
   and match by IP to get a hostname/name for context in the writeup. If
   the call fails (unreachable controller/server) or an IP has no match,
   proceed IP-only — enrichment must never block analysis. Don't call
   `mcp__unifi__get_client` speculatively; it needs a MAC address, which
   you only have after a `list_clients` match.

4. **Reason about the finding.** Weigh:
   - **Trigger type** — `repeat_offender` and `anomaly` are standing
     conditions; `new_signature`, `new_source_ip`, `new_client` and
     `internal_source` are one-off facts. Triggers don't change status.
   - **History** — for a recheck (`request.is_recheck`), the question is what
     changed since the last decision and whether it matters. Don't just
     re-state the old verdict.
   - **Severity and action** (`blocked` vs not, IDS/IPS severity score).
     `since_last_decision.unblocked_ips_alerts` is what the submit guardrail
     checks.
   - **Recurrence** — does `baselineHistory` or the event timestamps show
     this happening more than once, or is it a single blip?
   - **Enrichment** — a known/trusted hostname changes the read on
     otherwise-suspicious traffic; an unknown or unexpected device doesn't.

5. **Choose the verdict.**
   - **`attention`** — the operator should do or verify something in the
     UniFi console (add or tighten a firewall rule, check a client, confirm a
     port forward, investigate a host). Requires `recommended_action`: the
     concrete thing to do in UniFi.
   - **`close`** — nothing for the operator to do. Already-blocked noise
     with no new risk is a close, however many alerts there are.
   When unsure whether it's worth the operator's time, prefer `attention`
   with an honest `risk_level`; a wrongly-closed finding is hidden, a
   wrongly-flagged one costs a click.

6. **Cross-reference other pending findings.** If two or more pending
   findings clearly share a root cause (same source IP, same signature,
   overlapping events), say so explicitly in each one's `reasoning` rather
   than analyzing them as unrelated.

7. **Submit.** Call `mcp__unifi-siem-lens__submit_analysis` with:
   - `id`, `verdict` (`close` | `attention`), `risk_level`
     (`low`/`medium`/`high`);
   - `summary` — one or two lines the operator reads first;
   - `reasoning` — what was observed, why it does or doesn't matter, citing
     the actual signature names, IPs/hostnames and dates;
   - `recommended_action` — **required for `attention`**: what to do in the
     UniFi console;
   - `why_now` — **required for rechecks**: what changed since the last
     decision and why it matters;
   - `cited_entries` — optional playbook entry ids. There is no playbook
     yet, so omit it: any cited id is rejected.

   The server rejects a verdict (the request stays pending, so fix and
   resubmit) when `summary`/`reasoning` is blank, `attention` lacks
   `recommended_action`, a recheck lacks `why_now`, or a `close` has no
   citation while unblocked IPS alerts exist since the last decision — or
   the sink can't be checked at all (it fails closed). Since citations aren't
   available yet, a rejected close means an alert wasn't blocked, or the
   sink couldn't be checked:
   either submit `attention` with an action that addresses it, or report the
   rejection to the user. Never work around the guardrail.

8. **Check for noise-rule candidates.** After forming a verdict, a finding
   qualifies as a candidate to flag (not implement) only if **all** of:
   - every event behind it fits one clear, mechanical explanation (same
     signature/action/source-category pattern across *all* matching
     events, not just the ones in `recentEvents` — the same completeness
     bar `ruleTriage.ts`'s `isComplete` helper enforces: total count must
     equal matching count, not just "the sample looks clean"),
   - the verdict was `close` with `risk_level: low`,
   - the pattern has recurred (this finding or a clear lookalike has
     shown up more than once — not a first-time one-off), and
   - it doesn't already fit one of the existing rules in `ruleTriage.ts`
     (`admin_login`, `operational_noise`, `low_signal_category`,
     `reputation_blocklist`, `homelab_service_egress`, `exposed_host_scan`,
     `ignored_signature`). Skim `ruleTriage.ts` to confirm before flagging.

   Because `get_analysis_context`'s `recentEvents` is capped (LIMIT 20,
   sized for LLM context), you can't verify true completeness from it
   alone — treat this step as a heuristic flag for the user to verify with a
   real completeness query, the way `matchRules.ts` itself does, not as a
   claim that the pattern is proven complete.

9. **Summarize.** Report per finding: id, verdict, risk level, one-line
   rationale. Separately list any noise-rule candidates from step 8, each
   with the recurring pattern observed and a one-line sketch of what a new
   rule condition would check (e.g. "all events are `category=ips_alert`,
   `action=blocked`, signature matches ET SCAN family, source_ip always
   outside RFC1918") — left for the user to decide whether to implement.
