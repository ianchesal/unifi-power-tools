---
name: analyzing-findings
description: Use when asked to analyze, reanalyze, or triage pending findings in unifi-siem-lens — runs the lens's served triage playbook (get_playbook) over the MCP analysis queue, then adds a repo-only check that flags recurring low-risk findings as candidates for a new auto-triage rule.
---

# Analyzing Findings

The lens serves its own triage instructions. This skill runs them from a
development session and adds one step that only makes sense with this repo
checked out.

## 1. Run the served playbook

Call `mcp__unifi-siem-lens__get_playbook` and follow it for the whole run:
procedure, verdict rules, guardrails, rechecks and the final summary. It is the
source of truth (it is the same text as `/mcp__unifi-siem-lens__triage`), so
don't substitute your own procedure or restate it here. If the tool isn't
available, the lens MCP server isn't configured in this session: say so and
stop.

## 2. Repo-only: check for noise-rule candidates

The playbook's summary already lists rule candidates loosely. With the code
in front of you, tighten that list. A finding qualifies as a candidate to
flag (not implement) only if **all** of:

- every event behind it fits one clear, mechanical explanation (the same
  signature/action/source-category pattern across *all* matching events, not
  just the ones in `recentEvents`; this is the completeness bar
  `ruleTriage.ts`'s `isComplete` helper enforces: total count must equal
  matching count, not just "the sample looks clean");
- the verdict was `close` with `risk_level: low`;
- the pattern has recurred (this finding or a clear lookalike has shown up
  more than once, not a first-time one-off); and
- it doesn't already fit an existing rule in `server/src/analysis/ruleTriage.ts`
  (`admin_login`, `operational_noise`, `low_signal_category`,
  `reputation_blocklist`, `homelab_service_egress`, `exposed_host_scan`,
  `ignored_signature`). Skim the file to confirm before flagging.

Remember the two rule-layer restrictions in `matchRules.ts`: client findings
never get rule triage, and a finding carrying `internal_source` can only be
closed by `operational_noise`. A candidate that would need either relaxed is a
spec decision, not just a new rule; say so.

Because `recentEvents` is capped (LIMIT 20), you can't verify true
completeness from it alone. Treat this as a heuristic flag for the user to
verify with a real completeness query, the way `matchRules.ts` does, not as a
claim that the pattern is proven complete.

## 3. Report

After the playbook's summary, list each rule candidate with the recurring
pattern observed and a one-line sketch of what a new rule condition would
check (for example "all events are `category=ips_alert`, `action=blocked`,
signature matches the ET SCAN family, source_ip always outside RFC1918"),
left for the user to decide whether to implement.
