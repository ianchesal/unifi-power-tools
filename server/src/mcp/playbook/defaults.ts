// The starter site-knowledge entries, seeded into lens.db by seed.ts so a fresh
// install triages sensibly. They only cover ground the rules don't, and they are
// public, so they stay generic: no address or hostname from a real network
// (GitHub's published SSH range is the one real block named; a test checks).
//
// `key` is stable forever. Raise `version` when changing an entry's text: the
// operator then gets it as an edit proposal, never as an overwrite.

export interface PlaybookDefault {
  key: string;
  version: number;
  title: string;
  body: string;
}

export const PLAYBOOK_DEFAULTS: PlaybookDefault[] = [
  {
    key: 'blocked-scanner-fingerprints',
    version: 1,
    title: 'Blocked inbound scanner fingerprints',
    body: `Inbound alerts from an external source on a scanner-fingerprint signature (ET SCAN Zmap, masscan and the like), with every attempt blocked (\`since_last_decision.unblocked_ips_alerts\` is 0) and no event showing traffic from that source allowed: \`close\`. Does not cover a scan from an internal host, or other signatures from the same source.`,
  },
  {
    key: 'git-ssh-to-github',
    version: 1,
    title: 'Git over SSH to GitHub flagged as an outbound SSH scan',
    body: `"ET SCAN Potential SSH Scan OUTBOUND" from an internal workstation to port 22 in GitHub's published SSH range 140.82.112.0/20 is Git over SSH opening several connections: \`close\`. Does not cover any other destination or signature, or a source that is not a workstation (server, IoT device). This entry names no host, so it does not satisfy guardrail 1: if any of the traffic was not blocked, submit \`attention\` and recommend an entry naming the workstation.`,
  },
  {
    key: 'vpn-client-exploit-sigs',
    version: 1,
    title: 'Generic exploit signatures on a known VPN client',
    body: `Encrypted traffic to commercial VPN or WireGuard endpoints can trip generic exploit signatures. \`close\` such an outbound alert only if another site entry names the source host as running a VPN client, and the destination, port and signature fit what that entry covers. This entry names no host, so on its own it closes nothing: never cite it alone. A host entry should name the host, the endpoints or ports, and the signatures.`,
  },
  {
    key: 'device-status-events',
    version: 1,
    title: 'Device-status events',
    body: `For device-status events the rules did not close: \`attention\` only when the same device has gone offline repeatedly (recommend checking its power, cabling and firmware) or the WAN IP changed unexpectedly (recommend checking the WAN connection and anything that depends on the address). A single disconnect that recovered is a \`close\`.`,
  },
  {
    key: 'blocked-exploits-on-forwarded-service',
    version: 1,
    title: 'Repeated exploit attempts against a port-forwarded service',
    body: `Repeated exploit attempts from external sources against a port-forwarded service: \`close\` while every attempt is blocked. \`attention\` if any attempt was allowed (recommend restricting or removing the port forward, or switching the signature to block), or if the campaign is sustained and no firewall policy blocks the source (recommend a policy blocking that source inbound on WAN). Check \`firewallSummary\` and operator notes in \`history\` for an existing block.`,
  },
];
