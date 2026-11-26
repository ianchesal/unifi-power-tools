import type { ReactNode } from 'react';
import { ClientIcon, GlobeIcon, SeverityIcon, SignatureIcon, STANDING_TRIGGER_TYPES, TRIGGER_ICONS, TRIGGER_LABELS } from '../icons';
import { severityBand } from '../severity';
import type { EntityType, Finding } from '../types';

function entityIcon(entityType: EntityType) {
  if (entityType === 'signature') return <SignatureIcon />;
  if (entityType === 'client') return <ClientIcon />;
  return <GlobeIcon />;
}

// The identity block every finding card/row shares: entity icon and key (a
// client shows `display_name · MAC`), the priority chip, and trigger chips.
// `badge` renders next to the entity type (e.g. a closed_by badge).
export function FindingIdentity({ finding, badge }: { finding: Finding; badge?: ReactNode }) {
  const band = severityBand(finding.severity_score);
  return (
    <>
      <div className="finding-top">
        <div className="finding-id-row">
          <div className="entity-type-icon">{entityIcon(finding.entity_type)}</div>
          <div>
            <div className="entity-key">
              {finding.display_name ? `${finding.display_name} · ${finding.entity_key}` : finding.entity_key}
            </div>
            <div className="entity-type">{finding.entity_type.replace('_', ' ')}</div>
          </div>
          {badge}
        </div>
        <span className={`severity-chip ${band}`}>
          {band !== 'low' && <SeverityIcon />}
          Priority {finding.severity_score}
        </span>
      </div>

      <div className="trigger-row">
        {finding.triggers.map((t) => {
          const Icon = TRIGGER_ICONS[t.type];
          const classes = ['trigger-chip'];
          if (t.active && STANDING_TRIGGER_TYPES.has(t.type)) classes.push('active-standing');
          if (!t.active) classes.push('inactive');
          return (
            <div key={t.type} className={classes.join(' ')}>
              {Icon && <Icon />}
              <span className="chip-status">{TRIGGER_LABELS[t.type] ?? t.type}</span>
            </div>
          );
        })}
      </div>
    </>
  );
}
