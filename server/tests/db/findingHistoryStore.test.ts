import { describe, expect, it } from 'vitest';
import { applyTrigger } from '../../src/analysis/findings.js';
import { addHistory, listHistory } from '../../src/db/findingHistoryStore.js';
import { upsertFinding } from '../../src/db/findingsStore.js';
import { openLensDb } from '../../src/db/lensDb.js';

describe('findingHistoryStore', () => {
  it('appends and lists history in time order', () => {
    const db = openLensDb(':memory:');
    const f = upsertFinding(db, applyTrigger(null, 'internal_source', 't0', 'source_ip', '192.0.2.4'));
    const id = f.id as number;
    const later = addHistory(db, { finding_id: id, at: 't2', kind: 'queued', actor: 'system', summary: 'queued' });
    const first = addHistory(db, {
      finding_id: id,
      at: 't1',
      kind: 'created',
      actor: 'system',
      summary: 'created',
      note: 'n',
      analysis_request_id: 7,
    });
    const tie = addHistory(db, { finding_id: id, at: 't2', kind: 'ai_closed', actor: 'ai', summary: 'closed' });

    expect(later).toMatchObject({ note: null, analysis_request_id: null, feedback_considered_at: null });
    expect(first).toMatchObject({ note: 'n', analysis_request_id: 7 });
    expect(listHistory(db, id).map((h) => h.id)).toEqual([first.id, later.id, tie.id]);
    expect(listHistory(db, 999)).toEqual([]);
    db.close();
  });
});
