import { useState } from 'react';

// Inline note entry under a card's actions. With `required`, Confirm stays
// disabled until the note has non-blank text (the server rejects a blank
// reopen note too).
export function NoteBox({
  placeholder,
  required = false,
  busy,
  onConfirm,
  onCancel,
}: {
  placeholder: string;
  required?: boolean;
  busy: boolean;
  onConfirm: (note: string) => void;
  onCancel: () => void;
}) {
  const [note, setNote] = useState('');
  const blank = note.trim() === '';
  return (
    <div className="note-box">
      <textarea
        className="note-input"
        rows={2}
        placeholder={placeholder}
        value={note}
        onChange={(e) => setNote(e.target.value)}
      />
      <div className="note-actions">
        <button className="btn btn-primary" type="button" disabled={busy || (required && blank)} onClick={() => onConfirm(note.trim())}>
          {busy ? 'Saving…' : 'Confirm'}
        </button>
        <button className="btn btn-ghost" type="button" disabled={busy} onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
}
