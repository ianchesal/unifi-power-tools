import { type FormEvent, useState } from 'react';
import { ApiError, login } from '../api';
import { ShieldIcon } from '../icons';

export function LoginPage({ onSignedIn }: { onSignedIn: () => void }) {
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(password);
      onSignedIn();
    } catch (err) {
      const status = err instanceof ApiError ? err.status : 0;
      setError(
        status === 401
          ? 'Wrong password'
          : status === 429
            ? 'Too many attempts, try again later'
            : 'Sign-in failed, try again'
      );
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <div className="brand">
          <ShieldIcon size={28} />
          <div className="brand-text">
            <span className="brand-name">UniFi Power Tools</span>
            <span className="brand-sub">Sign in</span>
          </div>
        </div>
        <label className="login-label" htmlFor="password">
          Dashboard password
        </label>
        <input
          id="password"
          className="note-input"
          type="password"
          autoComplete="current-password"
          autoFocus
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        {error && <p className="login-error">{error}</p>}
        <button className="btn btn-primary" type="submit" disabled={busy || !password}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}
