export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

// Thrown for a 401: the session is missing or expired. The registered
// callback (App) switches to the login screen.
export class UnauthorizedError extends ApiError {
  constructor(path: string) {
    super(`${path}: not signed in`, 401);
    this.name = 'UnauthorizedError';
  }
}

let unauthorizedHandler: () => void = () => {};

export function onUnauthorized(cb: () => void): void {
  unauthorizedHandler = cb;
}

function checkUnauthorized(path: string, res: Response): void {
  if (res.status === 401) {
    unauthorizedHandler();
    throw new UnauthorizedError(path);
  }
}

export async function fetchJson<T>(path: string): Promise<T> {
  const res = await fetch(path);
  checkUnauthorized(path, res);
  if (!res.ok) {
    throw new Error(`${path} returned ${res.status}`);
  }
  return res.json() as Promise<T>;
}

async function sendJson<T>(method: 'POST' | 'PUT', path: string, body?: unknown): Promise<T> {
  // Always JSON, even with no body: the server rejects non-JSON writes (415)
  // so a cross-site form can't make one.
  const res = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
  checkUnauthorized(path, res);
  if (!res.ok) {
    let message = `${path} returned ${res.status}`;
    try {
      const data = (await res.json()) as { error?: unknown };
      if (typeof data.error === 'string') message = data.error;
    } catch {
      // non-JSON error body: keep the generic message
    }
    throw new ApiError(message, res.status);
  }
  return res.json() as Promise<T>;
}

export function postJson<T>(path: string, body?: unknown): Promise<T> {
  return sendJson<T>('POST', path, body);
}

export function putJson<T>(path: string, body: unknown): Promise<T> {
  return sendJson<T>('PUT', path, body);
}

// The message to show inline for a failed action: ApiError carries the
// server's `error` text.
export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// Sign in. Throws ApiError: 401 for a wrong password, 429 when rate-limited.
// Deliberately bypasses the unauthorized handler: a wrong password isn't an
// expired session.
export async function login(password: string): Promise<void> {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password }),
  });
  if (!res.ok) throw new ApiError(`login returned ${res.status}`, res.status);
}

export async function logout(): Promise<void> {
  await fetch('/api/auth/logout', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  });
}

export async function checkSession(): Promise<boolean> {
  const res = await fetch('/api/auth/session');
  return res.ok;
}

