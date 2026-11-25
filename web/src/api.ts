export async function fetchJson<T>(path: string): Promise<T> {
  const res = await fetch(path);
  if (!res.ok) {
    throw new Error(`${path} returned ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

export async function postJson<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method: 'POST',
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
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
