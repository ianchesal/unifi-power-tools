import { type NextFunction, type Request, type Response, Router } from 'express';
import rateLimit from 'express-rate-limit';
import { secretEquals } from '../auth/secretCompare.js';
import { issueToken, SESSION_COOKIE, SESSION_TTL_MS, verifyToken } from '../auth/session.js';

// One cookie is all this app sets; no cookie-parser dependency.
function sessionCookie(req: Request): string | null {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === SESSION_COOKIE) return part.slice(eq + 1).trim();
  }
  return null;
}

function hasSession(req: Request, key: Buffer, now: () => Date): boolean {
  const token = sessionCookie(req);
  return token !== null && verifyToken(key, token, now());
}

export function createAuthRouter(opts: {
  key: Buffer;
  password: string;
  now?: () => Date;
}): Router {
  const now = opts.now ?? (() => new Date());
  const router = Router();

  // Per immediate peer (or per client IP behind a trusted proxy); only failed
  // attempts count, so signing in normally never locks anyone out.
  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
  });

  router.post('/login', loginLimiter, (req, res) => {
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!secretEquals(password, opts.password)) {
      res.status(401).json({ error: 'Invalid password' });
      return;
    }
    res.cookie(SESSION_COOKIE, issueToken(opts.key, now()), {
      httpOnly: true,
      sameSite: 'strict',
      path: '/',
      maxAge: SESSION_TTL_MS,
      secure: req.secure,
    });
    res.json({ ok: true });
  });

  router.post('/logout', (req, res) => {
    res.clearCookie(SESSION_COOKIE, {
      httpOnly: true,
      sameSite: 'strict',
      path: '/',
      secure: req.secure,
    });
    res.json({ ok: true });
  });

  router.get('/session', (req, res) => {
    if (!hasSession(req, opts.key, now)) {
      res.status(401).json({ error: 'Not signed in' });
      return;
    }
    res.json({ ok: true });
  });

  return router;
}

export function requireSession(key: Buffer, now: () => Date = () => new Date()) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!hasSession(req, key, now)) {
      res.status(401).json({ error: 'Not signed in' });
      return;
    }
    next();
  };
}

const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

// A plain HTML form can't send application/json, so this (with the
// SameSite=Strict cookie) keeps cross-site pages from triggering writes.
export function requireJsonOnWrites(req: Request, res: Response, next: NextFunction) {
  if (WRITE_METHODS.has(req.method) && !req.is('application/json')) {
    res.status(415).json({ error: 'Content-Type must be application/json' });
    return;
  }
  next();
}
