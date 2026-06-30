import { verify } from './utils/jwt.js';

const LOGIN_ATTEMPTS = new Map();
const LOCKOUT_MS = 300000;
const MAX_ATTEMPTS = 5;

export function checkLoginRate(ip) {
  const entry = LOGIN_ATTEMPTS.get(ip);
  if (!entry) return true;
  if (Date.now() - entry.lastAttempt > LOCKOUT_MS) { LOGIN_ATTEMPTS.delete(ip); return true; }
  return entry.count < MAX_ATTEMPTS;
}

export function recordFailedLogin(ip) {
  const entry = LOGIN_ATTEMPTS.get(ip) || { count: 0, lastAttempt: 0 };
  entry.count++; entry.lastAttempt = Date.now();
  LOGIN_ATTEMPTS.set(ip, entry);
}

export function clearLoginAttempts(ip) {
  LOGIN_ATTEMPTS.delete(ip);
}

export async function authMiddleware(c, next) {
  const header = c.req.header('Authorization');
  const token = header && header.split(' ')[1];
  if (!token) return c.json({ error: 'Unauthorized' }, 401);
  const user = verify(token, c.env.JWT_SECRET);
  if (!user) return c.json({ error: 'Invalid token' }, 403);
  c.set('user', user);
  await next();
}
