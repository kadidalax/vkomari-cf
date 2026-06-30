import crypto from 'node:crypto';

const DEFAULT_SECRET = 'vkomari-secret-key-2026';

export function sign(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  payload = { ...payload, exp: Math.floor(Date.now() / 1000) + 86400, iat: Math.floor(Date.now() / 1000) };
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const h = b64(header);
  const p = b64(payload);
  const sig = crypto.createHmac('sha256', secret || DEFAULT_SECRET).update(`${h}.${p}`).digest('base64url');
  return `${h}.${p}.${sig}`;
}

export function verify(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [h, p, sig] = parts;
    const expected = crypto.createHmac('sha256', secret || DEFAULT_SECRET).update(`${h}.${p}`).digest('base64url');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
    if (payload.exp && payload.exp < Date.now() / 1000) return null;
    return payload;
  } catch { return null; }
}

export function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return { hash, salt };
}
