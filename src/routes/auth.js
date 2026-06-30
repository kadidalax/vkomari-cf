 import { Hono } from 'hono';
 import { sign, hashPassword } from '../utils/jwt.js';
 import { checkLoginRate, recordFailedLogin, clearLoginAttempts, authMiddleware } from '../auth.js';
 import { getDB, getUser, updatePassword } from '../db.js';
 
 const router = new Hono();
 
 router.post('/login', async (c) => {
   const ip = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown';
   if (!checkLoginRate(ip)) {
     return c.json({ error: 'Too many attempts. Try again later.' }, 429);
   }
   let body;
   try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid JSON' }, 400); }
   const { username, password } = body;
   if (!username || !password) return c.json({ error: 'Username and password required' }, 400);
   const user = await getUser(getDB(c), username);
   if (!user) { recordFailedLogin(ip); return c.json({ error: 'Invalid credentials' }, 401); }
   const { hash } = hashPassword(password, user.salt);
   if (hash !== user.password) { recordFailedLogin(ip); return c.json({ error: 'Invalid credentials' }, 401); }
   clearLoginAttempts(ip);
   const token = sign({ username: user.username }, c.env.JWT_SECRET);
   const isDefault = username === 'admin' && password === 'vkomari';
   return c.json({ token, isDefault });
 });
 
 router.post('/change-password', authMiddleware, async (c) => {
   let body;
   try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid JSON' }, 400); }
   const { newPassword } = body;
   if (!newPassword || newPassword.length < 6) return c.json({ error: 'Password must be at least 6 characters' }, 400);
   const user = c.get('user');
   const { hash, salt } = hashPassword(newPassword);
   await updatePassword(getDB(c), user.username, hash, salt);
   return c.json({ success: true });
 });
 
 router.get('/me', authMiddleware, (c) => {
   return c.json({ username: c.get('user').username });
 });
 
 export default router;
