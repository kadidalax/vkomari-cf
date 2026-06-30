import { Hono } from 'hono';
import crypto from 'node:crypto';
import { authMiddleware } from '../auth.js';
import { getDB, getNodes, saveNode } from '../db.js';

const router = new Hono();
router.use('*', authMiddleware);

router.get('/', async (c) => c.json(await getNodes(getDB(c))));

router.post('/', async (c) => {
  const d = await c.req.json();
  if (!d.client_uuid) d.client_uuid = crypto.randomUUID();
  if (d.fake_ip === undefined) d.fake_ip = '';
  if (!d.uptime_base) d.uptime_base = Math.floor(Math.random() * 7 + 1) * 86400;
  return c.json(await saveNode(getDB(c), d));
});

router.post('/toggle', async (c) => {
  const { id, enabled } = await c.req.json();
  await getDB(c).prepare('UPDATE nodes SET enabled = ? WHERE id = ?').bind(enabled ? 1 : 0, id).run();
  return c.json({ status: 'ok' });
});

router.post('/batch', async (c) => {
  const { action } = await c.req.json();
  await getDB(c).prepare('UPDATE nodes SET enabled = ?').bind(action === 'start' ? 1 : 0).run();
  return c.json({ status: 'ok' });
});

router.post('/reorder', async (c) => {
  const { updates } = await c.req.json();
  if (!Array.isArray(updates)) return c.json({ error: 'Invalid data' }, 400);
  const db = getDB(c);
  const stmts = [];
  for (const u of updates) {
    if (!u.id) continue;
    const parts = [];
    const params = [];
    if (typeof u.sort_order === 'number') { parts.push('sort_order = ?'); params.push(u.sort_order); }
    if (u.group_name !== undefined) { parts.push('group_name = ?'); params.push(u.group_name); }
    if (parts.length === 0) continue;
    params.push(u.id);
    stmts.push(db.prepare(`UPDATE nodes SET ${parts.join(', ')} WHERE id = ?`).bind(...params));
  }
  if (stmts.length > 0) await db.batch(stmts);
  return c.json({ status: 'ok', count: stmts.length });
});

router.post('/delete', async (c) => {
  const { id } = await c.req.json();
  await getDB(c).prepare('DELETE FROM nodes WHERE id = ?').bind(id).run();
  return c.json({ status: 'ok' });
});

router.post('/import', async (c) => {
  const { nodes } = await c.req.json();
  if (!Array.isArray(nodes)) return c.json({ error: 'Invalid data' }, 400);
  const db = getDB(c);
  const stmts = [];
  const fields = ['name', 'server_address', 'client_secret', 'client_uuid', 'cpu_model', 'cpu_cores', 'ram_total', 'swap_total', 'disk_total', 'os', 'arch', 'virtualization', 'region', 'kernel_version', 'load_profile', 'cpu_min', 'cpu_max', 'mem_min', 'mem_max', 'swap_min', 'swap_max', 'disk_min', 'disk_max', 'net_min', 'net_max', 'conn_min', 'conn_max', 'proc_min', 'proc_max', 'report_interval', 'enabled', 'boot_time', 'fake_ip', 'group_name', 'gpu_name', 'ipv6', 'traffic_reset_day', 'uptime_base', 'sort_order', 'komari_server', 'komari_token', 'cfmonitor_server', 'cfmonitor_token', 'report_enabled'];
  for (const n of nodes) {
    if (!n.client_uuid) n.client_uuid = crypto.randomUUID();
    if (!n.fake_ip) n.fake_ip = '';
    if (!n.uptime_base) n.uptime_base = Math.floor(Math.random() * 7 + 1) * 86400;
    stmts.push(db.prepare(`INSERT INTO nodes (${fields.join(',')}) VALUES (${fields.map(() => '?').join(',')})`).bind(...fields.map(k => n[k] === undefined ? null : n[k])));
  }
  if (stmts.length > 0) await db.batch(stmts);
  return c.json({ status: 'ok', count: stmts.length });
});

export default router;
