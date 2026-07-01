import { Hono } from 'hono';
import { cors } from 'hono/cors';
import authRoutes from './routes/auth.js';
import nodeRoutes from './routes/nodes.js';
import { authMiddleware } from './auth.js';
import { getDB, getTemplates, ensureSchema } from './db.js';
import { KomariReporter } from './reporters/komari.js';
import { CFMonitorReporter } from './reporters/cfmonitor.js';

const app = new Hono();
app.use('/api/*', cors());

// Auto-initialize DB schema on first request
app.use('*', async (c, next) => {
  if (c.env.DB) await ensureSchema(c.env.DB).catch(() => {});
  await next();
});

// Auth routes
app.route('/api', authRoutes);

// Node CRUD
app.route('/api/nodes', nodeRoutes);

// Groups
app.post('/api/groups/rename', authMiddleware, async (c) => {
  const { oldName, newName } = await c.req.json();
  if (!oldName || !newName || oldName === newName) return c.json({ status: 'no_change' });
  await getDB(c).prepare('UPDATE nodes SET group_name = ? WHERE group_name = ?').bind(newName, oldName).run();
  return c.json({ status: 'ok' });
});

// Templates
app.get('/api/templates', authMiddleware, async (c) => c.json(await getTemplates(getDB(c))));

app.post('/api/templates', authMiddleware, async (c) => {
  const { name, config } = await c.req.json();
  const res = await getDB(c).prepare('INSERT INTO templates (name, config) VALUES (?, ?)').bind(name, JSON.stringify(config)).run();
  return c.json({ status: 'ok', id: res.meta.last_row_id });
});

app.post('/api/templates/update', authMiddleware, async (c) => {
  const { id, name, config } = await c.req.json();
  if (!id) return c.json({ error: 'Missing template id' }, 400);
  await getDB(c).prepare('UPDATE templates SET name = ?, config = ? WHERE id = ?').bind(name, JSON.stringify(config), id).run();
  return c.json({ status: 'ok' });
});

app.post('/api/templates/delete', authMiddleware, async (c) => {
  const { id } = await c.req.json();
  await getDB(c).prepare('DELETE FROM templates WHERE id = ?').bind(id).run();
  return c.json({ status: 'ok' });
});

app.get('/api/health', (c) => c.json({ status: 'ok', time: new Date().toISOString() }));

app.get('/api/cfmonitor/diag', authMiddleware, async (c) => {
  const db = getDB(c);
  await ensureSchema(db).catch(() => {});
  let reporters = [];
  try {
    const row = await db.prepare('SELECT value FROM settings WHERE key = ?').bind('cf_diag').first();
    reporters = JSON.parse(row?.value || '[]');
  } catch (e) {
    // settings table might not exist yet — return empty
  }
  return c.json({ reporters, serverTime: Date.now() });
});

app.onError((err, c) => {
  console.error(`[vKomari Error] ${err}`);
  return c.json({ error: 'Internal Server Error', message: err.message }, 500);
});

// --- Cron scheduler: dual-panel simulation loop ---
async function runCron(env, ctx) {
  const db = env.DB;
  if (!db) return;
  await ensureSchema(db).catch(() => {});
  const { results } = await db.prepare('SELECT * FROM nodes WHERE enabled = 1 AND report_enabled = 1').all();
  if (!results || results.length === 0) return;

  console.log(`[vKomari] Cron: ${results.length} enabled nodes`);

  const reporters = [];
  for (const node of results) {
    if (node.komari_server && node.komari_token) {
      reporters.push({ type: 'komari', inst: new KomariReporter(node) });
    }
    if (node.cfmonitor_server && node.cfmonitor_token) {
      reporters.push({ type: 'cfmonitor', inst: new CFMonitorReporter(node, env) });
    }
  }

  // Connect all reporters in parallel to minimize startup latency
  await Promise.allSettled(reporters.map(r => r.inst.connect?.().catch(err => console.error(`[vKomari] connect failed: ${r.type}`, err))));

  const start = Date.now();
  const MAX_DURATION = 65000;

  while (Date.now() - start < MAX_DURATION) {
    const loopStart = Date.now();
    // Run all reporters in parallel — each internally throttles its own interval.
    // Serial execution caused cascading delays: N nodes × send latency > target interval.
    await Promise.allSettled(reporters.map(async (r) => {
      try {
        if (r.type === 'komari') await r.inst.send();
        else await r.inst.tick();
      } catch (err) {
        console.error(`[vKomari] reporter failed: ${r.type}`, err);
      }
    }));
    const elapsed = Date.now() - loopStart;
    // Persist CF Monitor diagnostics to D1 every ~5s for the /api/cfmonitor/diag endpoint
    const cfReporters = reporters.filter(r => r.type === 'cfmonitor' && r.inst.diag);
    if (cfReporters.length > 0) {
      const nowTs = Date.now();
      const diagData = cfReporters.map(r => {
        const d = r.inst.diag;
        return {
          name: d.name, wsState: d.wsState, policyMode: d.policyMode,
          lastSendAge: d.lastSendTs ? nowTs - d.lastSendTs : -1,
          lastPolicyAge: d.lastPolicyTs ? nowTs - d.lastPolicyTs : -1,
          sendCount: d.sendCount, recvCount: d.recvCount,
          wsError: d.wsError, wsUrl: d.wsUrl,
          usingServiceBinding: d.usingServiceBinding,
        };
      });
      db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)')
        .bind('cf_diag', JSON.stringify(diagData)).run().catch(() => {});
    }
    // Tick every 1s so Komari (1s interval) and CF Monitor (3s active) stay responsive
    const wait = Math.max(0, 1000 - elapsed);
    if (wait > 0) await new Promise(resolve => setTimeout(resolve, wait));
  }

  // Do NOT explicitly close WebSocket connections here.
  // Letting them die naturally when the execution context is cleaned up
  // maximizes overlap with the next cron invocation, reducing offline gaps.
  console.log(`[vKomari] Cron finished: ${Date.now() - start}ms`);
}

export default {
  fetch: app.fetch,
  scheduled: async (event, env, ctx) => {
    await runCron(env, ctx);
  }
};
