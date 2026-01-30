
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { VirtualAgent } from './agent.js';
import crypto from 'node:crypto';

// Hono App
const app = new Hono();

app.use('/api/*', cors());

// Helper for DB
const getDB = (c) => c.env.DB;

// JWT Helper using node:crypto (nodejs_compat)
const DEFAULT_JWT_SECRET = 'vkomari-secret-key-2026';

function signJWT(payload, secret) {
    const header = { alg: 'HS256', typ: 'JWT' };
    payload.exp = Math.floor(Date.now() / 1000) + (24 * 3600);
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = crypto.createHmac('sha256', secret || DEFAULT_JWT_SECRET)
        .update(encodedHeader + '.' + encodedPayload)
        .digest('base64url');
    return `${encodedHeader}.${encodedPayload}.${signature}`;
}

function verifyJWT(token, secret) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        const [header, payload, signature] = parts;
        const expectedSignature = crypto.createHmac('sha256', secret || DEFAULT_JWT_SECRET).update(`${header}.${payload}`).digest('base64url');
        if (signature !== expectedSignature) return null;
        const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString());
        if (decoded.exp && decoded.exp < Date.now() / 1000) return null;
        return decoded;
    } catch { return null; }
}

// Middleware
const auth = async (c, next) => {
    const authHeader = c.req.header('Authorization');
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return c.json({ error: 'Unauthorized' }, 401);
    const user = verifyJWT(token, c.env.JWT_SECRET);
    if (!user) return c.json({ error: 'Invalid token' }, 403);
    c.set('user', user);
    await next();
};

// Routes

// Login
app.post('/api/login', async (c) => {
    const { username, password } = await c.req.json();
    const db = getDB(c);
    const user = await db.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();

    if (!user) return c.json({ error: 'Invalid' }, 401);

    // Hash password check
    const salt = user.salt;
    const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

    if (hash !== user.password) return c.json({ error: 'Invalid' }, 401);

    const token = signJWT({ username: user.username }, c.env.JWT_SECRET);
    return c.json({ token, isDefault: username === 'admin' && password === 'vkomari' });
});

// Change Password
app.post('/api/change-password', auth, async (c) => {
    const { newPassword } = await c.req.json();
    if (!newPassword || newPassword.length < 6) return c.json({ error: 'Too short' }, 400);

    const user = c.get('user');
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(newPassword, salt, 10000, 64, 'sha512').toString('hex');

    await getDB(c).prepare('UPDATE users SET password = ?, salt = ? WHERE username = ?')
        .bind(hash, salt, user.username).run();

    return c.json({ success: true });
});

// Get Nodes
app.get('/api/nodes', auth, async (c) => {
    const nodes = await getDB(c).prepare('SELECT * FROM nodes ORDER BY sort_order ASC, id DESC').all();
    // In CF Worker, we don't have permanent activeAgents state to show "online" status for the management UI easily
    // unless we store "last_seen" in DB. 
    // For now, we return nodes. Interactive status might be static or unknown.
    // We can simulate online status if enabled.
    const result = nodes.results.map(r => ({
        ...r,
        online: !!r.enabled, // Fake online status based on enabled
        sendCount: 0,
        uptime: 0,
        lastError: ''
    }));
    return c.json(result);
});

// Edit/Add Node
app.post('/api/nodes', auth, async (c) => {
    const d = await c.req.json();
    const db = getDB(c);

    if (!d.client_uuid) d.client_uuid = crypto.randomUUID();
    if (d.fake_ip === undefined) d.fake_ip = '';
    if (!d.uptime_base) d.uptime_base = Math.floor(Math.random() * 7 + 1) * 86400;

    const fields = ['name', 'server_address', 'client_secret', 'client_uuid', 'cpu_model', 'cpu_cores', 'ram_total', 'swap_total', 'disk_total', 'os', 'arch', 'virtualization', 'region', 'kernel_version', 'load_profile', 'cpu_min', 'cpu_max', 'mem_min', 'mem_max', 'swap_min', 'swap_max', 'disk_min', 'disk_max', 'net_min', 'net_max', 'conn_min', 'conn_max', 'proc_min', 'proc_max', 'report_interval', 'enabled', 'boot_time', 'fake_ip', 'group_name', 'gpu_name', 'ipv6', 'traffic_reset_day', 'uptime_base', 'sort_order'];

    if (d.id) {
        // Update
        const updates = fields.map(k => `${k} = ?`).join(',');
        const values = fields.map(k => d[k] === undefined ? null : d[k]);
        values.push(d.id);

        await db.prepare(`UPDATE nodes SET ${updates} WHERE id = ?`).bind(...values).run();
        return c.json({ status: 'updated' });
    } else {
        // Insert
        const cols = fields.join(',');
        const placeholders = fields.map(() => '?').join(',');
        const values = fields.map(k => d[k] === undefined ? null : d[k]);

        const res = await db.prepare(`INSERT INTO nodes (${cols}) VALUES (${placeholders})`).bind(...values).run();
        return c.json({ status: 'created', id: res.meta.last_row_id });
    }
});

// Delete Node (wasn't in server.js explicit routes but often needed, skipping as not in original server.js)
// Toggle
app.post('/api/toggle', auth, async (c) => {
    const { id, enabled } = await c.req.json();
    await getDB(c).prepare('UPDATE nodes SET enabled = ? WHERE id = ?').bind(enabled ? 1 : 0, id).run();
    return c.json({ status: 'ok' });
});

// Batch
app.post('/api/batch', auth, async (c) => {
    const { action } = await c.req.json();
    const en = action === 'start' ? 1 : 0;
    await getDB(c).prepare('UPDATE nodes SET enabled = ?').bind(en).run();
    return c.json({ status: 'ok' });
});

// Reorder Nodes
app.post('/api/reorder', auth, async (c) => {
    const { updates } = await c.req.json();
    if (!Array.isArray(updates)) return c.json({ error: 'Invalid data' }, 400);

    const db = getDB(c);
    const stmts = [];

    for (const u of updates) {
        if (u.id && (typeof u.sort_order === 'number' || u.group_name !== undefined)) {
            let sql = 'UPDATE nodes SET ';
            const params = [];
            const parts = [];

            if (typeof u.sort_order === 'number') {
                parts.push('sort_order = ?');
                params.push(u.sort_order);
            }
            if (u.group_name !== undefined) {
                parts.push('group_name = ?');
                params.push(u.group_name);
            }

            sql += parts.join(', ') + ' WHERE id = ?';
            params.push(u.id);

            stmts.push(db.prepare(sql).bind(...params));
        }
    }

    if (stmts.length > 0) await db.batch(stmts);
    return c.json({ status: 'ok', count: stmts.length });
});

// Groups Rename
app.post('/api/groups/rename', auth, async (c) => {
    const { oldName, newName } = await c.req.json();
    if (!oldName || !newName || oldName === newName) return c.json({ status: 'no_change' });

    await getDB(c).prepare('UPDATE nodes SET group_name = ? WHERE group_name = ?').bind(newName, oldName).run();
    return c.json({ status: 'ok' });
});

// Templates
app.get('/api/templates', auth, async (c) => {
    const res = await getDB(c).prepare('SELECT * FROM templates ORDER BY id DESC').all();
    return c.json(res.results.map(r => ({ id: r.id, name: r.name, config: JSON.parse(r.config) })));
});

app.post('/api/templates', auth, async (c) => {
    const { name, config } = await c.req.json();
    const res = await getDB(c).prepare('INSERT INTO templates (name, config) VALUES (?, ?)').bind(name, JSON.stringify(config)).run();
    return c.json({ status: 'ok', id: res.meta.last_row_id });
});

app.post('/api/templates/delete', auth, async (c) => {
    const { id } = await c.req.json();
    await getDB(c).prepare('DELETE FROM templates WHERE id = ?').bind(id).run();
    return c.json({ status: 'ok' });
});

// Import
app.post('/api/import', auth, async (c) => {
    const { nodes } = await c.req.json();
    if (!Array.isArray(nodes)) return c.json({ error: 'Invalid data' }, 400);
    const db = getDB(c);

    // Batch insert? D1 supports batch.
    const stmts = [];
    const fields = ['name', 'server_address', 'client_secret', 'client_uuid', 'cpu_model', 'cpu_cores', 'ram_total', 'swap_total', 'disk_total', 'os', 'arch', 'virtualization', 'region', 'kernel_version', 'load_profile', 'cpu_min', 'cpu_max', 'mem_min', 'mem_max', 'swap_min', 'swap_max', 'disk_min', 'disk_max', 'net_min', 'net_max', 'conn_min', 'conn_max', 'proc_min', 'proc_max', 'report_interval', 'enabled', 'boot_time', 'fake_ip', 'group_name', 'gpu_name', 'ipv6', 'traffic_reset_day', 'uptime_base', 'sort_order'];

    for (const n of nodes) {
        if (!n.client_uuid) n.client_uuid = crypto.randomUUID();
        if (!n.fake_ip) n.fake_ip = '';
        if (!n.uptime_base) n.uptime_base = Math.floor(Math.random() * 7 + 1) * 86400;

        const cols = fields.join(',');
        const placeholders = fields.map(() => '?').join(',');
        const values = fields.map(k => n[k] === undefined ? null : n[k]);
        stmts.push(db.prepare(`INSERT INTO nodes (${cols}) VALUES (${placeholders})`).bind(...values));
    }

    if (stmts.length > 0) await db.batch(stmts);
    return c.json({ status: 'ok', count: stmts.length });
});

// --- Scheduled Event ---
// This handles the Cron Trigger or Manual Trigger loop
async function runSimulationLoop(env, ctx) {
    const db = env.DB;
    // Get all enabled nodes
    const { results } = await db.prepare('SELECT * FROM nodes WHERE enabled = 1').all();

    if (!results || results.length === 0) return;

    const WORKER_LOOP_DURATION = 62;
    const startTime = Date.now();

    const connections = [];

    // Parse nodes and create multiple connections if needed
    for (const r of results) {
        // Split server_address by command, comma or newline
        const addrs = (r.server_address || '').split(/[,，\s]+/).map(s => s.trim()).filter(Boolean);
        const agent = new VirtualAgent(r);

        for (const rawAddr of addrs) {
            let addr = rawAddr.replace(/\/+$/, '');
            if (!/^(ws|http)s?:\/\//.test(addr)) addr = 'wss://' + addr;
            // Construct WS URL
            const wsUrl = addr.replace(/^http/, 'ws') + '/api/clients/report?token=' + encodeURIComponent(r.client_secret);

            connections.push({
                agent: agent, // Shared agent state
                ws: null,
                url: wsUrl,
                rawAddr: rawAddr
            });
        }
    }

    async function establishConnection(conn) {
        try {
            if (conn.ws) {
                try { conn.ws.close(); } catch (e) { }
            }
            conn.ws = new WebSocket(conn.url);
            conn.ws.addEventListener('error', e => console.log(`[vKomari] WS Error (${conn.rawAddr}):`, e.message || e));
            conn.ws.addEventListener('open', () => {
                // Upload info on every reconnect to be safe
                const c = conn.agent.config;
                const info = {
                    cpu_name: c.cpu_model || 'Intel Xeon',
                    cpu_cores: parseInt(c.cpu_cores) || 2,
                    arch: c.arch || 'amd64',
                    os: c.os || 'Linux',
                    virtualization: c.virtualization || 'kvm',
                    kernel_version: c.kernel_version || '',
                    gpu_name: c.gpu_name || '',
                    mem_total: conn.agent.usable.ram,
                    swap_total: conn.agent.usable.swap,
                    disk_total: conn.agent.usable.disk,
                    ipv4: c.fake_ip || 'Hidden',
                    ipv6: c.ipv6 || '',
                    region: (c.region || 'CN').toUpperCase(),
                    version: '1.2.0'
                };
                const baseUrl = conn.url.split('/api/clients/report')[0].replace(/^ws/, 'http');
                const path = '/api/v1/client/upload-basic-info';
                const uploadUrl = `${baseUrl}${path}?token=${encodeURIComponent(c.client_secret)}`;
                ctx.waitUntil(fetch(uploadUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(info)
                }).catch(() => { }));
            });
        } catch (e) {
            console.log(`[vKomari] WS Setup Error (${conn.rawAddr}):`, e);
        }
    }

    // Initialize Connections and Upload Basic Info
    for (let i = 0; i < connections.length; i++) {
        await establishConnection(connections[i]);
    }

    // Wait for connections to open?
    await new Promise(r => setTimeout(r, 2000));

    // Loop
    while (Date.now() - startTime < WORKER_LOOP_DURATION * 1000) {
        const loopStart = Date.now();
        const elapsedSeconds = Math.floor((loopStart - startTime) / 1000);

        for (const conn of connections) {
            if (conn.ws && conn.ws.readyState === 1) { // OPEN
                const payload = await conn.agent.report(elapsedSeconds);
                if (payload) {
                    conn.ws.send(JSON.stringify(payload));
                }
            } else if (!conn.ws || conn.ws.readyState > 1) { // CLOSED or CLOSING
                // If the connection is broken, attempt to reconnect within the loop
                console.log(`[vKomari] Reconnecting (${conn.rawAddr})...`);
                establishConnection(conn);
            }
        }

        // Wait for next second
        const elapsed = Date.now() - loopStart;
        const wait = Math.max(0, 1000 - elapsed);
        if (wait > 0) await new Promise(r => setTimeout(r, wait));
    }

    // Cleanup
    connections.forEach(c => {
        if (c.ws) {
            try { c.ws.close(); } catch (e) { }
        }
    });
}

// Health Check
app.get('/api/health', (c) => c.json({ status: 'ok', time: new Date().toISOString() }));

app.onError((err, c) => {
    console.error(`[vKomari Error] ${err}`);
    return c.json({ error: 'Internal Server Error', message: err.message }, 500);
});

export default {
    fetch: app.fetch,
    scheduled: async (event, env, ctx) => {
        ctx.waitUntil(runSimulationLoop(env, ctx));
    }
};
