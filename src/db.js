 let schemaReady = false;

export function getDB(c) {
  if (!c.env.DB) throw new Error('D1 database not bound. Create a D1 database "vkomari-db" and bind it as "DB" in the Cloudflare Dashboard.');
  return c.env.DB;
}

 export async function ensureSchema(db) {
   if (schemaReady) return;
   try {
     await db.prepare('SELECT 1 FROM users LIMIT 1').first();
     schemaReady = true;
     return;
   } catch {
     await db.batch([
       db.prepare('CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, color TEXT, sort_order INTEGER)'),
       db.prepare('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, salt TEXT)'),
       db.prepare('CREATE TABLE IF NOT EXISTS templates (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, config TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)'),
       db.prepare('CREATE TABLE IF NOT EXISTS nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, group_name TEXT, server_address TEXT, client_secret TEXT, client_uuid TEXT, cpu_model TEXT, cpu_cores INTEGER, ram_total INTEGER, swap_total INTEGER, disk_total INTEGER, os TEXT, arch TEXT, virtualization TEXT, region TEXT, kernel_version TEXT, gpu_name TEXT, ipv4 TEXT, ipv6 TEXT, fake_ip TEXT, load_profile TEXT DEFAULT \'mid\', cpu_min REAL DEFAULT 5.0, cpu_max REAL DEFAULT 85.0, mem_min REAL DEFAULT 15.0, mem_max REAL DEFAULT 85.0, swap_min REAL DEFAULT 0, swap_max REAL DEFAULT 5.0, disk_min REAL DEFAULT 30.0, disk_max REAL DEFAULT 80.0, net_min INTEGER DEFAULT 102400, net_max INTEGER DEFAULT 10485760, conn_min INTEGER DEFAULT 10, conn_max INTEGER DEFAULT 200, proc_min INTEGER DEFAULT 50, proc_max INTEGER DEFAULT 300, report_interval INTEGER DEFAULT 3, enabled INTEGER DEFAULT 1, boot_time INTEGER DEFAULT 0, uptime_base INTEGER DEFAULT 86400, traffic_reset_day INTEGER DEFAULT 1, sort_order INTEGER DEFAULT 0, komari_server TEXT, komari_token TEXT, cfmonitor_server TEXT, cfmonitor_token TEXT, report_enabled INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)'),
       db.prepare('INSERT OR IGNORE INTO users (username, password, salt) VALUES (\'admin\', \'ce751a5323c718e60248219bb18bbe95d0143e5a5a4b3101463635339a1907e9867c6715b4e8080201b8a2792388b02e6d72a53dbb9b50198e651ea479aca728\', \'3374b09b526978182746180373809613\')')
     ]);
     schemaReady = true;
     console.log('[vKomari] Schema auto-initialized');
   }
 }

export async function getNodes(db) {
  const { results } = await db.prepare('SELECT * FROM nodes ORDER BY sort_order ASC, id DESC').all();
  return results.map(r => ({ ...r, online: !!r.enabled, sendCount: 0, uptime: 0, lastError: '' }));
}

export async function getEnabledNodes(db) {
  const { results } = await db.prepare('SELECT * FROM nodes WHERE enabled = 1 AND report_enabled = 1').all();
  return results;
}

export async function getUser(db, username) {
  return db.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
}

export async function updatePassword(db, username, hash, salt) {
  return db.prepare('UPDATE users SET password = ?, salt = ? WHERE username = ?').bind(hash, salt, username).run();
}

export async function getTemplates(db) {
  const { results } = await db.prepare('SELECT * FROM templates ORDER BY id DESC').all();
  return results.map(r => ({ id: r.id, name: r.name, config: JSON.parse(r.config) }));
}

const NODE_FIELDS = [
  'name', 'server_address', 'client_secret', 'client_uuid', 'cpu_model', 'cpu_cores',
  'ram_total', 'swap_total', 'disk_total', 'os', 'arch', 'virtualization', 'region',
  'kernel_version', 'load_profile', 'cpu_min', 'cpu_max', 'mem_min', 'mem_max',
  'swap_min', 'swap_max', 'disk_min', 'disk_max', 'net_min', 'net_max',
  'conn_min', 'conn_max', 'proc_min', 'proc_max', 'report_interval', 'enabled',
  'boot_time', 'fake_ip', 'group_name', 'gpu_name', 'ipv6', 'traffic_reset_day',
  'uptime_base', 'sort_order', 'komari_server', 'komari_token',
  'cfmonitor_server', 'cfmonitor_token', 'report_enabled'
];

export async function saveNode(db, data) {
  const values = NODE_FIELDS.map(k => data[k] === undefined ? null : data[k]);

  if (data.id) {
    const setClause = NODE_FIELDS.map(k => `${k} = ?`).join(',');
    await db.prepare(`UPDATE nodes SET ${setClause} WHERE id = ?`).bind(...values, data.id).run();
    return { status: 'updated' };
  } else {
    const placeholders = NODE_FIELDS.map(() => '?').join(',');
    const res = await db.prepare(`INSERT INTO nodes (${NODE_FIELDS.join(',')}) VALUES (${placeholders})`).bind(...values).run();
    return { status: 'created', id: res.meta.last_row_id };
  }
}
