export function getDB(c) {
  if (!c.env.DB) throw new Error('D1 database not bound. Create a D1 database "vkomari-db" and bind it as "DB" in the Cloudflare Dashboard.');
  return c.env.DB;
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
