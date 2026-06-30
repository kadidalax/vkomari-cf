// API client with JWT auth
const API = {
  _token: null,

  setToken(t) { this._token = t; localStorage.setItem('vkomari_token', t); },
  getToken() { return this._token || localStorage.getItem('vkomari_token'); },
  clearToken() { this._token = null; localStorage.removeItem('vkomari_token'); },

  async _fetch(path, opts = {}) {
    const headers = { 'Content-Type': 'application/json', ...opts.headers };
    const token = this.getToken();
    if (token) headers['Authorization'] = 'Bearer ' + token;
    const res = await fetch(path, { ...opts, headers });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  },

  get(path) { return this._fetch(path); },
  post(path, body) { return this._fetch(path, { method: 'POST', body: JSON.stringify(body) }); },

  // Auth
  login(username, password) { return this.post('/api/login', { username, password }); },
  changePassword(newPassword) { return this.post('/api/change-password', { newPassword }); },
  me() { return this.get('/api/me'); },

  // Nodes
  getNodes() { return this.get('/api/nodes'); },
  saveNode(data) { return this.post('/api/nodes', data); },
  toggleNode(id, enabled) { return this.post('/api/nodes/toggle', { id, enabled }); },
  batchNodes(action) { return this.post('/api/nodes/batch', { action }); },
  reorderNodes(updates) { return this.post('/api/nodes/reorder', { updates }); },
  deleteNode(id) { return this.post('/api/nodes/delete', { id }); },
  importNodes(nodes) { return this.post('/api/nodes/import', { nodes }); },

  // Groups
  renameGroup(oldName, newName) { return this.post('/api/groups/rename', { oldName, newName }); },

  // Templates
  getTemplates() { return this.get('/api/templates'); },
  saveTemplate(name, config) { return this.post('/api/templates', { name, config }); },
  deleteTemplate(id) { return this.post('/api/templates/delete', { id }); },
};
