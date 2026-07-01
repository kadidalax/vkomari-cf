// CF-VPS-Monitor reporter: Agent WebSocket policy mode, HTTP idle fallback.
import { VirtualAgent } from '../agent.js';
import { COUNTRY_REGIONS } from '../data/countries.js';
import { openReporterWebSocket } from './ws.js';

// Module-level diagnostic store — accessible from fetch handler
export const cfDiag = { reporters: [], lastUpdate: 0 };

export class CFMonitorReporter {
  constructor(config, env = {}) {
    this.config = config;
    this.env = env;
    this.agent = new VirtualAgent(config);
    this.tickCount = 0;
    this.policy = { mode: 'idle', sampleInterval: 120000, reportInterval: 120000 };
    this.ws = null;
    this.connecting = null;
    this.nextConnectAt = 0;
    this.lastSample = 0;
    this.lastSendAt = 0;
    this.lastPolicyAt = 0;
    this.lastIdleBucket = -1;
    this.infoSent = false;
    this.lastSendLogAt = 0;
    this.forceNextSend = false;
    this.diag = {
      name: config.name || '',
      wsState: 'closed',
      policyMode: 'idle',
      lastSendTs: 0,
      lastPolicyTs: 0,
      lastPolicyMode: '',
      sendCount: 0,
      wsError: '',
      wsUrl: '',
      usingServiceBinding: false,
    };
    cfDiag.reporters.push(this.diag);
  }

  get httpBase() {
    const base = String(this.config.cfmonitor_server || '').trim().replace(/\/+$/, '');
    return base.replace(/^ws/, 'http');
  }

  get wsUrl() {
    const base = String(this.config.cfmonitor_server || '').trim().replace(/\/+$/, '').replace(/^http/, 'ws');
    return `${base}/api/clients/report?token=${encodeURIComponent(String(this.config.cfmonitor_token || '').trim())}`;
  }

  headers() {
    return {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${String(this.config.cfmonitor_token || '').trim()}`
    };
  }

  fetcher() {
    const service = this.env?.CF_MONITOR;
    if (!service?.fetch) { this.diag.usingServiceBinding = false; return null; }
    try {
      const host = new URL(this.httpBase).hostname.toLowerCase();
      const allowed = String(this.env?.CF_MONITOR_SERVICE_HOSTS || 'cf-vps-monitor-demo.work-631.workers.dev')
        .split(',')
        .map(h => h.trim().toLowerCase())
        .filter(Boolean);
      // Also allow the bound service name as a valid host
      const serviceName = this.env?.CF_MONITOR?.name?.toLowerCase?.() || '';
      const isAllowed = allowed.includes(host) || host === serviceName || allowed.some(a => host.endsWith('.' + a) || a.endsWith('.' + host));
      this.diag.usingServiceBinding = isAllowed;
      return isAllowed ? service : null;
    } catch {
      this.diag.usingServiceBinding = false;
      return null;
    }
  }

  async targetFetch(path, options = {}) {
    const fetcher = this.fetcher();
    const url = `${this.httpBase}${path}`;
    return fetcher ? fetcher.fetch(new Request(url, options)) : fetch(url, options);
  }

  reportIntervalSec() {
    return Math.max(3, Number(this.config.report_interval) || 3);
  }

  policyReportIntervalSec() {
    const fallbackMs = this.policy.mode === 'active' ? this.reportIntervalSec() * 1000 : 120000;
    return Math.max(3, Math.round((Number(this.policy.reportInterval) || fallbackMs) / 1000));
  }

  regionLabel() {
    const raw = String(this.config.region || '').trim();
    if (raw.includes(',')) return raw;
    const code = (raw || 'CN').toUpperCase();
    return COUNTRY_REGIONS[code] || `VPS, ${code}, ${code}`;
  }

  basicInfo() {
    const c = this.config;
    return {
      cpu_name: c.cpu_model || 'Intel Xeon',
      cpu_cores: parseInt(c.cpu_cores) || 2,
      arch: c.arch || 'amd64',
      os: c.os || 'Linux',
      virtualization: c.virtualization || 'kvm',
      kernel_version: c.kernel_version || '',
      gpu_name: c.gpu_name || '',
      mem_total: this.agent.usable.ram,
      swap_total: this.agent.usable.swap,
      disk_total: this.agent.usable.disk,
      ipv4: c.fake_ip || '',
      ipv6: c.ipv6 || '',
      region: this.regionLabel(),
      version: '1.0.0'
    };
  }

  async connect() {
    if (!this.infoSent) {
      await this.uploadBasicInfo();
      this.infoSent = true;
    }
    if (!this.isOpen() && Date.now() < this.nextConnectAt) return;
    if (this.isOpen() || this.connecting) return this.connecting;
    this.connecting = (async () => {
      try { await this.connectWebSocket(); }
      finally { this.nextConnectAt = this.isOpen() ? 0 : Date.now() + 5000; }
    })().finally(() => { this.connecting = null; });
    return this.connecting;
  }

  isOpen() {
    return this.ws && this.ws.readyState === 1;
  }

  async connectWebSocket() {
    try { if (this.ws && this.ws.readyState !== 3) this.ws.close(); } catch {}
    this.diag.wsUrl = this.wsUrl.replace(/token=[^&]+/, 'token=***');
    const fetcher = this.fetcher();
    this.ws = await openReporterWebSocket(this.wsUrl, this.logName(), fetcher);
    if (!this.ws) {
      this.diag.wsState = 'no_socket';
      this.diag.wsError = 'openReporterWebSocket returned null';
      console.log(`[vKomari] ${this.logName()} WS: no socket created`);
      return;
    }
    this.diag.wsState = 'connecting';
    this.diag.wsError = '';
    this.ws.addEventListener('message', (event) => {
      try {
        const msg = JSON.parse(event.data);
        this.applyPolicy(msg);
        if (msg.type === 'ack') {
          // ack from server, no action needed
        }
      } catch {}
    });
    this.ws.addEventListener('close', () => { this.ws = null; this.diag.wsState = 'closed'; });
    this.ws.addEventListener('error', () => { this.ws = null; this.diag.wsState = 'error'; this.diag.wsError = 'ws error event'; });
    await new Promise((resolve) => {
      let done = false;
      const finish = () => { if (!done) { done = true; resolve(); } };
      this.ws.addEventListener('open', finish);
      this.ws.addEventListener('error', finish);
      if (this.isOpen()) finish();
      setTimeout(finish, 3000);
    });
    if (this.isOpen()) {
      this.diag.wsState = 'open';
      console.log(`[vKomari] ${this.logName()} WS: connected (binding=${this.diag.usingServiceBinding})`);
    } else {
      this.diag.wsState = this.diag.wsState === 'error' ? 'error' : 'timeout';
      console.log(`[vKomari] ${this.logName()} WS: not open after connect (state=${this.diag.wsState})`);
    }
  }

  async uploadBasicInfo() {
    try {
      await this.targetFetch('/api/clients/uploadBasicInfo', {
        method: 'POST',
        headers: this.headers(),
        body: JSON.stringify(this.basicInfo())
      });
    } catch {}
  }

  async refreshPolicy(now) {
    if (now - this.lastPolicyAt < 10000) return;
    this.lastPolicyAt = now;
    try {
      const res = await this.targetFetch('/api/clients/policy', { headers: this.headers() });
      if (!res.ok) return;
      const msg = await res.json();
      this.applyPolicy(msg);
    } catch {}
  }

  applyPolicy(msg) {
    if (msg?.type !== 'policy') return;
    const wasIdle = this.policy.mode !== 'active';
    this.policy.mode = msg.mode || 'idle';
    this.policy.sampleInterval = (msg.sample_interval_sec || 120) * 1000;
    this.policy.reportInterval = (msg.report_interval_sec || 120) * 1000;
    this.diag.policyMode = this.policy.mode;
    this.diag.lastPolicyTs = Date.now();
    this.diag.lastPolicyMode = msg.mode || 'idle';
    if (msg.report_now || (wasIdle && this.policy.mode === 'active')) {
      this.lastSample = 0;
      this.forceNextSend = true;
    }
    console.log(`[vKomari] ${this.logName()} policy: mode=${this.policy.mode} interval=${this.policy.sampleInterval}ms report_now=${!!msg.report_now}`);
  }

  async tick() {
    const now = Date.now();
    await this.connect();
    if (!this.isOpen()) {
      await this.refreshPolicy(now);
      return this.sendHttp(now);
    }

    return this.sendWebSocket(now);
  }

  shouldSend(now) {
    // Force immediate send when policy switches to active (viewer opened panel)
    if (this.forceNextSend) {
      this.forceNextSend = false;
      this.lastSample = now;
      this.lastSendAt = now;
      return true;
    }
    if (this.policy.mode === 'active') {
      const interval = Math.max(1000, this.policy.sampleInterval);
      if (now - this.lastSample < interval) return false;
      this.lastSample = now;
    } else {
      // Idle: use interval-based throttle instead of minute-parity check.
      // The old `getUTCMinutes() % 2` check could block sends for up to 119s
      // even after switching from active→idle, and caused unpredictable timing.
      const interval = Math.max(60000, this.policy.reportInterval);
      if (now - this.lastSendAt < interval) return false;
    }
    this.lastSendAt = now;
    return true;
  }

  reportBody(now) {
    const report = this.buildReport(now, this.policyReportIntervalSec());
    // Always use 'reports' format — server branch A triggers ack + policy refresh
    return { type: 'reports', reports: [report] };
  }

  async sendHttp(now) {
    if (!this.shouldSend(now)) return;
    try {
      const res = await this.targetFetch('/api/clients/report', {
        method: 'POST',
        headers: this.headers(),
        body: JSON.stringify(this.reportBody(now))
      });
      this.diag.sendCount++;
      this.diag.lastSendTs = now;
      this.logSend('http', now, `status=${res.status}`);
    } catch (e) {
      this.diag.wsError = `http: ${e?.name || e}`;
    }
  }

  sendWebSocket(now) {
    if (!this.shouldSend(now)) return;
    try {
      this.ws.send(JSON.stringify(this.reportBody(now)));
      this.diag.sendCount++;
      this.diag.lastSendTs = now;
      this.logSend('ws', now);
    } catch (e) {
      this.ws = null;
      this.diag.wsState = 'error';
      this.diag.wsError = `send: ${e?.name || e}`;
    }
  }

  logName() {
    return `cfmonitor ${this.config.name || this.config.client_uuid || ''}`.trim();
  }

  logSend(kind, now, extra = '') {
    if (now - this.lastSendLogAt < 30000) return;
    this.lastSendLogAt = now;
    console.log(`[vKomari] ${this.logName()} report ${kind} mode=${this.policy.mode} ${extra}`.trim());
  }

  buildReport(now, intervalSec = this.reportIntervalSec()) {
    const stats = this.agent.generateStats(this.tickCount++);
    const interval = Math.max(3, Number(intervalSec) || this.reportIntervalSec());
    return {
      cpu: parseFloat(stats.cpu.toFixed(1)),
      gpu: 0,
      ram: Math.round(this.agent.usable.ram * stats.mem / 100),
      ram_total: this.agent.usable.ram,
      swap: Math.round(this.agent.usable.swap * stats.swap / 100),
      swap_total: this.agent.usable.swap,
      load: stats.load1,
      temp: stats.temp,
      disk: Math.round(this.agent.usable.disk * stats.disk / 100),
      disk_total: this.agent.usable.disk,
      net_in: stats.down,
      net_out: stats.up,
      net_total_up: stats.totalUp,
      net_total_down: stats.totalDown,
      process_count: stats.proc,
      connections: stats.conn,
      connections_udp: stats.connUdp,
      uptime: stats.uptime,
      timestamp: now,
      version: '1.0.0',
      name: this.config.name || '',
      report_interval: interval,
      interval_sec: interval,
      ipv4: this.config.fake_ip || '',
      ipv6: this.config.ipv6 || '',
      region: this.regionLabel(),
      basic_info: this.basicInfo(),
      gpus: []
    };
  }

  close() {
    if (this.ws) { try { this.ws.close(); } catch {} this.ws = null; }
  }
}
