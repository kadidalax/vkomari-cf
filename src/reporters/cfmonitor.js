// CF-VPS-Monitor reporter: Agent WebSocket policy mode, HTTP idle fallback.
import { VirtualAgent } from '../agent.js';
import { COUNTRY_REGIONS } from '../data/countries.js';
import { openReporterWebSocket } from './ws.js';

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
    this.lastPolicyAt = 0;
    this.lastIdleBucket = -1;
    this.infoSent = false;
    this.lastSendLogAt = 0;
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
    if (!service?.fetch) return null;
    try {
      const host = new URL(this.httpBase).hostname.toLowerCase();
      const allowed = String(this.env?.CF_MONITOR_SERVICE_HOSTS || 'cf-vps-monitor-demo.work-631.workers.dev')
        .split(',')
        .map(h => h.trim().toLowerCase())
        .filter(Boolean);
      return allowed.includes(host) ? service : null;
    } catch {
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
    this.ws = await openReporterWebSocket(this.wsUrl, this.logName(), this.fetcher());
    if (!this.ws) return;
    this.ws.addEventListener('message', (event) => {
      try { this.applyPolicy(JSON.parse(event.data)); } catch {}
    });
    this.ws.addEventListener('close', () => { this.ws = null; });
    this.ws.addEventListener('error', () => { this.ws = null; });
    await new Promise((resolve) => {
      let done = false;
      const finish = () => { if (!done) { done = true; resolve(); } };
      this.ws.addEventListener('open', finish);
      this.ws.addEventListener('error', finish);
      if (this.isOpen()) finish();
      setTimeout(finish, 1500);
    });
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
    this.policy.mode = msg.mode || 'idle';
    this.policy.sampleInterval = (msg.sample_interval_sec || 120) * 1000;
    this.policy.reportInterval = (msg.report_interval_sec || 120) * 1000;
    if (msg.report_now) this.lastSample = 0;
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
    if (this.policy.mode === 'active') {
      if (now - this.lastSample < this.policy.sampleInterval) return false;
      this.lastSample = now;
    } else {
      const bucket = Math.floor(now / Math.max(60000, this.policy.reportInterval));
      if (new Date(now).getUTCMinutes() % 2 !== 0 || bucket === this.lastIdleBucket) return false;
      this.lastIdleBucket = bucket;
    }
    return true;
  }

  reportBody(now) {
    const report = this.buildReport(now, this.policyReportIntervalSec());
    return this.policy.mode === 'active' ? report : { type: 'reports', reports: [report] };
  }

  async sendHttp(now) {
    if (!this.shouldSend(now)) return;
    try {
      const res = await this.targetFetch('/api/clients/report', {
        method: 'POST',
        headers: this.headers(),
        body: JSON.stringify(this.reportBody(now))
      });
      this.logSend('http', now, `status=${res.status}`);
    } catch {}
  }

  sendWebSocket(now) {
    if (!this.shouldSend(now)) return;
    try {
      this.ws.send(JSON.stringify(this.reportBody(now)));
      this.logSend('ws', now);
    } catch {
      this.ws = null;
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
