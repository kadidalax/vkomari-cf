// CF-VPS-Monitor reporter: WebSocket with dynamic policy (active=3s, idle=120s batch)
import { VirtualAgent } from '../agent.js';

export class CFMonitorReporter {
  constructor(config) {
    this.config = config;
    this.agent = new VirtualAgent(config);
    this.ws = null;
    this.tick = 0;
    this.policy = { mode: 'idle', sampleInterval: 120000, reportInterval: 120000 };
    this.pending = [];
    this.lastSample = 0;
    this.infoSent = false;
  }

  get httpBase() {
    const base = (this.config.cfmonitor_server || '').replace(/\/+$/, '');
    return base.replace(/^ws/, 'http');
  }

  get wsUrl() {
    const base = (this.config.cfmonitor_server || '').replace(/\/+$/, '');
    return `${base.replace(/^http/, 'ws')}/api/clients/report`;
  }

  async uploadBasicInfo() {
    const c = this.config;
    const info = {
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
      ipv4: c.fake_ip || 'Hidden',
      ipv6: c.ipv6 || '',
      region: (c.region || 'CN').toUpperCase(),
      version: '1.0.0'
    };
    try {
      await fetch(`${this.httpBase}/api/v1/client/upload-basic-info?token=${encodeURIComponent(c.cfmonitor_token || '')}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(info)
      });
    } catch {}
  }

  connect() {
    if (this.ws) { try { this.ws.close(); } catch {} }
    // ponytail: CF Workers WebSocket API can't set custom upgrade headers,
    // so token goes via query param for cf-vps-monitor WS auth.
    const tokenParam = this.config.cfmonitor_token ? `?token=${encodeURIComponent(this.config.cfmonitor_token)}` : '';
    const url = tokenParam ? this.wsUrl + tokenParam : this.wsUrl;
    this.ws = new WebSocket(url);
    this.ws.addEventListener('open', async () => {
      console.log(`[CF-Monitor] Connected: ${this.config.name}`);
      if (!this.infoSent) { await this.uploadBasicInfo(); this.infoSent = true; }
    });
    this.ws.addEventListener('message', (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === 'policy') {
          this.policy.mode = msg.mode || 'idle';
          this.policy.sampleInterval = (msg.sample_interval_sec || 120) * 1000;
          this.policy.reportInterval = (msg.report_interval_sec || 120) * 1000;
        }
      } catch {}
    });
    this.ws.addEventListener('close', () => this.infoSent = false);
    this.ws.addEventListener('error', () => {});
  }

  isOpen() {
    return this.ws && this.ws.readyState === 1;
  }

  tick() {
    const now = Date.now();
    const sampleMs = this.policy.sampleInterval;
    const reportMs = this.policy.reportInterval;

    if (now - this.lastSample < sampleMs) return;
    this.lastSample = now;

    if (!this.isOpen()) { this.connect(); return; }

    const stats = this.agent.generateStats(this.tick++);
    const report = {
      cpu: parseFloat(stats.cpu.toFixed(1)),
      ram: Math.round(this.agent.usable.ram * stats.mem / 100),
      ram_total: this.agent.usable.ram,
      swap: Math.round(this.agent.usable.swap * stats.swap / 100),
      swap_total: this.agent.usable.swap,
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
      version: '1.0.0',
      name: this.config.name || '',
      ipv4: this.config.fake_ip || ''
    };

    if (this.policy.mode === 'active') {
      try { this.ws.send(JSON.stringify({ type: 'report', data: report })); } catch {}
    } else {
      this.pending.push(report);
      if (now - this._lastBatch >= reportMs) {
        this._lastBatch = now;
        if (this.pending.length > 0) {
          try { this.ws.send(JSON.stringify({ type: 'reports', reports: this.pending })); } catch {}
          this.pending = [];
        }
      }
      if (!this._lastBatch) this._lastBatch = now;
    }
  }

  close() {
    if (this.ws) { try { this.ws.close(); } catch {} this.ws = null; }
  }
}
