// Komari panel reporter: HTTP POST, sends every 1 second.
import { VirtualAgent } from '../agent.js';

function countryFlag(region) {
  const code = String(region || '').trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return String(region || '').trim();
  return [...code].map(ch => String.fromCodePoint(0x1f1e6 + ch.charCodeAt(0) - 65)).join('');
}

export class KomariReporter {
  constructor(config) {
    this.config = config;
    this.agent = new VirtualAgent(config);
    this.tickCount = 0;
    this.infoSent = false;
    this.ws = null;
    this.connecting = null;
    this.nextConnectAt = 0;
  }

  get httpBase() {
    return (this.config.komari_server || '').replace(/\/+$/, '');
  }

  get reportUrl() {
    return `${this.httpBase}/api/clients/report?token=${encodeURIComponent(this.config.komari_token || '')}`;
  }

  get wsUrl() {
    return `${this.httpBase.replace(/^http/, 'ws')}/api/clients/report?token=${encodeURIComponent(this.config.komari_token || '')}`;
  }

  async uploadBasicInfo() {
    const c = this.config;
    const region = countryFlag(c.region);
    const info = {
      cpu_name: c.cpu_model || 'Virtual CPU',
      cpu_cores: Number(c.cpu_cores) || 1,
      cpu_physical_cores: Number(c.cpu_cores) || 1,
      arch: c.arch || 'amd64',
      os: c.os || 'Linux',
      kernel_version: c.kernel_version || '',
      ipv4: c.fake_ip || c.ipv4 || '',
      ipv6: c.ipv6 || '',
      mem_total: this.agent.usable.ram,
      swap_total: this.agent.usable.swap,
      disk_total: this.agent.usable.disk,
      gpu_name: c.gpu_name || '',
      virtualization: c.virtualization || 'kvm',
      version: '1.0.0'
    };
    if (region) info.region = region;
    try {
      await fetch(`${this.httpBase}/api/clients/uploadBasicInfo?token=${encodeURIComponent(c.komari_token || '')}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(info)
      });
      this.infoSent = true;
    } catch {}
  }

  async connect() {
    if (!this.infoSent) await this.uploadBasicInfo();
    if (this.isOpen() || Date.now() < this.nextConnectAt) return;
    if (this.connecting) return this.connecting;
    this.connecting = this.connectWebSocket().finally(() => {
      this.connecting = null;
      this.nextConnectAt = this.isOpen() ? 0 : Date.now() + 5000;
    });
    return this.connecting;
  }

  isOpen() {
    return this.ws && this.ws.readyState === 1;
  }

  async connectWebSocket() {
    if (typeof WebSocket === 'undefined') return;
    try { if (this.ws && this.ws.readyState !== 3) this.ws.close(); } catch {}
    this.ws = new WebSocket(this.wsUrl);
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

  buildReport() {
    const stats = this.agent.generateStats(this.tickCount++);
    return {
      cpu: { usage: parseFloat(stats.cpu.toFixed(1)) },
      ram: { total: this.agent.usable.ram, used: Math.round(this.agent.usable.ram * stats.mem / 100) },
      swap: { total: this.agent.usable.swap, used: Math.round(this.agent.usable.swap * stats.swap / 100) },
      load: {
        load1: parseFloat((stats.cpu / 100 * (parseInt(this.config.cpu_cores) || 2)).toFixed(2)),
        load5: parseFloat((stats.cpu / 100 * (parseInt(this.config.cpu_cores) || 2) * 0.85).toFixed(2)),
        load15: parseFloat((stats.cpu / 100 * (parseInt(this.config.cpu_cores) || 2) * 0.7).toFixed(2))
      },
      disk: { total: this.agent.usable.disk, used: Math.round(this.agent.usable.disk * stats.disk / 100) },
      network: { up: stats.up, down: stats.down, totalUp: stats.totalUp, totalDown: stats.totalDown },
      connections: { tcp: stats.conn, udp: stats.connUdp },
      uptime: stats.uptime,
      process: stats.proc,
      gpu: {},
      message: ''
    };
  }

  async send() {
    await this.connect();
    if (!this.isOpen()) return;
    try { this.ws.send(JSON.stringify(this.buildReport())); } catch {}
  }

  close() {
    if (this.ws) { try { this.ws.close(); } catch {} this.ws = null; }
  }
}
