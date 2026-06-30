// Komari panel reporter: WebSocket v1, sends every 1 second
import { VirtualAgent } from '../agent.js';

export class KomariReporter {
  constructor(config) {
    this.config = config;
    this.agent = new VirtualAgent(config);
    this.ws = null;
    this.tick = 0;
  }

  get wsUrl() {
    const base = (this.config.komari_server || '').replace(/\/+$/, '');
    return `${base.replace(/^http/, 'ws')}/api/clients/report?token=${encodeURIComponent(this.config.komari_token || '')}`;
  }

  connect() {
    if (this.ws) { try { this.ws.close(); } catch {} }
    this.ws = new WebSocket(this.wsUrl);
    this.ws.addEventListener('open', () => console.log(`[Komari] Connected: ${this.config.name}`));
    this.ws.addEventListener('error', () => {});
  }

  isOpen() {
    return this.ws && this.ws.readyState === 1;
  }

  send() {
    if (!this.isOpen()) { this.connect(); return; }
    const stats = this.agent.generateStats(this.tick++);
    const payload = JSON.stringify({
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
    });
    try { this.ws.send(payload); } catch {}
  }

  close() {
    if (this.ws) { try { this.ws.close(); } catch {} this.ws = null; }
  }
}
