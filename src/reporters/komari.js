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
  }

  get httpBase() {
    return (this.config.komari_server || '').replace(/\/+$/, '');
  }

  get reportUrl() {
    return `${this.httpBase}/api/clients/report?token=${encodeURIComponent(this.config.komari_token || '')}`;
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
  }

  isOpen() {
    return true;
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
    try {
      await fetch(this.reportUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(this.buildReport())
      });
    } catch {}
  }

  close() {}
}
