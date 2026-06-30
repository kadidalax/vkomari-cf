// CF-VPS-Monitor reporter: HTTP policy mode (active=3s, idle=120s).
import { VirtualAgent } from '../agent.js';

export class CFMonitorReporter {
  constructor(config) {
    this.config = config;
    this.agent = new VirtualAgent(config);
    this.tickCount = 0;
    this.policy = { mode: 'idle', sampleInterval: 120000, reportInterval: 120000 };
    this.lastSample = 0;
    this.lastPolicyAt = 0;
    this.lastIdleBucket = -1;
    this.infoSent = false;
  }

  get httpBase() {
    const base = (this.config.cfmonitor_server || '').replace(/\/+$/, '');
    return base.replace(/^ws/, 'http');
  }

  headers() {
    return {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.config.cfmonitor_token || ''}`
    };
  }

  reportIntervalSec() {
    return Math.max(3, Number(this.config.report_interval) || 3);
  }

  policyReportIntervalSec() {
    const fallbackMs = this.policy.mode === 'active' ? this.reportIntervalSec() * 1000 : 120000;
    return Math.max(3, Math.round((Number(this.policy.reportInterval) || fallbackMs) / 1000));
  }

  regionLabel() {
    const code = String(this.config.region || 'CN').toUpperCase();
    const names = {
      AE: 'Dubai, Dubai, AE',
      CN: 'Shanghai, China, CN',
      HK: 'Hong Kong, HK',
      TW: 'Taipei, Taiwan, TW',
      US: 'Los Angeles, California, US',
      JP: 'Tokyo, Japan, JP',
      SG: 'Singapore, SG',
      DE: 'Frankfurt, Hesse, DE',
      GB: 'London, England, GB',
      NL: 'Amsterdam, North Holland, NL'
    };
    return names[code] || `${code} VPS`;
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
  }

  async uploadBasicInfo() {
    try {
      await fetch(`${this.httpBase}/api/clients/uploadBasicInfo`, {
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
      const res = await fetch(`${this.httpBase}/api/clients/policy`, { headers: this.headers() });
      if (!res.ok) return;
      const msg = await res.json();
      if (msg.type !== 'policy') return;
      this.policy.mode = msg.mode || 'idle';
      this.policy.sampleInterval = (msg.sample_interval_sec || 120) * 1000;
      this.policy.reportInterval = (msg.report_interval_sec || 120) * 1000;
      if (msg.report_now) this.lastSample = 0;
    } catch {}
  }

  async tick() {
    const now = Date.now();
    await this.connect();
    await this.refreshPolicy(now);

    if (this.policy.mode === 'active') {
      if (now - this.lastSample < this.policy.sampleInterval) return;
      this.lastSample = now;
    } else {
      const bucket = Math.floor(now / Math.max(60000, this.policy.reportInterval));
      if (new Date(now).getUTCMinutes() % 2 !== 0 || bucket === this.lastIdleBucket) return;
      this.lastIdleBucket = bucket;
    }

    const report = this.buildReport(now, this.policyReportIntervalSec());
    const body = this.policy.mode === 'active' ? report : { reports: [report] };
    try {
      await fetch(`${this.httpBase}/api/clients/report`, {
        method: 'POST',
        headers: this.headers(),
        body: JSON.stringify(body)
      });
    } catch {}
  }

  buildReport(now, intervalSec = this.reportIntervalSec()) {
    const stats = this.agent.generateStats(this.tickCount++);
    const interval = Math.max(3, Number(intervalSec) || this.reportIntervalSec());
    const cpu = parseFloat(stats.cpu.toFixed(1));
    return {
      cpu,
      gpu: 0,
      ram: Math.round(this.agent.usable.ram * stats.mem / 100),
      ram_total: this.agent.usable.ram,
      swap: Math.round(this.agent.usable.swap * stats.swap / 100),
      swap_total: this.agent.usable.swap,
      load: parseFloat((stats.cpu / 100 * (parseInt(this.config.cpu_cores) || 2)).toFixed(2)),
      temp: parseFloat((34 + cpu * 0.42 + this.agent.nodeSeed * 5).toFixed(1)),
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

  close() {}
}
