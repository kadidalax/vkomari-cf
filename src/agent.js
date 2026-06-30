// Virtual probe data generator — simulates realistic VPS metrics
// ponytail: deterministic PRNG seeded from UUID for per-node uniqueness, no external deps

export class VirtualAgent {
  constructor(config) {
    this.config = config;
    this.usable = this._calcUsable();
    this._seed = this._hashStr(config.client_uuid || config.name || 'node');
  }

  _hashStr(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) h = Math.imul(31, h) + str.charCodeAt(i) | 0;
    return Math.abs(h) / 2147483647;
  }

  _rand(min, max) {
    this._seed = (this._seed * 16807 + 0) % 2147483647;
    return min + (this._seed / 2147483647) * (max - min);
  }

  _calcUsable() {
    const c = this.config;
    const r = this._hashStr(c.client_uuid || c.name || '');
    return {
      ram: Math.floor(Number(c.ram_total || 1024) * (0.94 + r * 0.04) * 1048576),
      disk: Math.floor(Number(c.disk_total || 10240) * (0.91 + r * 0.04) * 1048576),
      swap: Math.floor(Number(c.swap_total || 0) * 1048576)
    };
  }

  generateStats(tick) {
    const c = this.config;
    const now = new Date();
    const hour = now.getHours();
    const minute = now.getMinutes();

    // Day-phase multiplier: business hours (9-18) peak, night (0-6) trough
    const dayPhase = 1 + 0.5 * Math.sin(((hour + minute / 60 - 6) / 24) * 2 * Math.PI);

    // Multi-layer waveforms for realistic CPU fluctuation
    const slowWave = Math.sin(tick / 300) * 0.15;
    const midWave = Math.sin(tick / 30) * 0.20;
    const fastWave = Math.sin(tick / 5) * 0.10;
    const spike = (Math.sin(tick / 7.3) > 0.95) ? this._rand(0.05, 0.15) : 0;

    const cpuBase = Number(c.cpu_min || 5) + (Number(c.cpu_max || 85) - Number(c.cpu_min || 5)) * 0.3;
    let cpu = cpuBase * dayPhase + (Number(c.cpu_max || 85) - Number(c.cpu_min || 5)) * (slowWave + midWave + fastWave + spike);
    cpu = Math.max(Number(c.cpu_min || 5), Math.min(Number(c.cpu_max || 85), cpu));

    // RAM follows CPU with damping
    const ramTotalMB = Number(c.ram_total || 1024);
    const systemMB = ramTotalMB <= 512 ? ramTotalMB * 0.35 : 120 + ramTotalMB * 0.08;
    const systemPct = (systemMB / ramTotalMB) * 100;
    let mem = systemPct + (cpu / 100) * (Number(c.mem_max || 85) - systemPct) * 0.6 + Math.sin(tick / 150) * 3;
    mem = Math.max(systemPct, Math.min(Number(c.mem_max || 85), mem));

    // Swap: only used when RAM is high
    let swap = mem > 80 ? (mem - 80) * 1.5 : (Number(c.swap_min || 0) + Math.sin(tick / 200) * 1);
    swap = Math.max(0, Math.min(Number(c.swap_max || 5), swap));

    // Disk: slow growth + OS baseline + random writes
    const diskTotalMB = Number(c.disk_total || 10240);
    const osMB = diskTotalMB <= 2048 ? diskTotalMB * 0.55 : 600 + diskTotalMB * 0.03;
    const osPct = (osMB / diskTotalMB) * 100;
    let disk = osPct + (tick % 100000) * 0.0001 + Math.sin(tick / 500) * 1;
    disk = Math.max(osPct, Math.min(Number(c.disk_max || 80), disk));

    // Network: bandwidth fluctuates with CPU load
    const netMin = Number(c.net_min || 102400);
    const netMax = Number(c.net_max || 10485760);
    const netBase = netMin + (netMax - netMin) * (cpu / 100);
    const up = Math.floor(netBase * 0.35 * (0.7 + 0.6 * Math.random()));
    const down = Math.floor(netBase * 0.65 * (0.7 + 0.6 * Math.random()));

    // Cumulative traffic
    const bootTime = Number(c.boot_time) || (Math.floor(Date.now() / 1000) - (c.uptime_base || 0));
    const uptime = Math.floor(Date.now() / 1000) - bootTime;
    const avgSpeed = (netMin + netMax) / 2;
    const totalUp = Math.floor(uptime * avgSpeed * 0.35);
    const totalDown = Math.floor(uptime * avgSpeed * 0.65);

    // Connections and processes
    const conn = Math.round(Number(c.conn_min || 10) + cpu * 2.5 + Math.random() * 15);
    const connUdp = Math.round(conn * (0.05 + 0.1 * Math.random()));
    const proc = Math.round(Number(c.proc_min || 50) + cpu * 3);

    return { cpu, mem, swap, disk, up, down, totalUp, totalDown, conn, connUdp, proc, uptime };
  }
}
