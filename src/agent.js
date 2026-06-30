// Virtual probe data generator - realistic-enough VPS metrics without deps.
// ponytail: deterministic waves by node id; no stored state needed across cron runs.

const PROFILE_DEFAULTS = {
  low: { cpu_min: 2, cpu_max: 32, mem_min: 18, mem_max: 38, swap_min: 0, swap_max: 2, disk_min: 10, disk_max: 35, net_min: 20480, net_max: 512000, conn_min: 5, conn_max: 35, proc_min: 45, proc_max: 90 },
  mid: { cpu_min: 10, cpu_max: 65, mem_min: 38, mem_max: 68, swap_min: 0, swap_max: 12, disk_min: 35, disk_max: 65, net_min: 131072, net_max: 3145728, conn_min: 40, conn_max: 180, proc_min: 80, proc_max: 180 },
  high: { cpu_min: 35, cpu_max: 92, mem_min: 68, mem_max: 92, swap_min: 5, swap_max: 45, disk_min: 65, disk_max: 88, net_min: 1048576, net_max: 12582912, conn_min: 200, conn_max: 900, proc_min: 160, proc_max: 450 }
};

export class VirtualAgent {
  constructor(config) {
    this.config = config;
    this.identity = config.client_uuid || config.name || 'node';
    this.nodeSeed = this._hashStr(this.identity) || 0.5;
    this.usable = this._calcUsable();
  }

  _hashStr(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) h = Math.imul(31, h) + str.charCodeAt(i) | 0;
    return Math.abs(h) / 2147483647;
  }

  _calcUsable() {
    const c = this.config;
    return {
      ram: Math.floor(Number(c.ram_total || 1024) * 1048576),
      disk: Math.floor(Number(c.disk_total || 10240) * 1048576),
      swap: Math.floor(Number(c.swap_total || 0) * 1048576)
    };
  }

  _profile() {
    return PROFILE_DEFAULTS[this.config.load_profile] || PROFILE_DEFAULTS.mid;
  }

  _num(key) {
    const value = Number(this.config[key]);
    return Number.isFinite(value) && value !== 0 ? value : this._profile()[key];
  }

  _range(minKey, maxKey) {
    let min = this._num(minKey);
    let max = this._num(maxKey);
    if (max < min) [min, max] = [max, min];
    return [min, max];
  }

  _wave(t, size, shift = 0) {
    return (Math.sin(t / size + shift + this.nodeSeed * 6.283) + 1) / 2;
  }

  _clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  generateStats(tick) {
    const c = this.config;
    const now = new Date();
    const hour = now.getHours();
    const minute = now.getMinutes();
    const t = Math.floor(Date.now() / 1000) + tick + Math.floor(this.nodeSeed * 997);

    const dayPhase = 0.75 + 0.25 * Math.sin(((hour + minute / 60 - 6) / 24) * 2 * Math.PI);
    const active = this._clamp(
      0.22 + dayPhase * 0.18 + this._wave(t, 900) * 0.18 + this._wave(t, 90, 1.7) * 0.22 + this._wave(t, 9, 3.1) * 0.12,
      0,
      1
    );
    const spike = this._wave(t, 17, 0.4) > 0.94 ? 0.12 + this.nodeSeed * 0.10 : 0;

    const [cpuMin, cpuMax] = this._range('cpu_min', 'cpu_max');
    const cpu = this._clamp(cpuMin + (cpuMax - cpuMin) * (active + spike), cpuMin, cpuMax);

    const [memMin, memMax] = this._range('mem_min', 'mem_max');
    const mem = this._clamp(memMin + (memMax - memMin) * (0.35 + active * 0.45 + this._wave(t, 600, 2.2) * 0.20), memMin, memMax);

    const [swapMin, swapMax] = this._range('swap_min', 'swap_max');
    const swapPressure = mem > 75 ? (mem - 75) / 25 : 0;
    const swap = this._clamp(swapMin + (swapMax - swapMin) * (swapPressure * 0.75 + this._wave(t, 1200, 1.1) * 0.25), swapMin, swapMax);

    const [diskMin, diskMax] = this._range('disk_min', 'disk_max');
    const diskGrowth = ((Math.floor(t / 3600) + Math.floor(this.nodeSeed * 100)) % 240) / 240;
    const disk = this._clamp(diskMin + (diskMax - diskMin) * (0.18 + this.nodeSeed * 0.44 + diskGrowth * 0.28 + this._wave(t, 1800, 0.7) * 0.10), diskMin, diskMax);

    const [netMin, netMax] = this._range('net_min', 'net_max');
    const netBase = netMin + (netMax - netMin) * this._clamp(active * (0.65 + this.nodeSeed * 0.35) + spike, 0, 1);
    const up = Math.floor(netBase * (0.22 + this.nodeSeed * 0.18) * (0.85 + this._wave(t, 11, 1.3) * 0.35));
    const down = Math.floor(netBase * (0.58 + this.nodeSeed * 0.22) * (0.85 + this._wave(t, 13, 2.4) * 0.35));

    const bootTime = Number(c.boot_time) || (Math.floor(Date.now() / 1000) - (c.uptime_base || 0));
    const uptime = Math.floor(Date.now() / 1000) - bootTime;
    const avgSpeed = (netMin + netMax) / 2;
    const totalUp = Math.floor(uptime * avgSpeed * 0.35);
    const totalDown = Math.floor(uptime * avgSpeed * 0.65);

    const [connMin, connMax] = this._range('conn_min', 'conn_max');
    const conn = Math.round(this._clamp(connMin + (connMax - connMin) * (active + this._wave(t, 40) * 0.15), connMin, connMax));
    const connUdp = Math.round(conn * (0.04 + this.nodeSeed * 0.12));
    const [procMin, procMax] = this._range('proc_min', 'proc_max');
    const proc = Math.round(this._clamp(procMin + (procMax - procMin) * (0.25 + active * 0.55 + this.nodeSeed * 0.20), procMin, procMax));

    return { cpu, mem, swap, disk, up, down, totalUp, totalDown, conn, connUdp, proc, uptime };
  }
}
