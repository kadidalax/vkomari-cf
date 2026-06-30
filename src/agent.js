// Virtual probe data generator - deterministic demo-realistic VPS metrics.
// ponytail: stateless waves/pulses; no D1 writes per sample.

const MB = 1048576;

const PROFILE_DEFAULTS = {
  low: { cpu_min: 1, cpu_max: 30, mem_min: 8, mem_max: 18, swap_min: 0, swap_max: 2, disk_min: 8, disk_max: 28, net_min: 10000, net_max: 200000, conn_min: 2, conn_max: 25, proc_min: 35, proc_max: 70 },
  mid: { cpu_min: 1, cpu_max: 60, mem_min: 35, mem_max: 55, swap_min: 0, swap_max: 8, disk_min: 30, disk_max: 58, net_min: 102400, net_max: 1024000, conn_min: 30, conn_max: 120, proc_min: 70, proc_max: 140 },
  high: { cpu_min: 1, cpu_max: 90, mem_min: 72, mem_max: 92, swap_min: 8, swap_max: 40, disk_min: 68, disk_max: 86, net_min: 1048576, net_max: 5242880, conn_min: 220, conn_max: 850, proc_min: 120, proc_max: 260 }
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
    for (let i = 0; i < String(str).length; i++) h = Math.imul(31, h) + String(str).charCodeAt(i) | 0;
    return Math.abs(h) / 2147483647;
  }

  _profile() {
    return PROFILE_DEFAULTS[this.config.load_profile] || PROFILE_DEFAULTS.mid;
  }

  _mb(key, fallback, allowZero = false) {
    const value = Number(this.config[key]);
    if (Number.isFinite(value) && (allowZero ? value >= 0 : value > 0)) return value;
    return fallback;
  }

  _calcUsable() {
    return {
      ram: Math.floor(this._mb('ram_total', 1024) * MB),
      disk: Math.floor(this._mb('disk_total', 10240) * MB),
      swap: Math.floor(this._mb('swap_total', 0, true) * MB)
    };
  }

  _num(key) {
    const value = Number(this.config[key]);
    return Number.isFinite(value) ? value : this._profile()[key];
  }

  _range(minKey, maxKey, limit = Infinity) {
    let min = this._num(minKey);
    let max = this._num(maxKey);
    min = Math.max(0, Math.min(limit, min));
    max = Math.max(0, Math.min(limit, max));
    if (max < min) [min, max] = [max, min];
    return [min, max];
  }

  _wave(t, size, shift = 0) {
    return (Math.sin(t / size + shift + this.nodeSeed * 6.283) + 1) / 2;
  }

  _pulse(t, period, width, shift = 0) {
    const phase = ((((t + shift) % period) + period) % period) / period;
    const distance = Math.min(phase, 1 - phase);
    return this._clamp(1 - distance / width, 0, 1);
  }

  _clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  _uptime(nowSec) {
    const bootTime = Number(this.config.boot_time);
    if (Number.isFinite(bootTime) && bootTime > 0) return Math.max(0, nowSec - bootTime);

    const base = Number.isFinite(Number(this.config.uptime_base)) ? Number(this.config.uptime_base) : 86400;
    const createdAt = Date.parse(this.config.created_at || '');
    if (Number.isFinite(createdAt)) return Math.max(0, Math.floor(base + nowSec - createdAt / 1000));
    return Math.max(0, Math.floor(base));
  }

  generateStats(tick = 0) {
    const now = new Date();
    const nowSec = Math.floor(Date.now() / 1000);
    const t = nowSec + tick + Math.floor(this.nodeSeed * 997);

    const hour = now.getHours() + now.getMinutes() / 60;
    const dayPhase = 0.55 + 0.45 * Math.sin(((hour - 7) / 24) * 2 * Math.PI);
    const active = this._clamp(
      0.12 + dayPhase * 0.18 + this._wave(t, 600) * 0.22 + this._wave(t, 55, 1.7) * 0.24 + this._wave(t, 8, 3.1) * 0.16,
      0,
      1
    );
    const burst = Math.max(
      this._pulse(t, 7 + this.nodeSeed * 4, 0.22, this.nodeSeed * 11),
      this._pulse(t, 17 + this.nodeSeed * 9, 0.16, 4.7)
    );

    const [cpuMin, cpuMax] = this._range('cpu_min', 'cpu_max', 100);
    const cpuSpan = Math.max(1, cpuMax - cpuMin);
    const cpuSoft = cpuMin + cpuSpan * (0.10 + active * 0.45 + this._wave(t, 23, 0.8) * 0.18 + this._wave(t, 4.5, 2.4) * 0.12);
    const cpuOvershoot = Math.min(26, Math.max(1.2, cpuSpan * 0.34));
    const cpu = this._clamp(cpuSoft + burst * cpuOvershoot - this._wave(t, 11, 2.1) * cpuSpan * 0.08, 0, 100);

    const [memMin, memMax] = this._range('mem_min', 'mem_max', 100);
    const memSpan = Math.max(1, memMax - memMin);
    const memBase = 0.30 + this.nodeSeed * 0.12 + this._wave(t, 1800, 2.2) * 0.34 + active * 0.16 + (cpu / 100) * 0.08;
    const mem = this._clamp(memMin + memSpan * memBase + burst * Math.min(3, memSpan * 0.08), 0, 100);

    const [swapMin, swapMax] = this._range('swap_min', 'swap_max', 100);
    const swapSpan = Math.max(1, swapMax - swapMin);
    const swapPressure = this._clamp((mem - 70) / 30, 0, 1);
    const swap = this._clamp(swapMin + swapSpan * (swapPressure * 0.72 + this._wave(t, 2400, 1.1) * 0.20 + burst * 0.08), 0, 100);

    const [diskMin, diskMax] = this._range('disk_min', 'disk_max', 100);
    const diskSpan = Math.max(1, diskMax - diskMin);
    const diskGrowth = ((Math.floor(t / 3600) + Math.floor(this.nodeSeed * 100)) % 720) / 720;
    const disk = this._clamp(diskMin + diskSpan * (0.12 + this.nodeSeed * 0.58 + diskGrowth * 0.22 + this._wave(t, 7200, 0.7) * 0.06), 0, 100);

    const [netMin, netMax] = this._range('net_min', 'net_max');
    const netSpan = Math.max(0, netMax - netMin);
    const netActivity = this._clamp(active * 0.25 + (cpu / 100) * 0.62 + burst * 0.22, 0, 1);
    const netBase = netMin + netSpan * netActivity;
    const up = Math.max(0, Math.floor(netBase * (0.20 + this.nodeSeed * 0.22) * (0.72 + this._wave(t, 3.7, 1.3) * 0.70)));
    const down = Math.max(0, Math.floor(netBase * (0.55 + this.nodeSeed * 0.28) * (0.72 + this._wave(t, 4.1, 2.4) * 0.70)));

    const uptime = this._uptime(nowSec);
    const avgSpeed = (netMin + netMax) / 2;
    const totalUp = Math.floor(uptime * avgSpeed * (0.28 + this.nodeSeed * 0.12));
    const totalDown = Math.floor(uptime * avgSpeed * (0.55 + this.nodeSeed * 0.18));

    const [connMin, connMax] = this._range('conn_min', 'conn_max');
    const connSpan = Math.max(1, connMax - connMin);
    const conn = Math.round(this._clamp(connMin + connSpan * (active * 0.60 + cpu / 100 * 0.25 + burst * 0.16), 0, Math.max(connMax * 1.15, connMin)));
    const connUdp = Math.round(conn * (0.04 + this.nodeSeed * 0.12));

    const [procMin, procMax] = this._range('proc_min', 'proc_max');
    const procSpan = Math.max(1, procMax - procMin);
    const proc = Math.round(this._clamp(procMin + procSpan * (0.18 + active * 0.42 + cpu / 100 * 0.24 + this.nodeSeed * 0.12), 1, Math.max(procMax * 1.10, procMin)));

    return { cpu, mem, swap, disk, up, down, totalUp, totalDown, conn, connUdp, proc, uptime };
  }
}
