// Virtual probe data generator - deterministic demo-realistic VPS metrics.
// ponytail: stateless waves/pulses; no D1 writes per sample.

const MB = 1048576;

const PROFILE_DEFAULTS = {
  low: { cpu_min: 0, cpu_max: 35, cpu_rest: 0.01, cpu_burst_period1: 22, cpu_burst_period2: 55, cpu_burst_period3: 9, cpu_burst_amp: 0.55, mem_min: 8, mem_max: 18, swap_min: 0, swap_max: 2, disk_min: 8, disk_max: 28, net_min: 10000, net_max: 200000, conn_min: 2, conn_max: 25, proc_min: 35, proc_max: 70 },
  mid: { cpu_min: 0, cpu_max: 65, cpu_rest: 0.04, cpu_burst_period1: 11, cpu_burst_period2: 31, cpu_burst_period3: 6, cpu_burst_amp: 0.75, mem_min: 35, mem_max: 55, swap_min: 0, swap_max: 8, disk_min: 30, disk_max: 58, net_min: 102400, net_max: 1024000, conn_min: 30, conn_max: 120, proc_min: 70, proc_max: 140 },
  high: { cpu_min: 0, cpu_max: 95, cpu_rest: 0.08, cpu_burst_period1: 5, cpu_burst_period2: 15, cpu_burst_period3: 3.5, cpu_burst_amp: 1.0, mem_min: 72, mem_max: 92, swap_min: 8, swap_max: 40, disk_min: 68, disk_max: 86, net_min: 1048576, net_max: 5242880, conn_min: 220, conn_max: 850, proc_min: 120, proc_max: 260 }
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
    const ramTotalMB = this._mb('ram_total', 1024);
    const diskTotalMB = this._mb('disk_total', 10240);
    return {
      ram: Math.floor(ramTotalMB * MB),
      disk: Math.floor(diskTotalMB * MB),
      swap: Math.floor(this._mb('swap_total', 0, true) * MB),
      // System base overhead in MB: OS kernel + init + ssh + monitoring agent.
      // This is a FIXED floor that never fluctuates with activity.
      // RAM: ~80MB baseline + 5% of total, capped at 160MB.
      ramBaseMB: Math.round(80 + Math.min(ramTotalMB * 0.05, 80)),
      // Disk: ~2GB baseline + 3% of total, capped at 4GB.
      diskBaseMB: Math.round(2048 + Math.min(diskTotalMB * 0.03, 2048))
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
    // Slow activity for metrics that shouldn't fluctuate rapidly (mem/swap/conn/proc/temp).
    const slowActive = this._clamp(0.15 + dayPhase * 0.18 + this._wave(t, 600) * 0.25, 0, 1);
    const cpuBurstP1 = this._num('cpu_burst_period1');
    const cpuBurstP2 = this._num('cpu_burst_period2');
    const cpuBurstP3 = this._num('cpu_burst_period3');
    const burst = Math.max(
      this._pulse(t, cpuBurstP1 + this.nodeSeed * 4, 0.22, this.nodeSeed * 11),
      this._pulse(t, cpuBurstP2 + this.nodeSeed * 9, 0.16, 4.7),
      this._pulse(t, cpuBurstP3 + this.nodeSeed * 2, 0.12, this.nodeSeed * 7.3)
    );

    const [cpuMin, cpuMax] = this._range('cpu_min', 'cpu_max', 100);
    const cpuSpan = Math.max(1, cpuMax - cpuMin);
    const cpuRest = this._num('cpu_rest');
    const cpuBurstAmp = this._num('cpu_burst_amp');
    const cpuSoft = cpuMin + cpuSpan * (cpuRest + active * 0.30 + this._wave(t, 23, 0.8) * 0.16 + this._wave(t, 4.5, 2.4) * 0.12 + this._wave(t, 2.2, 4.1) * 0.08);
    const cpuOvershoot = Math.min(40, Math.max(1.2, cpuSpan * cpuBurstAmp));
    const cpu = this._clamp(cpuSoft + burst * cpuOvershoot - this._wave(t, 11, 2.1) * cpuSpan * (cpuRest + 0.18), 0, 100);

    // Memory: system base (absolute MB) + variable workload percentage of total.
    // The base covers OS + daemons and never drops; the variable part uses
    // slowActive + long waves so short-term fluctuation is minimal.
    const [memMin, memMax] = this._range('mem_min', 'mem_max', 100);
    const memVarSpan = Math.max(1, memMax - memMin);
    const memVarPct = this._clamp(
      memMin + memVarSpan * (0.18 + this.nodeSeed * 0.14 + this._wave(t, 1800, 2.2) * 0.34 + this._wave(t, 5400, 3.5) * 0.14 + slowActive * 0.10),
      0, 100
    );
    const ramTotalMB = this._mb('ram_total', 1024);
    const memUsedMB = this.usable.ramBaseMB + (ramTotalMB - this.usable.ramBaseMB) * memVarPct / 100;
    const mem = this._clamp(memUsedMB / ramTotalMB * 100, 0, 100);

    // Swap: very slow, only sustained memory pressure drives it. No burst at all.
    const [swapMin, swapMax] = this._range('swap_min', 'swap_max', 100);
    const swapSpan = Math.max(1, swapMax - swapMin);
    const swapPressure = this._clamp((mem - 65) / 35, 0, 1);
    const swap = this._clamp(swapMin + swapSpan * (swapPressure * 0.55 + this._wave(t, 5400, 1.1) * 0.22 + slowActive * 0.10), 0, 100);

    // Disk: system base (absolute MB) + slow growth. Barely moves short-term.
    const [diskMin, diskMax] = this._range('disk_min', 'disk_max', 100);
    const diskVarSpan = Math.max(1, diskMax - diskMin);
    const diskGrowth = ((Math.floor(t / 3600) + Math.floor(this.nodeSeed * 100)) % 720) / 720;
    const diskVarPct = this._clamp(
      diskMin + diskVarSpan * (0.12 + this.nodeSeed * 0.58 + diskGrowth * 0.22 + this._wave(t, 7200, 0.7) * 0.06),
      0, 100
    );
    const diskTotalMB = this._mb('disk_total', 10240);
    const diskUsedMB = this.usable.diskBaseMB + (diskTotalMB - this.usable.diskBaseMB) * diskVarPct / 100;
    const disk = this._clamp(diskUsedMB / diskTotalMB * 100, 0, 100);

    // Network: tied to CPU activity + burst, but with slightly slower oscillation.
    const [netMin, netMax] = this._range('net_min', 'net_max');
    const netSpan = Math.max(0, netMax - netMin);
    const netActivity = this._clamp(active * 0.25 + (cpu / 100) * 0.62 + burst * 0.22, 0, 1);
    const netBase = netMin + netSpan * netActivity;
    const up = Math.max(0, Math.floor(netBase * (0.20 + this.nodeSeed * 0.22) * (0.72 + this._wave(t, 5.5, 1.3) * 0.70)));
    const down = Math.max(0, Math.floor(netBase * (0.55 + this.nodeSeed * 0.28) * (0.72 + this._wave(t, 6.2, 2.4) * 0.70)));

    const uptime = this._uptime(nowSec);
    const avgSpeed = (netMin + netMax) / 2;
    const totalUp = Math.floor(uptime * avgSpeed * (0.28 + this.nodeSeed * 0.12));
    const totalDown = Math.floor(uptime * avgSpeed * (0.55 + this.nodeSeed * 0.18));

    // Connections: driven by slow activity + medium wave, tiny fixed burst.
    const [connMin, connMax] = this._range('conn_min', 'conn_max');
    const connSpan = Math.max(1, connMax - connMin);
    const conn = Math.round(this._clamp(connMin + connSpan * (slowActive * 0.80 + this._wave(t, 120, 1.5) * 0.10) + burst * 1.5, 0, Math.max(connMax * 1.15, connMin)));
    const connUdp = Math.round(conn * (0.04 + this.nodeSeed * 0.12));

    // Process count: nearly constant, only slow drift.
    const [procMin, procMax] = this._range('proc_min', 'proc_max');
    const procSpan = Math.max(1, procMax - procMin);
    const proc = Math.round(this._clamp(procMin + procSpan * (0.32 + this.nodeSeed * 0.14 + slowActive * 0.14 + this._wave(t, 7200, 2.0) * 0.08), 1, Math.max(procMax * 1.10, procMin)));

    // Temperature: thermal lag — mostly follows a 2-minute smoothed CPU, not instantaneous.
    const cpuThermal = this._clamp(cpuRest * 100 + slowActive * 30 + this._wave(t, 120, 0.8) * cpuMax * 0.50, 0, 100);
    const temp = parseFloat((34 + cpuThermal * 0.42 + this.nodeSeed * 5).toFixed(1));

    // Load averages: load1 = instantaneous; load5/load15 use longer waves to simulate EMA lag.
    const cores = parseInt(this.config.cpu_cores) || 2;
    const load1 = parseFloat((cpu / 100 * cores).toFixed(2));
    const load5 = parseFloat((this._clamp(cpu * 0.30 + this._wave(t, 300, 0.5) * cpuMax * 0.50 + slowActive * cpuMax * 0.20, 0, 100) / 100 * cores).toFixed(2));
    const load15 = parseFloat((this._clamp(cpu * 0.10 + this._wave(t, 900, 1.2) * cpuMax * 0.40 + slowActive * cpuMax * 0.50, 0, 100) / 100 * cores).toFixed(2));

    return { cpu, mem, swap, disk, up, down, totalUp, totalDown, conn, connUdp, proc, uptime, temp, load1, load5, load15 };
  }
}
