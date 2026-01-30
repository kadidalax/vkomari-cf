
// src/agent.js
// Stateless adaptation of vkomari Agent for Cloudflare Workers

export class VirtualAgent {
  constructor(config) {
    this.config = config;
    this.usable = this.calculateUsableHardware();
  }

  calculateUsableHardware() {
    const c = this.config;
    const ramTotalMB = Number(c.ram_total) || 1024;
    const diskTotalMB = Number(c.disk_total) || 10240;
    const swapTotalMB = Number(c.swap_total) || 0;

    // Deterministic random based on ID or UUID to keep "hardware" consistent for same node
    // Simple hash to float 0-1
    const seed = (str) => {
      let h = 0;
      for (let i = 0; i < str.length; i++) h = Math.imul(31, h) + str.charCodeAt(i) | 0;
      return Math.abs(h) / 2147483647;
    };
    const rand = seed(c.client_uuid || c.name || 'node');

    const ramFactor = 0.94 + (rand * 0.04);
    const diskFactor = 0.91 + (rand * 0.04);

    return {
      ram: Math.floor(ramTotalMB * ramFactor * 1048576),
      disk: Math.floor(diskTotalMB * diskFactor * 1048576),
      swap: Math.floor(swapTotalMB * 1048576)
    };
  }

  // Generate stats based on time (stateless)
  generateStats(tickCount) {
    const c = this.config;
    const now = new Date();
    const hour = now.getHours();

    // Profile settings
    const profile = (c.load_profile || 'low').toLowerCase();
    const multipliers = {
      'low': 0.8, 'mid': 1.0, 'high': 1.2
    };
    const mult = multipliers[profile] || 1.0;

    // CPU Simulation
    // Use clear trigonometric functions for smooth waves without state
    const timeFactor = (Math.sin(((hour - 9) / 24) * 2 * Math.PI) + 1) / 2;
    const waveFactor = Math.sin(tickCount / 10) * 0.1;
    const fastWave = Math.sin(tickCount) * 0.05;

    const cpuMin = Number(c.cpu_min) || 0.5;
    const cpuMax = Number(c.cpu_max) || 100;
    const range = cpuMax - cpuMin;

    let cpu = cpuMin + (range * (0.1 + waveFactor) * timeFactor) + (range * fastWave);
    // Add some random noise
    cpu += (Math.random() - 0.5) * 2 * mult;
    cpu = Math.max(cpuMin, Math.min(cpuMax, cpu));

    // RAM Simulation
    const ramTotalMB = Number(c.ram_total) || 1024;
    const systemBaseMB = ramTotalMB <= 512 ? (ramTotalMB * 0.4) : (150 + ramTotalMB * 0.1);
    const systemBasePct = (systemBaseMB / ramTotalMB) * 100;

    const memMin = Math.max(Number(c.mem_min) || 0, systemBasePct);
    const memMax = Math.max(Number(c.mem_max) || 0, memMin + 20);

    // RAM follows CPU slightly
    let mem = memMin + (cpu / 100) * (memMax - memMin) * 0.5;
    mem += (Math.sin(tickCount / 50) * 2);
    mem = Math.max(memMin, Math.min(memMax, mem));

    // Disk
    const diskTotalMB = Number(c.disk_total) || 10240;
    const osUsageMB = diskTotalMB <= 2048 ? (diskTotalMB * 0.65) : (800 + diskTotalMB * 0.03);
    const osUsagePct = (osUsageMB / diskTotalMB) * 100;
    const dMin = Math.max(Number(c.disk_min) || 0, osUsagePct);

    let disk = dMin + (tickCount % 1000) * 0.0001; // Slow growth
    disk = Math.min(99, disk);

    // Swap
    let swap = (mem > 80) ? (mem - 80) * 1.2 : (Number(c.swap_min) || 0);

    // Network
    const netMin = Number(c.net_min) || 1024; // Bytes/sec approx base
    const netMax = Number(c.net_max) || 1024 * 1024;
    const netRange = netMax - netMin;
    const netVals = netMin + (netRange * (cpu / 100));

    const currentUp = netVals * 0.4 * (1 + Math.random() * 0.5);
    const currentDown = netVals * 0.6 * (1 + Math.random() * 0.5);

    // Calculate Total Traffic based on uptime
    // We can't persist totalUp/Dowm easily without D1 write every time.
    // So we approximate it based on uptimeBase + current session.
    // Or just send 0 if the dashboard calculates method calls.
    // But usually dashboard expects cumulative.
    // Approximation: Uptime (sec) * Average Speed
    const bootTime = Number(c.boot_time) || (Math.floor(Date.now() / 1000) - (c.uptime_base || 0));
    const uptime = Math.floor(Date.now() / 1000) - bootTime;
    const totalUp = uptime * (netMin + netMax) / 2 * 0.4;
    const totalDown = uptime * (netMin + netMax) / 2 * 0.6;

    // Connections
    const conn = Math.round((Number(c.conn_min) || 10) + (cpu * 2) + Math.random() * 10);
    const proc = Math.round((Number(c.proc_min) || 50) + (cpu * 0.5));

    return {
      cpu: parseFloat(cpu.toFixed(1)),
      mem: parseFloat(mem.toFixed(1)),
      swap: parseFloat(swap.toFixed(1)),
      disk: parseFloat(disk.toFixed(1)),
      net: {
        up: Math.floor(currentUp),
        down: Math.floor(currentDown),
        totalUp: Math.floor(totalUp),
        totalDown: Math.floor(totalDown)
      },
      conn: conn,
      proc: proc,
      gpu: 0 // Simplification
    };
  }

  async report(tickCount) {
    if (!this.config.enabled) return;

    // If not configured properly
    if (!this.config.server_address) return;

    const stats = this.generateStats(tickCount);
    const bootTime = Number(this.config.boot_time) || (Math.floor(Date.now() / 1000) - (this.config.uptime_base || 0));
    const uptime = Math.floor(Date.now() / 1000) - bootTime;

    const payload = {
      type: 'report',
      cpu: {
        name: this.config.cpu_model || 'Intel Xeon',
        cores: parseInt(this.config.cpu_cores) || 2,
        arch: this.config.arch || 'amd64',
        usage: stats.cpu
      },
      ram: {
        total: this.usable.ram,
        used: Math.round(this.usable.ram * stats.mem / 100)
      },
      swap: {
        total: this.usable.swap,
        used: Math.round(this.usable.swap * stats.swap / 100)
      },
      load: {
        load1: parseFloat((stats.cpu / 100 * (parseInt(this.config.cpu_cores) || 1)).toFixed(2)),
        load5: parseFloat((stats.cpu / 100 * (parseInt(this.config.cpu_cores) || 1) * 0.9).toFixed(2)),
        load15: parseFloat((stats.cpu / 100 * (parseInt(this.config.cpu_cores) || 1) * 0.8).toFixed(2))
      },
      disk: {
        total: this.usable.disk,
        used: Math.round(this.usable.disk * stats.disk / 100)
      },
      network: {
        up: stats.net.up,
        down: stats.net.down,
        totalUp: stats.net.totalUp,
        totalDown: stats.net.totalDown
      },
      connections: {
        tcp: stats.conn,
        udp: 0
      },
      uptime: uptime,
      process: stats.proc,
      ipv4: this.config.fake_ip || '',
      ipv6: this.config.ipv6 || ''
    };

    // Send logic
    // We try HTTP report mainly because keeping WebSocket open for 1s in a loop is expensive/complex vs one-off HTTP POST
    // Does the target support HTTP POST for report? 
    // Agent logic in server.js supports ws or http. 
    // Line 404: /api/v1/client/upload-basic-info via HTTP
    // Line 435: sendToConn via WS.
    // If target ONLY supports WS for stats, we MUST use WS.
    // Assuming target supports WS.

    // We will attempt to open a WS, send, and close immediately? 
    // Or just use HTTP if possible. 
    // Let's assume we try WS. 
    // But opening/closing WS every second is bad.
    // If we run a loop of 60s, we should OPEN WS at start, reuse it, close at end.

    return payload;
  }
}
