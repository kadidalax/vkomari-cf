import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { VirtualAgent } from '../src/agent.js';
import { CFMonitorReporter } from '../src/reporters/cfmonitor.js';
import { KomariReporter } from '../src/reporters/komari.js';
import { normalizeNodeData } from '../src/db.js';
import { cidrToIp } from '../public/js/ip.js';

function avg(profile, key) {
  const agent = new VirtualAgent({
    name: 'same-template-node',
    client_uuid: '11111111-1111-4111-8111-111111111111',
    ram_total: 2048,
    swap_total: 512,
    disk_total: 20480,
    load_profile: profile
  });
  let total = 0;
  for (let i = 0; i < 90; i++) total += agent.generateStats(i)[key];
  return total / 90;
}

assert.equal(typeof new CFMonitorReporter({}).tick, 'function', 'CF monitor tick method must not be shadowed');

const exactAgent = new VirtualAgent({
  name: 'exact-total-node',
  ram_total: 1024,
  swap_total: 2048,
  disk_total: 100
});
assert.equal(exactAgent.usable.ram, 1024 * 1048576, 'reported RAM total must match configured MB');
assert.equal(exactAgent.usable.swap, 2048 * 1048576, 'reported swap total must match configured MB');
assert.equal(exactAgent.usable.disk, 100 * 1048576, 'reported disk total must match configured MB');

const normalized = normalizeNodeData({ cpu_min: 100, cpu_max: 61.1, mem_min: 35.2, mem_max: 41.6, disk_min: 31.1, disk_max: 30.8 });
assert.equal(normalized.cpu_min, 61.1, 'CPU min/max should be sorted before save');
assert.equal(normalized.cpu_max, 100, 'CPU min/max should be sorted before save');
assert.equal(normalized.disk_min, 30.8, 'disk min/max should be sorted before save');
assert.equal(normalized.disk_max, 31.1, 'disk min/max should be sorted before save');
assert.equal(cidrToIp('15.0.0.0/4', () => 0), '15.0.0.1', 'country IP generation should stay inside the declared country block');
assert.match(cidrToIp('36.96.0.0/9', () => 0.99), /^36\.(?:9[6-9]|1\d\d|2[01]\d|22[0-3])\./, 'CN IP should stay inside the configured CN block');

const zeroRangeAgent = new VirtualAgent({
  name: 'zero-range-node',
  load_profile: 'high',
  ram_total: 1024,
  swap_total: 512,
  disk_total: 10240,
  cpu_min: 0,
  cpu_max: 1,
  mem_min: 0,
  mem_max: 10,
  swap_min: 0,
  swap_max: 1,
  disk_min: 0,
  disk_max: 10
});
for (let i = 0; i < 20; i++) {
  const s = zeroRangeAgent.generateStats(i);
  assert(s.cpu >= 0 && s.cpu <= 100, 'CPU must stay in valid percent bounds');
  assert(s.mem >= 0 && s.mem <= 100, 'memory must stay in valid percent bounds');
  assert(s.swap >= 0 && s.swap <= 100, 'swap must stay in valid percent bounds');
  assert(s.disk >= 0 && s.disk <= 100, 'disk must stay in valid percent bounds');
}
assert(avgFor(zeroRangeAgent, 'cpu') < 12, 'explicit CPU 0-1 soft range must not fall back to high profile defaults');
assert(avgFor(zeroRangeAgent, 'mem') < 18, 'explicit memory 0-10 soft range must not fall back to high profile defaults');

const demoCpuAgent = new VirtualAgent({
  name: 'demo-spike-node',
  client_uuid: '22222222-2222-4222-8222-222222222222',
  ram_total: 2048,
  swap_total: 512,
  disk_total: 20480,
  load_profile: 'high',
  cpu_min: 5,
  cpu_max: 95
});
const demoCpu = Array.from({ length: 180 }, (_, i) => demoCpuAgent.generateStats(i).cpu);
assert(Math.max(...demoCpu) - Math.min(...demoCpu) > 25, 'demo CPU should have frequent large swings');

const uptimeAgent = new VirtualAgent({
  name: 'moving-uptime-node',
  ram_total: 1024,
  disk_total: 10240,
  uptime_base: 86400,
  created_at: new Date(Date.now() - 600000).toISOString()
});
assert(uptimeAgent.generateStats(0).uptime >= 86900, 'uptime should continue from uptime_base when boot_time is absent');

function avgFor(agent, key, count = 90) {
  let total = 0;
  for (let i = 0; i < count; i++) total += agent.generateStats(i)[key];
  return total / count;
}

{
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    calls.push({ url: String(url), body: JSON.parse(options.body) });
    return { ok: true };
  };
  try {
    const reporter = new KomariReporter({
      komari_server: 'https://komari.example',
      komari_token: 'token',
      cpu_model: 'Intel Xeon',
      cpu_cores: 2,
      arch: 'amd64',
      os: 'Debian 12',
      kernel_version: '6.1.0',
      fake_ip: '154.126.95.20',
      region: 'KM',
      ram_total: 1024,
      swap_total: 2048,
      disk_total: 100,
      virtualization: 'kvm'
    });
    await reporter.uploadBasicInfo();
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(calls[0].url, 'https://komari.example/api/clients/uploadBasicInfo?token=token');
  assert.equal(calls[0].body.mem_total, 1024 * 1048576, 'Komari basic info RAM total must match config');
  assert.equal(calls[0].body.swap_total, 2048 * 1048576, 'Komari basic info swap total must match config');
  assert.equal(calls[0].body.disk_total, 100 * 1048576, 'Komari basic info disk total must match config');
  assert.equal(calls[0].body.region, String.fromCodePoint(0x1f1f0, 0x1f1f2), 'Komari basic info should send the configured country flag');
}

{
  const originalFetch = globalThis.fetch;
  const originalWebSocket = globalThis.WebSocket;
  const calls = [];
  const wsSends = [];
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), method: options.method, body: options.body ? JSON.parse(options.body) : null });
    return { ok: true };
  };
  class FakeWebSocket {
    static CONNECTING = 0;
    static OPEN = 1;
    constructor() {
      this.readyState = 1;
      this.handlers = {};
    }
    addEventListener(name, fn) { this.handlers[name] = fn; }
    send(body) { wsSends.push(JSON.parse(body)); }
    close() {}
  }
  globalThis.WebSocket = FakeWebSocket;
  try {
    const reporter = new KomariReporter({
      komari_server: 'https://komari.example',
      komari_token: 'token',
      ram_total: 1024,
      disk_total: 10240
    });
    await reporter.connect();
    await reporter.send();
    assert(calls.some(call => call.url === 'https://komari.example/api/clients/report?token=token' && call.method === 'POST'), 'Komari should use HTTP POST reports so Worker cron handoffs keep presence alive');
    assert.equal(wsSends.length, 0, 'Komari reporter should not depend on a long-lived WebSocket in Worker cron');
  } finally {
    globalThis.fetch = originalFetch;
    globalThis.WebSocket = originalWebSocket;
  }
}

assert(avg('mid', 'mem') > avg('low', 'mem') + 15, 'mid memory should be clearly above low');
assert(avg('high', 'mem') > avg('mid', 'mem') + 20, 'high memory should be clearly above mid');
assert(avg('high', 'disk') > avg('low', 'disk') + 35, 'disk load should differ by profile');
assert(avg('high', 'down') > avg('low', 'down') * 5, 'network load should differ by profile');

{
  const originalFetch = globalThis.fetch;
  const originalWebSocket = globalThis.WebSocket;
  const sockets = [];
  const sent = [];
  globalThis.fetch = async () => ({ ok: true });
  class FakeWebSocket {
    static CONNECTING = 0;
    static OPEN = 1;
    constructor(url) {
      this.url = url;
      this.readyState = 1;
      this.handlers = {};
      sockets.push(this);
    }
    addEventListener(name, fn) { this.handlers[name] = fn; }
    send(body) { sent.push(JSON.parse(body)); }
    close() {}
  }
  globalThis.WebSocket = FakeWebSocket;
  const reporter = new CFMonitorReporter({
    name: 'cf-demo',
    cfmonitor_server: 'https://cf.example',
    cfmonitor_token: 'cf-token',
    region: 'AE',
    fake_ip: '94.202.159.66',
    report_interval: 3,
    ram_total: 2048,
    swap_total: 512,
    disk_total: 20480,
    cpu_model: 'Intel Xeon',
    cpu_cores: 2,
    os: 'Debian 12',
    arch: 'amd64',
    virtualization: 'kvm'
  });
  try {
    const report = reporter.buildReport(Date.now());
    assert.equal(report.report_interval, 3, 'CF monitor report should include report_interval for live TTL');
    assert.equal(reporter.buildReport(Date.now(), 120).report_interval, 120, 'CF monitor idle report should use 120s TTL interval');
    assert(report.load > 0, 'CF monitor report should include load instead of always reporting 0');
    assert(report.temp > 0, 'CF monitor report should include realistic temperature instead of always reporting 0');
    assert.equal(report.ipv4, '94.202.159.66', 'CF monitor report should carry configured fake IPv4');
    assert.equal(report.basic_info?.ipv4, '94.202.159.66', 'CF monitor report should carry basic_info for metadata sync');
    assert.notEqual(report.region, 'AE', 'CF monitor region should not be a bare country code that the panel prefers below edge region');

    await reporter.connect();
    assert.equal(sockets[0]?.url, 'wss://cf.example/api/clients/report?token=cf-token', 'CF monitor should use Agent WebSocket with query token so active viewer policy can reach vKomari');
    sockets[0].handlers.message({ data: JSON.stringify({ type: 'policy', mode: 'active', sample_interval_sec: 3, report_interval_sec: 3, report_now: true }) });
    await reporter.tick();
    assert.equal(sent[0]?.report_interval, 3, 'active viewer policy should switch CF monitor reports to 3 seconds');
  } finally {
    globalThis.fetch = originalFetch;
    globalThis.WebSocket = originalWebSocket;
  }
}

const { parseInstallScript } = await import('../public/js/install.js');

assert.deepEqual(
  parseInstallScript('wget -qO- https://raw.githubusercontent.com/komari-monitor/komari-agent/refs/heads/main/install.sh | sudo bash -s -- -e https://komari.54bpg.eu.org -t QpiV5Jn4aXbs6wZ9soHS9q --disable-web-ssh --month-rotate 1'),
  { panel: 'komari', server: 'https://komari.54bpg.eu.org', token: 'QpiV5Jn4aXbs6wZ9soHS9q' }
);

assert.deepEqual(
  parseInstallScript(`wget -qO- 'https://raw.githubusercontent.com/kadidalax/cf-monitor-test/refs/heads/main/agent/install-linux.sh' | { SUDO=; [ "$(id -u)" -eq 0 ] || SUDO=sudo; $SUDO bash -s -- '-s' 'https://cf-vps-monitor.qaq-bde.workers.dev' '-t' 'ff347643539d0fb0f53f1bedc7489e8ba8c13fde6c88272abf95f2492a6398b2' '-n' '4' '-i' '4d0ec364-38a3-42b3-acc9-24bf38b702f6'; }`),
  {
    panel: 'cfmonitor',
    server: 'https://cf-vps-monitor.qaq-bde.workers.dev',
    token: 'ff347643539d0fb0f53f1bedc7489e8ba8c13fde6c88272abf95f2492a6398b2',
    name: '4',
    uuid: '4d0ec364-38a3-42b3-acc9-24bf38b702f6'
  }
);

const indexHtml = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
assert.match(indexHtml, /@click="refreshLoad\(\)"/, 'modal random button should refresh load only');
assert(!indexHtml.includes('randomizeConfig'), 'refresh load must not randomize node hardware, OS, region, IP, or tokens');
assert(indexHtml.includes('sessionExpired'), 'expired login state should have a visible page/message');
assert(indexHtml.includes('window.cidrToIp'), 'country IP generation should use the shared tested CIDR helper');

const indexJs = readFileSync(new URL('../src/index.js', import.meta.url), 'utf8');
assert(!indexJs.includes('setTimeout(resolve, 2000)'), 'Komari cron loop must not add a fixed 2s upload gap before sending');
assert.match(indexJs, /MAX_DURATION\s*=\s*6[2-9]\d{3}/, 'Komari cron loop should overlap the next minute to hide handoff gaps');
assert.match(indexJs, /await\s+r\.inst\.send\(\)/, 'cron must await Komari POST reports before the Worker tick ends');
