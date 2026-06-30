import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { VirtualAgent } from '../src/agent.js';
import { CFMonitorReporter } from '../src/reporters/cfmonitor.js';
import { KomariReporter } from '../src/reporters/komari.js';
import { normalizeNodeData } from '../src/db.js';

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
}

assert(avg('mid', 'mem') > avg('low', 'mem') + 15, 'mid memory should be clearly above low');
assert(avg('high', 'mem') > avg('mid', 'mem') + 20, 'high memory should be clearly above mid');
assert(avg('high', 'disk') > avg('low', 'disk') + 35, 'disk load should differ by profile');
assert(avg('high', 'down') > avg('low', 'down') * 5, 'network load should differ by profile');

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
