import assert from 'node:assert/strict';
import { VirtualAgent } from '../src/agent.js';
import { CFMonitorReporter } from '../src/reporters/cfmonitor.js';

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
