export function parseInstallScript(input) {
  const args = String(input || '').match(/'[^']*'|"[^"]*"|\S+/g)?.map(cleanArg) || [];
  const flag = (name, ok = () => true) => {
    for (let i = 0; i < args.length - 1; i++) {
      if (args[i] === name && ok(args[i + 1])) return cleanArg(args[i + 1] || '');
    }
    return '';
  };
  const isUrl = (value) => /^https?:\/\//i.test(value);
  const komariServer = flag('-e', isUrl);
  const cfServer = flag('-s', isUrl);
  const server = komariServer || cfServer;
  const token = flag('-t');
  if (!server || !token) return null;
  const panel = cfServer ? 'cfmonitor' : 'komari';
  const result = { panel, server, token };
  const name = flag('-n');
  const uuid = flag('-i');
  if (name) result.name = name;
  if (uuid) result.uuid = uuid;
  return result;
}

function cleanArg(value) {
  return String(value || '').replace(/^['"]|['"]$/g, '').replace(/[;}]+$/g, '');
}

if (typeof window !== 'undefined') window.parseInstallScript = parseInstallScript;
