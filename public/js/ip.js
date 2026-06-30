export function cidrToIp(cidr, random = Math.random) {
  const [base, maskText] = String(cidr || '').split('/');
  const mask = Number(maskText);
  const parts = base.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255) || mask < 0 || mask > 32) return '';

  const start = (((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3]) >>> 0;
  const size = 2 ** (32 - mask);
  const usable = Math.max(1, size - 2);
  const offset = size <= 2 ? 0 : 1 + Math.floor(random() * usable);
  const final = Math.min(0xffffffff, start + offset) >>> 0;
  return [final >>> 24, (final >>> 16) & 255, (final >>> 8) & 255, final & 255].join('.');
}

if (typeof window !== 'undefined') window.cidrToIp = cidrToIp;
