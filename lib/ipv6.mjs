import { execFile } from 'node:child_process';
import os from 'node:os';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

// Relay routes IPv4 only. If the router hands out public IPv6, listed devices can reach the
// internet over IPv6 straight through the router, around Relay. Local-only IPv6 (fd00::/8 ULA,
// e.g. from a HomePod acting as a Thread border router, and fe80:: link-local) is harmless.
export const isGlobalIPv6 = (address) => /^[23][0-9a-f]{0,3}:/i.test(address);

const normalizeMac = (mac) => (/^[0-9a-f]{1,2}(:[0-9a-f]{1,2}){5}$/i.test(mac) ? mac.toLowerCase().split(':').map((p) => p.padStart(2, '0')).join(':') : null);
const prefix64 = (address) => `${address.split(':').slice(0, 4).join(':')}::/64`;

/** `arp -an` lines: "? (192.168.0.1) at 50:f:f5:d9:c3:50 on en7 ifscope [ethernet]". */
export function parseArp(text) {
  const result = new Map();
  for (const line of text.split('\n')) {
    const match = line.match(/\((\d+\.\d+\.\d+\.\d+)\) at (\S+)/);
    const mac = match && normalizeMac(match[2]);
    if (mac) result.set(match[1], mac);
  }
  return result;
}

/** `ndp -an` lines: "2a02:…:55ab  f2:49:53:91:b4:c2  en7 22h3m52s  S". */
export function parseNdp(text) {
  const result = [];
  for (const line of text.split('\n').slice(1)) {
    const [address, link, iface] = line.trim().split(/\s+/);
    const mac = normalizeMac(link ?? '');
    if (address && mac) result.push({ address: address.split('%')[0], mac, iface });
  }
  return result;
}

/**
 * Public IPv6 on this Mac's LAN interfaces (the router advertises a public prefix), and listed
 * devices that have a public IPv6 address (matched by MAC through the ARP and NDP tables).
 */
export function ipv6Exposure({ interfaces, arp, ndp, devices }) {
  const prefixes = new Set();
  for (const [name, addresses] of Object.entries(interfaces)) {
    if (!/^(en|bridge)\d+$/.test(name)) continue;
    for (const a of addresses ?? []) if (a.family === 'IPv6' && isGlobalIPv6(a.address)) prefixes.add(prefix64(a.address));
  }
  for (const entry of ndp) if (/^(en|bridge)\d+$/.test(entry.iface ?? '') && isGlobalIPv6(entry.address)) prefixes.add(prefix64(entry.address));
  const exposedDevices = [];
  for (const device of devices) {
    const mac = arp.get(device.ip);
    const addresses = mac ? ndp.filter((n) => n.mac === mac && isGlobalIPv6(n.address)).map((n) => n.address) : [];
    if (addresses.length) exposedDevices.push({ id: device.id, name: device.name, addresses: [...new Set(addresses)] });
  }
  return { exposed: prefixes.size > 0 || exposedDevices.length > 0, prefixes: [...prefixes].sort(), devices: exposedDevices };
}

async function run(command, args) {
  try {
    return (await execFileAsync(command, args, { timeout: 5000 })).stdout;
  } catch {
    return '';
  }
}

/** Read the live tables. MAC addresses in them are only visible to root. */
export async function readIPv6Exposure(devices) {
  const [arp, ndp] = await Promise.all([run('/usr/sbin/arp', ['-an']), run('/usr/sbin/ndp', ['-an'])]);
  return { ...ipv6Exposure({ interfaces: os.networkInterfaces(), arp: parseArp(arp), ndp: parseNdp(ndp), devices }), at: Date.now() };
}
