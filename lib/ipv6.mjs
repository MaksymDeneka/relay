import { execFile } from 'node:child_process';
import os from 'node:os';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const LAN = /^(en|bridge)\d+$/;

// Relay routes IPv4 only. If the router hands out public IPv6, listed devices can reach the
// internet over IPv6 straight through the router, around Relay. Local-only IPv6 (fd00::/8 ULA,
// e.g. from a HomePod acting as a Thread border router, and fe80:: link-local) is harmless.
export const isGlobalIPv6 = (address) => /^[23][0-9a-f]{0,3}:/i.test(address);

/** The 8 groups of an IPv6 address as numbers. */
function groups(address) {
  const [head, tail = null] = address.split('%')[0].split('::');
  const parse = (part) => (part ? part.split(':').map((g) => parseInt(g, 16)) : []);
  const left = parse(head);
  const right = tail === null ? [] : parse(tail);
  return [...left, ...new Array(8 - left.length - right.length).fill(0), ...right];
}

/** "2001:4860::1234" with length 64 → "2001:4860::/64". */
export function ipv6Prefix(address, length = 64) {
  const masked = groups(address).map((g, i) => {
    const bits = Math.max(0, Math.min(16, length - i * 16));
    return bits === 16 ? g : bits === 0 ? 0 : g & (0xffff << (16 - bits)) & 0xffff;
  });
  let end = masked.length;
  while (end > 0 && masked[end - 1] === 0) end--;
  const text = masked.slice(0, end).map((g) => g.toString(16)).join(':');
  return `${text}${end < 8 ? '::' : ''}/${length}`;
}

const netmaskLength = (mask) => groups(mask).reduce((n, g) => n + g.toString(2).replace(/0/g, '').length, 0);
const normalizeMac = (mac) => (/^[0-9a-f]{1,2}(:[0-9a-f]{1,2}){5}$/i.test(mac) ? mac.toLowerCase().split(':').map((p) => p.padStart(2, '0')).join(':') : null);
const ipv4Number = (ip) => ip.split('.').reduce((n, part) => n * 256 + Number(part), 0);
const sameSubnet = (a, b, mask) => (ipv4Number(a) & ipv4Number(mask)) >>> 0 === (ipv4Number(b) & ipv4Number(mask)) >>> 0;

/** `arp -an` lines: "? (192.168.0.1) at 50:f:f5:d9:c3:50 on en7 ifscope [ethernet]". */
export function parseArp(text) {
  const result = new Map();
  for (const line of text.split('\n')) {
    const match = line.match(/\((\d+\.\d+\.\d+\.\d+)\) at (\S+) on (\S+)/);
    const mac = match && normalizeMac(match[2]);
    if (mac) result.set(match[1], { mac, iface: match[3] });
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

/** `ndp -pn` blocks start with "2a02:…::/64 if=en0": prefixes learned from router advertisements. */
export function parsePrefixes(text) {
  const result = [];
  for (const line of text.split('\n')) {
    const match = line.match(/^([0-9a-f:]+)\/(\d+) if=(\S+)/i);
    if (match) result.push({ prefix: match[1], length: Number(match[2]), iface: match[3] });
  }
  return result;
}

/** Interfaces that serve listed devices: where ARP saw them, or whose IPv4 subnet holds them. */
function managedInterfaces({ interfaces, arp, devices }) {
  const names = new Set();
  for (const device of devices) {
    const entry = arp.get(device.ip);
    if (entry && LAN.test(entry.iface)) names.add(entry.iface);
  }
  for (const [name, addresses] of Object.entries(interfaces)) {
    if (!LAN.test(name)) continue;
    for (const a of addresses ?? []) {
      if (a.family === 'IPv4' && devices.some((d) => sameSubnet(d.ip, a.address, a.netmask))) names.add(name);
    }
  }
  return names;
}

/**
 * Public IPv6 on the network that serves listed devices (an address of this Mac, a prefix the
 * router advertises, or a neighbour's address), and listed devices that have a public IPv6
 * address themselves (matched by MAC on the same link). `available` is false when the tables
 * could not be read, which is not the same as a clear result.
 */
export function ipv6Exposure({ interfaces, arp, ndp, prefixes = [], devices, available = true }) {
  const managed = managedInterfaces({ interfaces, arp, devices });
  const found = new Set();
  for (const name of managed) {
    for (const a of interfaces[name] ?? []) {
      if (a.family === 'IPv6' && isGlobalIPv6(a.address)) found.add(ipv6Prefix(a.address, a.netmask ? netmaskLength(a.netmask) : 64));
    }
  }
  for (const p of prefixes) if (managed.has(p.iface) && isGlobalIPv6(p.prefix)) found.add(ipv6Prefix(p.prefix, p.length));
  const neighbours = ndp.filter((n) => managed.has(n.iface) && isGlobalIPv6(n.address));
  if (found.size === 0) for (const n of neighbours) found.add(n.address);
  const exposedDevices = [];
  for (const device of devices) {
    const entry = arp.get(device.ip);
    const addresses = entry ? neighbours.filter((n) => n.mac === entry.mac && n.iface === entry.iface).map((n) => n.address) : [];
    if (addresses.length) exposedDevices.push({ id: device.id, name: device.name, addresses: [...new Set(addresses)] });
  }
  return { available, exposed: found.size > 0 || exposedDevices.length > 0, prefixes: [...found].sort(), devices: exposedDevices };
}

async function run(command, args) {
  try {
    return { ok: true, out: (await execFileAsync(command, args, { timeout: 5000 })).stdout };
  } catch {
    return { ok: false, out: '' };
  }
}

/** Read the live tables. MAC addresses in them are only visible to root. */
export async function readIPv6Exposure(devices) {
  const [arp, ndp, prefixes] = await Promise.all([run('/usr/sbin/arp', ['-an']), run('/usr/sbin/ndp', ['-an']), run('/usr/sbin/ndp', ['-pn'])]);
  const arpTable = parseArp(arp.out);
  const available = arp.ok && ndp.ok && prefixes.ok && (devices.length === 0 || arpTable.size > 0);
  return { ...ipv6Exposure({ interfaces: os.networkInterfaces(), arp: arpTable, ndp: parseNdp(ndp.out), prefixes: parsePrefixes(prefixes.out), devices, available }), at: Date.now() };
}
