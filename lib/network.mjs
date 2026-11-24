import { execFile } from 'node:child_process';
import os from 'node:os';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export function isPrivateIPv4(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  return p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168);
}

export function isValidIPv4(ip) {
  return /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(ip) && ip.split('.').every((n) => Number(n) <= 255);
}

/** LAN-facing interfaces (Ethernet, Wi-Fi, bridges) with a private IPv4 address. */
export function lanInterfaces() {
  const result = [];
  for (const [name, addresses] of Object.entries(os.networkInterfaces())) {
    if (!/^(en|bridge)\d+$/.test(name)) continue;
    for (const address of addresses ?? []) {
      if (address.family !== 'IPv4' || address.internal || !isPrivateIPv4(address.address)) continue;
      result.push({ name, address: address.address, netmask: address.netmask, cidr: address.cidr });
    }
  }
  return result;
}

export async function hardwarePortNames() {
  try {
    const { stdout } = await execFileAsync('/usr/sbin/networksetup', ['-listallhardwareports']);
    const names = {};
    for (const block of stdout.split(/\n\n+/)) {
      const port = block.match(/Hardware Port: (.+)/)?.[1];
      const device = block.match(/Device: (.+)/)?.[1];
      if (port && device) names[device.trim()] = port.trim();
    }
    return names;
  } catch {
    return {};
  }
}

export async function defaultGateway() {
  try {
    const { stdout } = await execFileAsync('/sbin/route', ['-n', 'get', 'default']);
    return {
      gateway: stdout.match(/gateway: (\S+)/)?.[1] ?? null,
      interface: stdout.match(/interface: (\S+)/)?.[1] ?? null,
    };
  } catch {
    return { gateway: null, interface: null };
  }
}

export async function networkSummary() {
  const [names, route] = await Promise.all([hardwarePortNames(), defaultGateway()]);
  const interfaces = lanInterfaces().map((i) => ({
    ...i,
    kind: names[i.name] ?? i.name,
    primary: i.name === route.interface,
  }));
  return { interfaces, router: route.gateway, primaryInterface: route.interface };
}
