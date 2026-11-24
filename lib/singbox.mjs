import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import path from 'node:path';
import { writeFileAtomic } from './store.mjs';

export const proxyTag = (proxy) => `p-${proxy.id}`;
export const deviceTag = (device) => `dev-${device.id}`;

/** Outbound tag a device should use right now. */
export function deviceTarget(device, proxies) {
  if (device.mode === 'direct') return 'direct';
  if (device.mode === 'proxy') {
    const proxy = proxies.find((p) => p.id === device.proxyId);
    if (proxy) return proxyTag(proxy);
  }
  return 'block';
}

function proxyOutbound(proxy) {
  const base = { tag: proxyTag(proxy), server: proxy.host, server_port: proxy.port };
  if (proxy.username) {
    base.username = proxy.username;
    base.password = proxy.password ?? '';
  }
  if (proxy.type === 'http') return { type: 'http', ...base };
  return { type: 'socks', version: '5', ...base };
}

/**
 * Build the sing-box config. TCP from devices arrives on the redirect inbound (pf rdr),
 * DNS on the direct inbound. DNS answers are fake IPs, so proxies receive domain names and
 * resolve them on their side.
 */
export function buildConfig({ devices, proxies, ports, clashSecret, directDomains = [], logLevel = 'warn' }) {
  const selectable = [...proxies.map(proxyTag), 'direct', 'block'];
  return {
    log: { level: logLevel, timestamp: true },
    dns: {
      servers: [
        { type: 'local', tag: 'local' },
        { type: 'fakeip', tag: 'fakeip', inet4_range: '198.18.0.0/15' },
      ],
      rules: [
        { query_type: ['AAAA', 'HTTPS', 'SVCB'], action: 'predefined', rcode: 'NOERROR' },
        { query_type: ['A'], server: 'fakeip' },
      ],
      final: 'local',
      strategy: 'ipv4_only',
    },
    inbounds: [
      { type: 'redirect', tag: 'tcp-in', listen: '127.0.0.1', listen_port: ports.redirect },
      { type: 'direct', tag: 'dns-udp', listen: '127.0.0.1', listen_port: ports.dns, network: 'udp' },
      { type: 'direct', tag: 'dns-tcp', listen: '127.0.0.1', listen_port: ports.dns, network: 'tcp' },
    ],
    outbounds: [
      { type: 'direct', tag: 'direct' },
      { type: 'block', tag: 'block' },
      ...proxies.map(proxyOutbound),
      ...devices.map((device) => ({
        type: 'selector',
        tag: deviceTag(device),
        outbounds: selectable,
        default: deviceTarget(device, proxies),
        interrupt_exist_connections: true,
      })),
    ],
    route: {
      rules: [
        { inbound: ['dns-udp', 'dns-tcp'], action: 'hijack-dns' },
        { action: 'sniff' },
        // This Mac's own dashboards: reachable even when a device is blocked or its proxy only allows ports 80/443.
        ...(directDomains.length ? [{ domain: directDomains, outbound: 'direct' }] : []),
        ...devices.map((device) => ({ source_ip_cidr: [`${device.ip}/32`], outbound: deviceTag(device) })),
      ],
      final: 'block',
      default_domain_resolver: 'local',
    },
    experimental: {
      cache_file: { enabled: true, path: 'cache.db', store_fakeip: true },
      clash_api: { external_controller: `127.0.0.1:${ports.clash}`, secret: clashSecret },
    },
  };
}

/** Hash of everything except selector defaults: a change here needs a sing-box restart. */
export function structureHash(config) {
  const copy = structuredClone(config);
  for (const outbound of copy.outbounds) if (outbound.type === 'selector') delete outbound.default;
  return crypto.createHash('sha256').update(JSON.stringify(copy)).digest('hex');
}

export class SingBox extends EventEmitter {
  constructor({ binary, workDir, ports, clashSecret }) {
    super();
    this.binary = binary;
    this.workDir = workDir;
    this.configFile = path.join(workDir, 'sing-box.json');
    this.ports = ports;
    this.clashSecret = clashSecret;
    this.child = null;
    this.wanted = false;
    this.logs = [];
    this.restartDelay = 1000;
    this.startedAt = null;
    this.lastExit = null;
  }

  log(line) {
    this.logs.push({ at: Date.now(), line });
    if (this.logs.length > 400) this.logs.splice(0, this.logs.length - 400);
  }

  writeConfig(config) {
    fs.mkdirSync(this.workDir, { recursive: true, mode: 0o700 });
    writeFileAtomic(this.configFile, `${JSON.stringify(config, null, 2)}\n`, path.dirname(this.workDir));
  }

  get running() {
    return Boolean(this.child && this.child.exitCode === null);
  }

  async check() {
    return new Promise((resolve) => {
      const child = spawn(this.binary, ['check', '-c', this.configFile, '-D', this.workDir]);
      let output = '';
      child.stdout.on('data', (d) => (output += d));
      child.stderr.on('data', (d) => (output += d));
      child.on('error', (error) => resolve({ ok: false, output: error.message }));
      child.on('exit', (code) => resolve({ ok: code === 0, output: output.trim() }));
    });
  }

  start() {
    this.wanted = true;
    if (this.running) return;
    const child = spawn(this.binary, ['run', '-c', this.configFile, '-D', this.workDir], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    this.child = child;
    this.startedAt = Date.now();
    this.log(`[relay] sing-box started (pid ${child.pid})`);
    const onData = (chunk) => {
      for (const line of chunk.toString().split('\n')) if (line.trim()) this.log(line.replace(/\x1b\[[0-9;]*m/g, ''));
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('error', (error) => this.log(`[relay] failed to start sing-box: ${error.message}`));
    child.on('exit', (code, signal) => {
      this.lastExit = { code, signal, at: Date.now() };
      if (this.child === child) this.child = null;
      this.log(`[relay] sing-box exited (code ${code}, signal ${signal})`);
      this.emit('exit');
      if (this.wanted) {
        const uptime = Date.now() - (this.startedAt ?? 0);
        this.restartDelay = uptime > 30000 ? 1000 : Math.min(this.restartDelay * 2, 30000);
        setTimeout(() => this.wanted && !this.running && this.start(), this.restartDelay).unref();
      }
    });
  }

  async stop() {
    this.wanted = false;
    const child = this.child;
    if (!child || child.exitCode !== null) return;
    await new Promise((resolve) => {
      const timer = setTimeout(() => child.kill('SIGKILL'), 4000);
      child.once('exit', () => {
        clearTimeout(timer);
        resolve();
      });
      child.kill('SIGTERM');
    });
  }

  async restart() {
    await this.stop();
    this.start();
    await this.waitForApi(5000);
  }

  async api(method, pathname, body) {
    const response = await fetch(`http://127.0.0.1:${this.ports.clash}${pathname}`, {
      method,
      headers: { Authorization: `Bearer ${this.clashSecret}`, 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(3000),
    });
    if (!response.ok) throw new Error(`sing-box API ${method} ${pathname}: HTTP ${response.status}`);
    const text = await response.text();
    return text ? JSON.parse(text) : null;
  }

  async waitForApi(timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (!this.running) return false;
      try {
        await this.api('GET', '/version');
        return true;
      } catch {
        await new Promise((r) => setTimeout(r, 150));
      }
    }
    return false;
  }

  async select(selectorTag, outboundTag) {
    await this.api('PUT', `/proxies/${encodeURIComponent(selectorTag)}`, { name: outboundTag });
  }

  async connections() {
    return this.api('GET', '/connections');
  }
}
