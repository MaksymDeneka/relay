import { spawn } from 'node:child_process';
import { isValidIPv4, lanInterfaces } from './network.mjs';
import { renderRules } from './pf.mjs';
import { buildConfig, deviceTag, deviceTarget, structureHash } from './singbox.mjs';

/** Keeps sing-box, the pf anchor and the sleep assertion in line with the saved devices and proxies. */
export class Gateway {
  constructor({ store, singbox, pf, ports, isRoot, dashboards = null }) {
    this.store = store;
    this.singbox = singbox;
    this.pf = pf;
    this.ports = ports;
    this.isRoot = isRoot;
    this.dashboards = dashboards;
    this.queue = Promise.resolve();
    this.lastHash = null;
    this.applied = new Map();
    this.lastError = isRoot ? null : 'The dashboard is not running as root, so routing is off. Install it as a service (see README).';
    this.lastAppliedAt = null;
    this.caffeinate = null;
    this.lastSeen = new Map();
    singbox.on('exit', () => {
      this.applied.clear();
    });
  }

  run(task) {
    const result = this.queue.then(task, task);
    this.queue = result.catch(() => {});
    return result;
  }

  activeDevices() {
    return this.store.data.devices.filter((d) => isValidIPv4(d.ip));
  }

  apply() {
    return this.run(() => this.#apply());
  }

  async #apply() {
    if (!this.isRoot) return;
    const { proxies, settings } = this.store.data;
    const devices = this.activeDevices();
    try {
      if (devices.length === 0) {
        await this.singbox.stop();
        await this.pf.clear();
        this.#setAwake(false);
        this.lastHash = null;
        this.applied.clear();
        this.lastError = null;
        this.lastAppliedAt = Date.now();
        return;
      }

      const config = buildConfig({ devices, proxies, ports: this.ports, clashSecret: settings.clashSecret, dashboards: this.dashboards });
      // Targets as written into this config; devices can change while sing-box restarts.
      const targets = new Map(devices.map((d) => [d.id, deviceTarget(d, proxies)]));
      const hash = structureHash(config);
      if (hash !== this.lastHash || !this.singbox.running) {
        this.singbox.writeConfig(config);
        const check = await this.singbox.check();
        if (!check.ok) throw new Error(`sing-box rejected the config: ${check.output}`);
        await this.singbox.restart();
        this.lastHash = hash;
        this.applied.clear();
        for (const [id, target] of targets) this.applied.set(id, target);
      } else {
        this.singbox.writeConfig(config);
        for (const device of devices) {
          const target = targets.get(device.id);
          if (this.applied.get(device.id) === target) continue;
          await this.singbox.select(deviceTag(device), target);
          this.applied.set(device.id, target);
        }
      }

      const interfaces = [...new Set(lanInterfaces().map((i) => i.name))];
      if (interfaces.length === 0) throw new Error('No LAN interface with a private IPv4 address was found.');
      const rules = renderRules({ interfaces, deviceIps: devices.map((d) => d.ip), ports: this.ports });
      if (rules !== this.pf.lastRules || !(await this.pf.healthy())) await this.pf.apply(rules);

      this.#setAwake(true);
      this.lastError = null;
      this.lastAppliedAt = Date.now();
    } catch (error) {
      this.lastError = error.message;
      throw error;
    }
  }

  #setAwake(on) {
    if (on && !this.caffeinate) {
      // Prevent idle sleep while devices depend on this Mac; exits with this process.
      this.caffeinate = spawn('/usr/bin/caffeinate', ['-i', '-w', String(process.pid)], { stdio: 'ignore' });
      this.caffeinate.on('exit', () => (this.caffeinate = null));
    } else if (!on && this.caffeinate) {
      this.caffeinate.kill();
      this.caffeinate = null;
    }
  }

  async shutdown() {
    await this.run(async () => {
      await this.singbox.stop();
      if (this.isRoot) {
        const devices = this.activeDevices();
        const interfaces = [...new Set(lanInterfaces().map((i) => i.name))];
        if (devices.length && interfaces.length) {
          await this.pf
            .apply(renderRules({ interfaces, deviceIps: devices.map((d) => d.ip), ports: this.ports, blockOnly: true }))
            .catch(() => this.pf.clear());
        } else {
          await this.pf.clear();
        }
      }
      this.#setAwake(false);
    });
  }

  /** Active connections and traffic per device, from the sing-box API. */
  async live() {
    const result = {};
    if (!this.singbox.running) return { running: false, devices: result };
    let data;
    try {
      data = await this.singbox.connections();
    } catch (error) {
      return { running: true, error: error.message, devices: result };
    }
    const byIp = new Map(this.activeDevices().map((d) => [d.ip, d]));
    for (const connection of data?.connections ?? []) {
      const ip = connection.metadata?.sourceIP;
      const device = byIp.get(ip);
      if (!device) continue;
      this.lastSeen.set(device.id, Date.now());
      const entry = (result[device.id] ??= { connections: 0, upload: 0, download: 0, hosts: {} });
      entry.connections += 1;
      entry.upload += connection.upload ?? 0;
      entry.download += connection.download ?? 0;
      const host = connection.metadata?.host || connection.metadata?.destinationIP;
      if (host) entry.hosts[host] = (entry.hosts[host] ?? 0) + 1;
    }
    for (const device of this.activeDevices()) {
      const entry = (result[device.id] ??= { connections: 0, upload: 0, download: 0, hosts: {} });
      entry.lastSeen = this.lastSeen.get(device.id) ?? null;
      entry.topHosts = Object.entries(entry.hosts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([host, count]) => ({ host, count }));
      delete entry.hosts;
    }
    return { running: true, devices: result };
  }
}
