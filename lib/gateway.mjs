import { spawn } from 'node:child_process';
import { isValidIPv4 } from './network.mjs';
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
    this.epoch = '';
    singbox.on('exit', () => {
      this.applied.clear();
    });
    // After a crash, rebuild from saved routes with fresh selector tags rather than letting
    // sing-box restore cached choices that may predate the last change.
    singbox.on('crash', (delay) => {
      this.lastHash = null;
      setTimeout(() => this.apply().catch(() => {}), delay).unref();
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

      const deviceIps = devices.map((d) => d.ip);
      const rules = renderRules({ deviceIps, ports: this.ports });
      const blockOnly = renderRules({ deviceIps, ports: this.ports, blockOnly: true });
      // An IP new to the rules (every IP, at boot) is cut off first, so it is never forwarded
      // unproxied while sing-box is checked and started.
      if (rules !== this.pf.lastRules) await this.pf.apply(blockOnly);

      const build = (epoch) => buildConfig({ devices, proxies, ports: this.ports, clashSecret: settings.clashSecret, dashboards: this.dashboards, epoch });
      // Targets as written into this config; devices can change while sing-box restarts.
      const targets = new Map(devices.map((d) => [d.id, deviceTarget(d, proxies)]));
      const hash = structureHash(build(''));
      if (hash !== this.lastHash || !this.singbox.running) {
        // New selector tags, so no cached choice from an earlier run applies: each device starts
        // on the route in this config.
        this.epoch = Date.now().toString(36);
        this.singbox.writeConfig(build(this.epoch));
        const check = await this.singbox.check();
        if (!check.ok) throw new Error(`sing-box rejected the config: ${check.output}`);
        await this.singbox.restart();
        this.lastHash = hash;
        this.applied = new Map(targets);
      } else {
        this.singbox.writeConfig(build(this.epoch));
      }
      try {
        for (const device of devices) {
          const target = targets.get(device.id);
          if (this.applied.get(device.id) === target) continue;
          await this.singbox.select(deviceTag(device, this.epoch), target);
          this.applied.set(device.id, target);
        }
      } catch (error) {
        // A device could be on a stale route, and connections it already has would survive a pf
        // reload: block, stop sing-box, and start over from saved routes on the next apply.
        await this.pf.apply(blockOnly).catch(() => {});
        await this.singbox.stop();
        this.lastHash = null;
        throw error;
      }

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
        if (devices.length) {
          // Keep listed devices offline while stopped, in case they still use this Mac as their
          // router. If that fails, leave the loaded rules: with sing-box gone they block as well.
          try {
            await this.pf.apply(renderRules({ deviceIps: devices.map((d) => d.ip), ports: this.ports, blockOnly: true }));
          } catch (error) {
            console.error(`Kept the running pf rules: ${error.message}`);
          }
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
