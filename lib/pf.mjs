import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { writeFileAtomic } from './store.mjs';

const execFileAsync = promisify(execFile);
const PFCTL = '/sbin/pfctl';
const SYSCTL = '/usr/sbin/sysctl';
// A sub-anchor of com.apple/* is evaluated by the stock /etc/pf.conf, so no system file is edited.
export const ANCHOR = 'com.apple/relay';

export const LOCAL_RANGES = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '224.0.0.0/4',
  '240.0.0.0/4',
];

/**
 * Rules for the anchor: DNS and outside-bound TCP from managed devices go to sing-box;
 * everything else they send to outside addresses (UDP, ICMP) is dropped so nothing leaks.
 */
export function renderRules({ deviceIps, ports, blockOnly = false }) {
  // No interface names: listed IPs only ever arrive from the LAN, and matching on every
  // interface means one attached later (Wi-Fi rejoining, a new adapter) is covered at once.
  return [
    `table <relay_devices> const { ${deviceIps.join(' ')} }`,
    `table <relay_local> const { ${LOCAL_RANGES.join(' ')} }`,
    // blockOnly: kept while the service is stopped, so devices that still use this Mac as their
    // router get no internet rather than being forwarded around the proxy.
    ...(blockOnly
      ? []
      : [
          `rdr pass inet proto { tcp udp } from <relay_devices> to any port 53 -> 127.0.0.1 port ${ports.dns}`,
          `rdr pass inet proto tcp from <relay_devices> to ! <relay_local> -> 127.0.0.1 port ${ports.redirect}`,
        ]),
    `block drop in quick inet from <relay_devices> to { 127.0.0.0/8 100.64.0.0/10 }`,
    `block drop in quick inet from <relay_devices> to ! <relay_local>`,
    '',
  ].join('\n');
}

async function pfctl(args) {
  try {
    const { stdout, stderr } = await execFileAsync(PFCTL, args);
    return { ok: true, stdout, stderr };
  } catch (error) {
    return { ok: false, stdout: error.stdout ?? '', stderr: error.stderr ?? error.message };
  }
}

async function bootTime() {
  try {
    const { stdout } = await execFileAsync(SYSCTL, ['-n', 'kern.boottime']);
    return stdout.match(/sec = (\d+)/)?.[1] ?? null;
  } catch {
    return null;
  }
}

/**
 * pf stays enabled while anyone holds an enable reference (pfctl -E). Relay holds one, kept in
 * pf-token with the boot time, so a restart replaces it instead of piling up references and
 * uninstall can release it. A token from an earlier boot is never released: its number may
 * belong to another program by now.
 */
export class PacketFilter {
  constructor({ workDir }) {
    this.workDir = workDir;
    this.rulesFile = path.join(workDir, 'pf-relay.conf');
    this.tokenFile = path.join(workDir, 'pf-token');
    this.token = null;
    this.lastRules = null;
    this.lastError = null;
  }

  async apply(rules) {
    writeFileAtomic(this.rulesFile, rules, path.dirname(this.workDir));
    const load = await pfctl(['-a', ANCHOR, '-f', this.rulesFile]);
    if (!load.ok) {
      this.lastError = load.stderr.trim();
      throw new Error(`pfctl could not load rules: ${this.lastError}`);
    }
    const enabled = await this.enabled();
    if (!this.token || !enabled) await this.#takeReference(enabled);
    this.lastRules = rules;
    this.lastError = null;
  }

  async #takeReference(releaseOld) {
    const enable = await pfctl(['-E']);
    const token = `${enable.stdout}\n${enable.stderr}`.match(/Token\s*:\s*(\d+)/)?.[1];
    if (!token) {
      this.lastError = enable.stderr.trim();
      throw new Error(`pfctl could not enable pf: ${this.lastError}`);
    }
    // Take the new reference before dropping the old one, so pf never switches off in between.
    // If pf had been switched off (pfctl -d), old references are gone; leave their numbers alone.
    await this.#releaseSaved({ keep: token, release: releaseOld });
    this.token = token;
    writeFileAtomic(this.tokenFile, `${token} ${(await bootTime()) ?? ''}\n`, path.dirname(this.workDir));
  }

  async #releaseSaved({ keep = null, release = true } = {}) {
    const previous = new Set([this.token]);
    try {
      const [token, boot] = fs.readFileSync(this.tokenFile, 'utf8').trim().split(/\s+/);
      if (boot && boot === (await bootTime())) previous.add(token);
    } catch {}
    if (release) for (const token of previous) if (token && token !== keep) await pfctl(['-X', token]);
    fs.rmSync(this.tokenFile, { force: true });
    this.token = null;
  }

  async enabled() {
    return /Status: Enabled/.test((await pfctl(['-s', 'info'])).stdout);
  }

  async clear() {
    await pfctl(['-a', ANCHOR, '-F', 'all']);
    await this.#releaseSaved({ release: await this.enabled() });
    this.lastRules = null;
  }

  /** True when the anchor still holds our redirect rules and pf is enabled. */
  async healthy() {
    const [nat, info] = await Promise.all([pfctl(['-a', ANCHOR, '-s', 'nat']), pfctl(['-s', 'info'])]);
    return nat.stdout.includes('rdr pass') && /Status: Enabled/.test(info.stdout);
  }

  async status() {
    const [nat, rules, info] = await Promise.all([
      pfctl(['-a', ANCHOR, '-s', 'nat']),
      pfctl(['-a', ANCHOR, '-s', 'rules']),
      pfctl(['-s', 'info']),
    ]);
    return {
      enabled: /Status: Enabled/.test(info.stdout),
      loaded: nat.stdout.includes('rdr pass'),
      rules: `${nat.stdout}${rules.stdout}`.trim(),
      error: this.lastError,
    };
  }
}
