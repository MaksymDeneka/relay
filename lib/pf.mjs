import { execFile } from 'node:child_process';
import path from 'node:path';
import { promisify } from 'node:util';
import { writeFileAtomic } from './store.mjs';

const execFileAsync = promisify(execFile);
const PFCTL = '/sbin/pfctl';
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
export function renderRules({ interfaces, deviceIps, ports, blockOnly = false }) {
  const ifs = `{ ${interfaces.join(' ')} }`;
  return [
    `table <relay_devices> const { ${deviceIps.join(' ')} }`,
    `table <relay_local> const { ${LOCAL_RANGES.join(' ')} }`,
    // blockOnly: kept while the service is stopped, so devices that still use this Mac as their
    // router get no internet rather than being forwarded around the proxy.
    ...(blockOnly
      ? []
      : [
          `rdr pass on ${ifs} inet proto { tcp udp } from <relay_devices> to any port 53 -> 127.0.0.1 port ${ports.dns}`,
          `rdr pass on ${ifs} inet proto tcp from <relay_devices> to ! <relay_local> -> 127.0.0.1 port ${ports.redirect}`,
        ]),
    `block drop in quick on ${ifs} inet from <relay_devices> to { 127.0.0.0/8 100.64.0.0/10 }`,
    `block drop in quick on ${ifs} inet from <relay_devices> to ! <relay_local>`,
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

export class PacketFilter {
  constructor({ workDir }) {
    this.workDir = workDir;
    this.rulesFile = path.join(workDir, 'pf-relay.conf');
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
    if (this.token && !(await this.enabled())) this.token = null; // pf was disabled behind our back
    if (!this.token) {
      const enable = await pfctl(['-E']);
      const token = `${enable.stdout}\n${enable.stderr}`.match(/Token\s*:\s*(\d+)/)?.[1];
      if (!token) {
        this.lastError = enable.stderr.trim();
        throw new Error(`pfctl could not enable pf: ${this.lastError}`);
      }
      this.token = token;
    }
    this.lastRules = rules;
    this.lastError = null;
  }

  async enabled() {
    return /Status: Enabled/.test((await pfctl(['-s', 'info'])).stdout);
  }

  async clear() {
    await pfctl(['-a', ANCHOR, '-F', 'all']);
    if (this.token) {
      await pfctl(['-X', this.token]);
      this.token = null;
    }
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
