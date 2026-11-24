import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { renderRules } from '../lib/pf.mjs';
import { buildConfig, DIRECT_TAG, deviceTarget, structureHash } from '../lib/singbox.mjs';

const ports = { redirect: 17890, dns: 15353, clash: 19090, direct: 17891 };
const proxies = [
  { id: 'aaa', type: 'socks5', host: 'p.example', port: 1337, username: 'u', password: 'p' },
  { id: 'bbb', type: 'http', host: 'h.example', port: 8080, username: '', password: '' },
];
const devices = [
  { id: 'd1', ip: '192.168.0.201', mode: 'proxy', proxyId: 'aaa' },
  { id: 'd2', ip: '192.168.0.202', mode: 'direct', proxyId: null },
  { id: 'd3', ip: '192.168.0.203', mode: 'proxy', proxyId: 'gone' },
];

test('device targets fall back to block', () => {
  assert.equal(deviceTarget(devices[0], proxies), 'p-aaa');
  assert.equal(deviceTarget(devices[1], proxies), DIRECT_TAG);
  assert.equal(deviceTarget(devices[2], proxies), 'block');
});

test('config routes each device by source IP through its selector', () => {
  const config = buildConfig({ devices, proxies, ports, clashSecret: 's' });
  const rules = config.route.rules.filter((r) => r.source_ip_cidr);
  assert.deepEqual(rules.map((r) => [r.source_ip_cidr[0], r.outbound]), [
    ['192.168.0.201/32', 'dev-d1'],
    ['192.168.0.202/32', 'dev-d2'],
    ['192.168.0.203/32', 'dev-d3'],
  ]);
  // Devices get only A (fake IP) answers; other query types are refused, not sent to the Mac's resolver.
  assert.deepEqual(config.dns.rules.at(-1), { inbound: ['dns-udp', 'dns-tcp'], action: 'predefined', rcode: 'REFUSED' });
  assert.equal(config.route.final, 'block');
  const http = config.outbounds.find((o) => o.tag === 'p-bbb');
  assert.equal(http.type, 'http');
  assert.equal(http.username, undefined);
});

test('Direct goes through the guarded loopback, never a plain direct outbound', () => {
  const config = buildConfig({ devices, proxies, ports, clashSecret: 's' });
  const selectors = config.outbounds.filter((o) => o.type === 'selector');
  assert.ok(selectors.every((o) => o.outbounds.includes(DIRECT_TAG) && !o.outbounds.includes('direct')));
  const hop = config.outbounds.find((o) => o.tag === DIRECT_TAG);
  const inbound = config.inbounds.find((i) => i.tag === 'direct-in');
  assert.deepEqual([hop.server, hop.server_port, inbound.listen, inbound.listen_port], ['127.0.0.1', 17891, '127.0.0.1', 17891]);
  assert.deepEqual(inbound.users, [{ username: hop.username, password: hop.password }]);
  // Resolve on the Mac, refuse loopback, tailnet and fake IPs, then dial out.
  const guard = config.route.rules.filter((r) => r.inbound?.includes('direct-in') && !r.network);
  assert.deepEqual(guard.map((r) => r.action ?? r.outbound), ['resolve', 'reject', 'direct']);
  assert.equal(guard[0].server, 'local');
  assert.ok(guard[1].ip_cidr.includes('127.0.0.0/8') && guard[1].ip_cidr.includes('100.64.0.0/10') && guard[1].ip_cidr.includes('198.18.0.0/15'));
  const firstDevice = config.route.rules.findIndex((r) => r.source_ip_cidr);
  assert.ok(config.route.rules.indexOf(guard[2]) < firstDevice);
});

test('the Direct hop never carries UDP, not even before the dashboard exception', () => {
  const config = buildConfig({ devices, proxies, ports, clashSecret: 's', dashboards: { domains: ['mac.example.ts.net'], ports: [10000] } });
  const udp = config.route.rules.findIndex((r) => r.inbound?.includes('direct-in') && r.network?.includes('udp'));
  assert.equal(config.route.rules[udp].action, 'reject');
  assert.ok(udp < config.route.rules.findIndex((r) => r.domain));
});

test('selector tags carry the restart epoch, so cached choices from an earlier run never apply', () => {
  const config = buildConfig({ devices, proxies, ports, clashSecret: 's', epoch: 'k1' });
  const tags = config.outbounds.filter((o) => o.type === 'selector').map((o) => o.tag);
  assert.deepEqual(tags, ['dev-d1.k1', 'dev-d2.k1', 'dev-d3.k1']);
  assert.deepEqual(config.route.rules.filter((r) => r.source_ip_cidr).map((r) => r.outbound), tags);
  assert.deepEqual(config.outbounds.filter((o) => o.type === 'selector').map((o) => o.default), ['p-aaa', 'direct-guarded', 'block']);
});

test('own dashboard bypasses the proxy only on its ports, matched before sniffing', () => {
  const config = buildConfig({ devices, proxies, ports, clashSecret: 's', dashboards: { domains: ['mac.example.ts.net'], ports: [10000] } });
  const index = config.route.rules.findIndex((r) => r.domain);
  assert.deepEqual(config.route.rules[index], { domain: ['mac.example.ts.net'], port: [10000], outbound: 'direct' });
  assert.ok(index < config.route.rules.findIndex((r) => r.action === 'sniff'));
});

test('switching proxy, Direct or Block does not change the structure hash', () => {
  const hash = (list) => structureHash(buildConfig({ devices: list, proxies, ports, clashSecret: 's' }));
  const a = hash(devices);
  assert.equal(a, hash(devices.map((d) => (d.id === 'd1' ? { ...d, proxyId: 'bbb' } : d))));
  assert.equal(a, hash(devices.map((d) => (d.id === 'd1' ? { ...d, mode: 'direct' } : d))));
  assert.equal(a, hash(devices.map((d) => (d.id === 'd2' ? { ...d, mode: 'block' } : d))));
  assert.notEqual(a, hash(devices.slice(0, 2)));
});

test('sing-box accepts the generated config', { skip: !fs.existsSync('/opt/homebrew/bin/sing-box') }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-test-'));
  try {
    const file = path.join(dir, 'c.json');
    fs.writeFileSync(file, JSON.stringify(buildConfig({ devices, proxies, ports, clashSecret: 's', dashboards: { domains: ['mac.example.ts.net'], ports: [10000] } })));
    execFileSync('/opt/homebrew/bin/sing-box', ['check', '-c', file, '-D', dir]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('pf rules only touch listed devices, on every interface', () => {
  const rules = renderRules({ deviceIps: ['192.168.0.201'], ports });
  assert.match(rules, /table <relay_devices> const \{ 192\.168\.0\.201 \}/);
  assert.match(rules, /^rdr pass inet proto tcp from <relay_devices> to ! <relay_local> -> 127\.0\.0\.1 port 17890$/m);
  assert.match(rules, /port 53 -> 127\.0\.0\.1 port 15353/);
  assert.match(rules, /^block drop in quick inet from <relay_devices> to ! <relay_local>$/m);
  assert.match(rules, /^block drop in quick inet from <relay_devices> to \{ 127\.0\.0\.0\/8 100\.64\.0\.0\/10 \}$/m);
  assert.doesNotMatch(rules, / on /);
});

test('block-only rules keep devices offline while the service is stopped', () => {
  const rules = renderRules({ deviceIps: ['192.168.0.201'], ports, blockOnly: true });
  assert.doesNotMatch(rules, /rdr/);
  assert.match(rules, /^block drop in quick inet from <relay_devices> to ! <relay_local>$/m);
  // Including DNS to a resolver on the LAN or this Mac.
  assert.match(rules, /^block drop in quick inet proto \{ tcp udp \} from <relay_devices> to any port 53$/m);
});
