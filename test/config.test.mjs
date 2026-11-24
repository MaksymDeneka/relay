import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { renderRules } from '../lib/pf.mjs';
import { buildConfig, deviceTarget, structureHash } from '../lib/singbox.mjs';

const ports = { redirect: 17890, dns: 15353, clash: 19090 };
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
  assert.equal(deviceTarget(devices[1], proxies), 'block'); // direct mode is routed by rules
  assert.equal(deviceTarget(devices[2], proxies), 'block');
});

test('config routes each device by source IP through its selector', () => {
  const config = buildConfig({ devices, proxies, ports, clashSecret: 's' });
  const rules = config.route.rules.filter((r) => r.source_ip_cidr);
  assert.deepEqual(rules.map((r) => [r.source_ip_cidr[0], r.outbound ?? r.action]), [
    ['192.168.0.201/32', 'dev-d1'],
    ['192.168.0.202/32', 'resolve'],
    ['192.168.0.202/32', 'reject'],
    ['192.168.0.202/32', 'direct'],
    ['192.168.0.203/32', 'dev-d3'],
  ]);
  // Direct mode can't reach the Mac's loopback or tailnet services through a resolved name.
  const reject = rules.find((r) => r.action === 'reject');
  assert.ok(reject.ip_cidr.includes('127.0.0.0/8') && reject.ip_cidr.includes('100.64.0.0/10'));
  assert.equal(rules.find((r) => r.action === 'resolve').server, 'local');
  // Selectors never offer an unguarded direct route.
  assert.ok(config.outbounds.filter((o) => o.type === 'selector').every((o) => !o.outbounds.includes('direct')));
  // Devices get only A (fake IP) answers; other query types are refused, not sent to the Mac's resolver.
  assert.deepEqual(config.dns.rules.at(-1), { inbound: ['dns-udp', 'dns-tcp'], action: 'predefined', rcode: 'REFUSED' });
  assert.equal(config.route.final, 'block');
  const http = config.outbounds.find((o) => o.tag === 'p-bbb');
  assert.equal(http.type, 'http');
  assert.equal(http.username, undefined);
});

test('own dashboard bypasses the proxy only on its ports, matched before sniffing', () => {
  const config = buildConfig({ devices, proxies, ports, clashSecret: 's', dashboards: { domains: ['mac.example.ts.net'], ports: [10000] } });
  const index = config.route.rules.findIndex((r) => r.domain);
  assert.deepEqual(config.route.rules[index], { domain: ['mac.example.ts.net'], port: [10000], outbound: 'direct' });
  assert.ok(index < config.route.rules.findIndex((r) => r.action === 'sniff'));
});

test('switching a proxy does not change the structure hash', () => {
  const a = structureHash(buildConfig({ devices, proxies, ports, clashSecret: 's' }));
  const switched = devices.map((d) => (d.id === 'd1' ? { ...d, proxyId: 'bbb' } : d));
  const b = structureHash(buildConfig({ devices: switched, proxies, ports, clashSecret: 's' }));
  assert.equal(a, b);
  const added = structureHash(buildConfig({ devices: devices.slice(0, 2), proxies, ports, clashSecret: 's' }));
  assert.notEqual(a, added);
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

test('pf rules only touch listed devices', () => {
  const rules = renderRules({ interfaces: ['en0', 'en7'], deviceIps: ['192.168.0.201'], ports });
  assert.match(rules, /table <relay_devices> const \{ 192\.168\.0\.201 \}/);
  assert.match(rules, /rdr pass on \{ en0 en7 \} inet proto tcp from <relay_devices> to ! <relay_local> -> 127\.0\.0\.1 port 17890/);
  assert.match(rules, /port 53 -> 127\.0\.0\.1 port 15353/);
  assert.match(rules, /block drop in quick on \{ en0 en7 \} inet from <relay_devices> to ! <relay_local>/);
  assert.match(rules, /block drop in quick on \{ en0 en7 \} inet from <relay_devices> to \{ 127\.0\.0\.0\/8 100\.64\.0\.0\/10 \}/);
});

test('block-only rules keep devices offline while the service is stopped', () => {
  const rules = renderRules({ interfaces: ['en0'], deviceIps: ['192.168.0.201'], ports, blockOnly: true });
  assert.doesNotMatch(rules, /rdr/);
  assert.match(rules, /block drop in quick on \{ en0 \} inet from <relay_devices> to ! <relay_local>/);
});
