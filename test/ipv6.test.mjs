import assert from 'node:assert/strict';
import test from 'node:test';
import { ipv6Exposure, ipv6Prefix, isGlobalIPv6, parseArp, parseNdp, parsePrefixes } from '../lib/ipv6.mjs';

const arp = parseArp(`? (192.168.0.1) at 50:f:f5:d9:c3:50 on en7 ifscope [ethernet]
? (192.168.0.201) at f2:49:53:91:b4:c2 on en7 ifscope [ethernet]
? (192.168.0.202) at (incomplete) on en7 ifscope [ethernet]`);
const header = 'Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs\n';
const devices = [
  { id: 'a', name: 'iPhone 1', ip: '192.168.0.201' },
  { id: 'b', name: 'iPhone 2', ip: '192.168.0.202' },
];
const lan = { family: 'IPv4', address: '192.168.0.101', netmask: '255.255.255.0' };

test('only global unicast IPv6 counts, and prefixes are masked properly', () => {
  assert.equal(isGlobalIPv6('2a02:2378:1:2::5'), true);
  assert.equal(isGlobalIPv6('fd07:2947:1d2a:476f::1'), false);
  assert.equal(isGlobalIPv6('fe80::1'), false);
  assert.deepEqual(arp.get('192.168.0.1'), { mac: '50:0f:f5:d9:c3:50', iface: 'en7' });
  assert.equal(arp.has('192.168.0.202'), false);
  assert.equal(ipv6Prefix('2001:4860::1234', 64), '2001:4860::/64');
  assert.equal(ipv6Prefix('2a02:2378:1:2:c10:1047:236e:8a65', 64), '2a02:2378:1:2::/64');
  assert.equal(ipv6Prefix('2a02:2378:1:2ff::', 56), '2a02:2378:1:200::/56');
});

test('a local-only network (ULA from a Thread border router) is not flagged', () => {
  const ndp = parseNdp(`${header}fd07:2947:1d2a:476f:1888:f2e:e222:f4ee  f2:49:53:91:b4:c2    en7 22h3m52s  S
fe80::1032:2e93:1629:3fb7%en7           8c:26:aa:ed:b1:25    en7 23h44m44s S  R`);
  const interfaces = { en7: [lan, { family: 'IPv6', address: 'fd07:2947:1d2a:476f:140a:4f1a:72f7:b497', netmask: 'ffff:ffff:ffff:ffff::' }], utun4: [{ family: 'IPv6', address: '2001:db8::1' }] };
  const prefixes = parsePrefixes('fd07:2947:1d2a:476f::/64 if=en7\nflags=LAO vltime=1800\n  advertised by\n    fe80::1032:2e93:1629:3fb7%en7');
  assert.deepEqual(ipv6Exposure({ interfaces, arp, ndp, prefixes, devices }), { available: true, exposed: false, prefixes: [], devices: [] });
});

test('a public prefix and a listed phone with a public address are flagged', () => {
  const ndp = parseNdp(`${header}2a02:2378:1:2:1888:f2e:e222:f4ee  f2:49:53:91:b4:c2    en7 22h3m52s  S
2a02:2378:1:2:aaaa::1  de:ad:be:ef:0:1    en7 22h3m52s  S`);
  const interfaces = { en7: [lan, { family: 'IPv6', address: '2a02:2378:1:2:c10:1047:236e:8a65', netmask: 'ffff:ffff:ffff:ffff::' }] };
  const result = ipv6Exposure({ interfaces, arp, ndp, devices });
  assert.equal(result.exposed, true);
  assert.deepEqual(result.prefixes, ['2a02:2378:1:2::/64']);
  assert.deepEqual(result.devices, [{ id: 'a', name: 'iPhone 1', addresses: ['2a02:2378:1:2:1888:f2e:e222:f4ee'] }]);
});

test('a prefix the router advertises counts even when this Mac has no public address', () => {
  const interfaces = { en7: [lan] };
  const prefixes = parsePrefixes('2a02:2378:1:2::/64 if=en7\nflags=LAO vltime=86400\n  advertised by\n    fe80::1%en7');
  assert.deepEqual(ipv6Exposure({ interfaces, arp, ndp: [], prefixes, devices }).prefixes, ['2a02:2378:1:2::/64']);
});

test('public IPv6 on an interface that serves no listed device is ignored', () => {
  const interfaces = { en7: [lan], en0: [{ family: 'IPv4', address: '10.0.0.5', netmask: '255.255.255.0' }, { family: 'IPv6', address: '2a02:2378:1:2::9', netmask: 'ffff:ffff:ffff:ffff::' }] };
  const prefixes = parsePrefixes('2a02:2378:1:2::/64 if=en0');
  assert.equal(ipv6Exposure({ interfaces, arp, ndp: [], prefixes, devices }).exposed, false);
});
