import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import { Gateway } from '../lib/gateway.mjs';

const ports = { redirect: 17890, dns: 15353, clash: 19090, direct: 17891 };

function fakes({ failSelect = false } = {}) {
  const log = [];
  const singbox = new EventEmitter();
  Object.assign(singbox, {
    running: false,
    config: null,
    writeConfig(config) {
      this.config = config;
    },
    async check() {
      log.push('check');
      return { ok: true };
    },
    async restart() {
      log.push('restart');
      this.running = true;
    },
    async stop() {
      log.push('stop');
      this.running = false;
    },
    async select(tag, target) {
      log.push(`select ${tag} ${target}`);
      if (failSelect) throw new Error('API down');
    },
  });
  const pf = {
    lastRules: null,
    async apply(rules) {
      log.push(rules.includes('rdr') ? 'pf full' : 'pf block-only');
      this.lastRules = rules;
    },
    async healthy() {
      return true;
    },
    async clear() {
      log.push('pf clear');
    },
  };
  const store = {
    data: {
      settings: { clashSecret: 's' },
      proxies: [{ id: 'aaa', type: 'socks5', host: 'p.example', port: 1, username: 'u', password: 'p' }],
      devices: [{ id: 'd1', ip: '192.168.0.201', mode: 'proxy', proxyId: 'aaa' }],
    },
  };
  const gateway = new Gateway({ store, singbox, pf, ports, isRoot: true });
  return { gateway, singbox, pf, store, log };
}

// The gateway holds a caffeinate child while routing; shutdown releases it.
function cleanup(t, gateway) {
  t.after(() => gateway.shutdown());
}

test('a newly listed IP is blocked before sing-box is checked and started', async (t) => {
  const { gateway, log } = fakes();
  cleanup(t, gateway);
  await gateway.apply();
  assert.deepEqual(log, ['pf block-only', 'check', 'restart', 'pf full']);
});

test('a failed route switch blocks, stops sing-box and rebuilds next time', async (t) => {
  const { gateway, singbox, store, log } = fakes();
  cleanup(t, gateway);
  await gateway.apply();
  store.data.devices[0].mode = 'direct';
  singbox.select = async () => {
    throw new Error('API down');
  };
  await assert.rejects(gateway.apply(), /API down/);
  assert.deepEqual(log.slice(-2), ['pf block-only', 'stop']);
  assert.equal(singbox.running, false);
  const before = singbox.config.outbounds.find((o) => o.type === 'selector').tag;
  singbox.select = async () => {};
  await gateway.apply();
  // Rebuilt with fresh selector tags and the saved route as the default.
  const selector = singbox.config.outbounds.find((o) => o.type === 'selector');
  assert.notEqual(selector.tag, before);
  assert.equal(selector.default, 'direct-guarded');
  assert.equal(log.at(-1), 'pf full');
});

test('after a crash, sing-box is rebuilt with fresh selector tags', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 1_000_000 });
  const { gateway, singbox, log } = fakes();
  cleanup(t, gateway);
  await gateway.apply();
  const first = singbox.config.outbounds.find((o) => o.type === 'selector').tag;
  singbox.running = false;
  t.mock.timers.tick(5000);
  singbox.emit('crash', 1000);
  t.mock.timers.tick(1000);
  await gateway.queue;
  await new Promise((resolve) => setImmediate(resolve));
  await gateway.queue;
  const second = singbox.config.outbounds.find((o) => o.type === 'selector').tag;
  assert.notEqual(second, first);
  assert.equal(log.filter((l) => l === 'restart').length, 2);
});
