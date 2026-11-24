import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

// A fake HTTP CONNECT proxy whose exit IP follows the session number in the username, like
// residential providers do. Sessions in `dead` fail the lookup.
function fakeProvider({ dead = new Set() } = {}) {
  const server = net.createServer((socket) => {
    let buffer = '';
    let sid = null;
    socket.on('data', (data) => {
      buffer += data;
      if (sid === null && buffer.includes('\r\n\r\n')) {
        const head = buffer.slice(0, buffer.indexOf('\r\n\r\n'));
        buffer = buffer.slice(buffer.indexOf('\r\n\r\n') + 4);
        const auth = Buffer.from(head.match(/Proxy-Authorization: Basic (\S+)/)?.[1] ?? '', 'base64').toString();
        sid = auth.match(/sid-(\d+)/)?.[1] ?? '';
        if (dead.has(sid)) return socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
        socket.write('HTTP/1.1 200 Connection established\r\n\r\n');
      }
      if (sid !== null && buffer.includes('\r\n\r\n')) {
        const ip = `203.0.${Number(sid) % 250}.${Math.floor(Number(sid) / 250) % 250}`;
        const body = JSON.stringify({ ip, country: 'US', city: 'Testville', region: 'Test', org: 'AS64500 Example' });
        socket.end(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
      }
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port })));
}

async function freePort() {
  return new Promise((resolve) => {
    const server = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

test('New proxy gives a device a fresh, checked session and retires the one it made before', async () => {
  const provider = await fakeProvider();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-rotate-'));
  const port = await freePort();
  const child = spawn(process.execPath, ['server.mjs'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: { ...process.env, RELAY_DATA: dir, RELAY_PORT: String(port), RELAY_SING_BOX: '/nonexistent', RELAY_LOOKUP: 'http://lookup.test/json', RELAY_LOCAL_DASHBOARD: '1' },
    stdio: 'ignore',
  });
  const api = async (method, p, body) => {
    const response = await fetch(`http://127.0.0.1:${port}/api${p}`, { method, headers: { 'X-Relay': '1', 'Content-Type': 'application/json' }, body: body && JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  };
  try {
    for (let i = 0; i < 100; i++) {
      try {
        await fetch(`http://127.0.0.1:${port}/healthz`);
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 50));
      }
    }
    const imported = await api('POST', '/proxies/import', { text: `http\t127.0.0.1:${provider.port}:user-country-us-sid-1000-ttl-60:pw\tproxiware` });
    assert.equal(imported.status, 200);
    const original = (await api('GET', '/state')).body.proxies[0];
    assert.equal(original.rotatable, true);
    const { body: added } = await api('POST', '/devices', { name: 'Phone', ip: '192.168.250.77', proxyId: original.id });

    const first = await api('POST', `/devices/${added.device.id}/rotate`);
    assert.equal(first.status, 200, JSON.stringify(first.body));
    assert.notEqual(first.body.device.proxyId, original.id);
    assert.equal(first.body.proxy.lastCheck.ok, true);
    assert.match(first.body.proxy.label, /^sid \d{8}$/);

    const second = await api('POST', `/devices/${added.device.id}/rotate`);
    assert.equal(second.status, 200);
    const state = (await api('GET', '/state')).body;
    // The imported proxy stays; the first fresh session was retired once the phone moved on.
    assert.deepEqual(state.proxies.map((p) => p.id).sort(), [original.id, second.body.proxy.id].sort());
    assert.equal(state.devices[0].proxyId, second.body.proxy.id);
    assert.equal(state.devices[0].mode, 'proxy');

    // Moving the phone back to the imported proxy retires the fresh session too.
    await api('PATCH', `/devices/${added.device.id}`, { proxyId: original.id });
    assert.deepEqual((await api('GET', '/state')).body.proxies.map((p) => p.id), [original.id]);
  } finally {
    child.kill();
    provider.server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('New proxy needs a proxy with a session id', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-rotate-'));
  const port = await freePort();
  const child = spawn(process.execPath, ['server.mjs'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: { ...process.env, RELAY_DATA: dir, RELAY_PORT: String(port), RELAY_SING_BOX: '/nonexistent', RELAY_LOOKUP: 'http://lookup.test/json', RELAY_LOCAL_DASHBOARD: '1' },
    stdio: 'ignore',
  });
  try {
    for (let i = 0; i < 100; i++) {
      try {
        await fetch(`http://127.0.0.1:${port}/healthz`);
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 50));
      }
    }
    const post = (p, body) => fetch(`http://127.0.0.1:${port}/api${p}`, { method: 'POST', headers: { 'X-Relay': '1', 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then((r) => r.json().then((b) => ({ status: r.status, body: b })));
    await post('/proxies/import', { text: 'p.example.com:1080:plainuser:pw' });
    const { body } = await post('/devices', { name: 'Phone', ip: '192.168.250.78' });
    const result = await post(`/devices/${body.device.id}/rotate`);
    assert.equal(result.status, 400);
    assert.match(result.body.error, /sid-/);
  } finally {
    child.kill();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
