import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { checkPassword, createSession, validSession } from '../lib/auth.mjs';

function writePasswordFile(dir, password) {
  const passwordSalt = crypto.randomBytes(16).toString('hex');
  const passwordHash = crypto.scryptSync(password, passwordSalt, 32).toString('hex');
  const file = path.join(dir, 'gateway.json');
  fs.writeFileSync(file, JSON.stringify({ passwordSalt, passwordHash }));
  return file;
}

test('password check reads a salt and scrypt hash from a file', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-auth-'));
  try {
    const file = writePasswordFile(dir, 'correct horse');
    assert.equal(checkPassword('correct horse', file), true);
    assert.equal(checkPassword('wrong', file), false);
    assert.equal(checkPassword('', file), false);
    assert.equal(checkPassword('correct horse', path.join(dir, 'missing.json')), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('sessions are signed and expire', () => {
  const token = createSession('k');
  assert.equal(validSession(token, 'k'), true);
  assert.equal(validSession(token, 'other'), false);
  assert.equal(validSession(`${token}x`, 'k'), false);
  assert.equal(validSession(token, 'k', Date.now() + 31 * 86400 * 1000), false);
  assert.equal(validSession(undefined, 'k'), false);
});

async function freePort() {
  return new Promise((resolve) => {
    const server = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function waitFor(url) {
  for (let i = 0; i < 100; i++) {
    try {
      await fetch(url);
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 50));
    }
  }
  throw new Error(`server did not start: ${url}`);
}

test('server admits the tailnet owner, local requests and signed-in phones only', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-server-'));
  const [port, publicPort] = [await freePort(), await freePort()];
  const passwordFile = writePasswordFile(dir, 'pw-123456');
  const tailnetHost = `mac.example.ts.net:${port}`;
  const origin = `https://mac.example.ts.net:${publicPort}`;
  fs.writeFileSync(path.join(dir, 'access.json'), JSON.stringify({
    tailnet: { host: tailnetHost, allowedLogin: 'owner@example.com' },
    public: { origin, port: publicPort, passwordFile },
  }));
  const child = spawn(process.execPath, ['server.mjs'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: { ...process.env, RELAY_DATA: dir, RELAY_PORT: String(port), RELAY_SING_BOX: '/nonexistent' },
    stdio: 'ignore',
  });
  // fetch() drops custom Host headers, so use node:http.
  const get = (p, headers = {}, listenPort = port, init = {}) =>
    new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port: listenPort, path: p, method: init.method ?? 'GET', headers }, (res) => {
        res.resume();
        res.on('end', () => resolve({ status: res.statusCode, headers: { get: (name) => res.headers[name] && [].concat(res.headers[name]).join(', ') } }));
      });
      req.on('error', reject);
      req.end(init.body);
    });
  try {
    await waitFor(`http://127.0.0.1:${port}/healthz`);
    await waitFor(`http://127.0.0.1:${publicPort}/healthz`);

    // Tailnet listener
    assert.equal((await get('/api/state', { host: tailnetHost })).status, 403);
    assert.equal((await get('/api/state', { host: tailnetHost, 'tailscale-user-login': 'someone@else.com' })).status, 403);
    assert.equal((await get('/api/state', { host: 'evil.example', 'tailscale-user-login': 'owner@example.com' })).status, 403);
    assert.equal((await get('/api/state', { host: tailnetHost, 'tailscale-user-login': 'owner@example.com' })).status, 200);
    assert.equal((await get('/api/state', { host: `localhost:${port}` })).status, 200);
    const crossOrigin = await get('/api/apply', { host: tailnetHost, 'tailscale-user-login': 'owner@example.com', origin: 'https://evil.example', 'x-relay': '1' }, port, { method: 'POST' });
    assert.equal(crossOrigin.status, 403);

    // Public (Funnel) listener
    const publicHost = new URL(origin).host;
    const spoofed = await get('/api/state', { host: publicHost, 'tailscale-user-login': 'owner@example.com' }, publicPort);
    assert.equal(spoofed.status, 401);
    const page = await get('/', { host: publicHost }, publicPort);
    assert.equal(page.status, 303);
    assert.equal(page.headers.get('location'), '/login');
    assert.equal((await get('/api/state', { host: tailnetHost, 'tailscale-user-login': 'owner@example.com' }, publicPort)).status, 403);

    const login = (password, extra = {}) =>
      get('/login', { host: publicHost, origin, 'content-type': 'application/x-www-form-urlencoded', ...extra }, publicPort, {
        method: 'POST',
        body: new URLSearchParams({ username: 'relay', password }).toString(),
      });
    assert.equal((await login('nope')).status, 401);
    assert.equal((await login('pw-123456', { origin: 'https://evil.example' })).status, 403);
    const ok = await login('pw-123456');
    assert.equal(ok.status, 303);
    const cookie = ok.headers.get('set-cookie');
    assert.match(cookie, /^__Host-relay_session=.+; Path=\/; HttpOnly; Secure; SameSite=Lax/);
    const session = cookie.split(';')[0];
    assert.equal((await get('/api/state', { host: publicHost, cookie: session }, publicPort)).status, 200);
    assert.equal((await get('/', { host: publicHost, cookie: session }, publicPort)).status, 200);
  } finally {
    child.kill();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
