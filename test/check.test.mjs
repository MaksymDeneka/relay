import assert from 'node:assert/strict';
import net from 'node:net';
import test from 'node:test';
import { checkProxy, LOOKUP } from '../lib/check.mjs';

// The fake proxy answers the lookup itself, without TLS.
const lookup = { host: 'lookup.test', port: 443, path: '/json', tls: false };

// A fake HTTP proxy that only supports CONNECT, then answers the lookup itself.
function fakeConnectProxy({ status = 200 } = {}) {
  const seen = [];
  const server = net.createServer((socket) => {
    let buffer = '';
    let tunnel = false;
    socket.on('data', (data) => {
      buffer += data;
      if (!tunnel && buffer.includes('\r\n\r\n')) {
        const head = buffer.slice(0, buffer.indexOf('\r\n\r\n'));
        seen.push(head.split('\r\n')[0]);
        buffer = buffer.slice(buffer.indexOf('\r\n\r\n') + 4);
        if (!head.startsWith('CONNECT ') || status !== 200) {
          socket.end(`HTTP/1.1 ${status === 200 ? 405 : status} No\r\n\r\n`);
          return;
        }
        tunnel = true;
        socket.write('HTTP/1.1 200 Connection established\r\n\r\n');
      }
      if (tunnel && buffer.includes('\r\n\r\n')) {
        const body = JSON.stringify({ ip: '203.0.113.9', country: 'DE', city: 'Testville', region: 'Test', org: 'AS64500 Example Net' });
        socket.end(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
      }
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, seen })));
}

test('HTTP proxies are checked through a CONNECT tunnel, like sing-box uses them', async () => {
  const { server, port, seen } = await fakeConnectProxy();
  try {
    const result = await checkProxy({ type: 'http', host: '127.0.0.1', port, username: 'u', password: 'p' }, { timeoutMs: 5000, lookup });
    assert.equal(result.ok, true, result.error);
    assert.deepEqual([result.ip, result.country, result.countryCode, result.isp], ['203.0.113.9', 'Germany', 'DE', 'Example Net']);
    assert.match(seen[0], /^CONNECT lookup\.test:443 HTTP\/1\.1$/);
  } finally {
    server.close();
  }
});

test('a proxy that rejects credentials is reported, not treated as working', async () => {
  const { server, port } = await fakeConnectProxy({ status: 407 });
  try {
    const result = await checkProxy({ type: 'http', host: '127.0.0.1', port, username: 'u', password: 'bad' }, { timeoutMs: 5000, lookup });
    assert.equal(result.ok, false);
    assert.match(result.error, /username or password/);
  } finally {
    server.close();
  }
});

test('the real lookup goes over HTTPS on port 443, which proxies limited to web ports allow', () => {
  assert.deepEqual([LOOKUP.port, LOOKUP.tls], [443, true]);
});
