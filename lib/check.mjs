import net from 'node:net';
import tls from 'node:tls';

// HTTPS on port 443: many proxies only tunnel to TLS ports, and devices mostly use HTTPS anyway.
export const LOOKUP = { host: 'ipinfo.io', port: 443, path: '/json', tls: true };
const regionNames = new Intl.DisplayNames(['en'], { type: 'region' });

function readExactly(socket, size, state) {
  return new Promise((resolve, reject) => {
    const tryRead = () => {
      if (state.buffer.length >= size) {
        const chunk = state.buffer.subarray(0, size);
        state.buffer = state.buffer.subarray(size);
        cleanup();
        resolve(chunk);
      }
    };
    const onData = (data) => {
      state.buffer = Buffer.concat([state.buffer, data]);
      tryRead();
    };
    const onEnd = () => {
      cleanup();
      reject(new Error('Proxy closed the connection'));
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const cleanup = () => {
      socket.off('data', onData);
      socket.off('end', onEnd);
      socket.off('error', onError);
    };
    socket.on('data', onData);
    socket.on('end', onEnd);
    socket.on('error', onError);
    tryRead();
  });
}

const SOCKS_ERRORS = {
  1: 'general failure',
  2: 'connection not allowed',
  3: 'network unreachable',
  4: 'host unreachable',
  5: 'connection refused',
  6: 'TTL expired',
  7: 'command not supported',
  8: 'address type not supported',
};

async function socksConnect(socket, proxy, host, port) {
  const state = { buffer: Buffer.alloc(0) };
  const useAuth = Boolean(proxy.username);
  socket.write(Buffer.from(useAuth ? [5, 2, 0, 2] : [5, 1, 0]));
  const [version, method] = await readExactly(socket, 2, state);
  if (version !== 5) throw new Error('Not a SOCKS5 proxy');
  if (method === 0xff) throw new Error('Proxy rejected the authentication methods');
  if (method === 2) {
    const user = Buffer.from(proxy.username ?? '');
    const pass = Buffer.from(proxy.password ?? '');
    socket.write(Buffer.concat([Buffer.from([1, user.length]), user, Buffer.from([pass.length]), pass]));
    const [, status] = await readExactly(socket, 2, state);
    if (status !== 0) throw new Error('Proxy rejected the username or password');
  }
  const hostBuf = Buffer.from(host);
  socket.write(
    Buffer.concat([Buffer.from([5, 1, 0, 3, hostBuf.length]), hostBuf, Buffer.from([port >> 8, port & 0xff])]),
  );
  const head = await readExactly(socket, 4, state);
  if (head[1] !== 0) throw new Error(`Proxy could not connect: ${SOCKS_ERRORS[head[1]] ?? `code ${head[1]}`}`);
  const addrLen = head[3] === 1 ? 4 : head[3] === 4 ? 16 : (await readExactly(socket, 1, state))[0];
  await readExactly(socket, addrLen + 2, state);
  return state.buffer;
}

function readUntil(socket, marker, state, max = 16384) {
  return new Promise((resolve, reject) => {
    const check = () => {
      const index = state.buffer.indexOf(marker);
      if (index !== -1) {
        cleanup();
        resolve(index + marker.length);
      } else if (state.buffer.length > max) {
        cleanup();
        reject(new Error('Proxy sent an oversized reply'));
      }
    };
    const onData = (data) => {
      state.buffer = Buffer.concat([state.buffer, data]);
      check();
    };
    const onEnd = () => {
      cleanup();
      reject(new Error('Proxy closed the connection'));
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const cleanup = () => {
      socket.off('data', onData);
      socket.off('end', onEnd);
      socket.off('error', onError);
    };
    socket.on('data', onData);
    socket.on('end', onEnd);
    socket.on('error', onError);
    check();
  });
}

async function httpConnect(socket, proxy, host, port) {
  const auth = proxy.username
    ? `Proxy-Authorization: Basic ${Buffer.from(`${proxy.username}:${proxy.password ?? ''}`).toString('base64')}\r\n`
    : '';
  socket.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n${auth}\r\n`);
  const state = { buffer: Buffer.alloc(0) };
  const end = await readUntil(socket, '\r\n\r\n', state);
  const status = state.buffer.subarray(0, end).toString().match(/^HTTP\/1\.[01] (\d{3})/)?.[1];
  if (status === '407') throw new Error('Proxy rejected the username or password');
  if (status !== '200') throw new Error(`Proxy could not connect (HTTP ${status ?? '?'})`);
  return state.buffer.subarray(end);
}

function readAll(socket, initial) {
  return new Promise((resolve, reject) => {
    const chunks = [initial];
    socket.on('data', (d) => chunks.push(d));
    socket.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    socket.on('close', () => resolve(Buffer.concat(chunks).toString('utf8')));
    socket.on('error', reject);
  });
}

function parseBody(json) {
  if (!json?.ip || json.bogon) throw new Error(json?.error?.message ?? 'IP lookup failed');
  let country = json.country;
  try {
    country = regionNames.of(json.country);
  } catch {}
  return { ip: json.ip, country, countryCode: json.country, region: json.region, city: json.city, isp: json.org?.replace(/^AS\d+\s+/, '') };
}

function parseLookup(raw) {
  const body = raw.slice(raw.indexOf('\r\n\r\n') + 4);
  const status = raw.match(/^HTTP\/1\.[01] (\d+)/)?.[1];
  if (status === '407') throw new Error('Proxy rejected the username or password');
  if (status !== '200') throw new Error(`IP lookup failed (HTTP ${status ?? '?'})`);
  return parseBody(JSON.parse(body));
}

/** Connect through the proxy and look up the exit IP. Never throws. */
export async function checkProxy(proxy, { timeoutMs = 15000, lookup = LOOKUP } = {}) {
  const started = Date.now();
  const raw = net.connect({ host: proxy.host, port: proxy.port });
  let socket = raw;
  const deadline = setTimeout(() => socket.destroy(new Error('Timed out')), timeoutMs);
  try {
    await new Promise((resolve, reject) => {
      socket.once('connect', resolve);
      socket.once('error', reject);
    });
    // Tunnel the same way sing-box does: SOCKS5 CONNECT or HTTP CONNECT.
    const tunnel = proxy.type === 'http' ? httpConnect : socksConnect;
    const leftover = await tunnel(socket, proxy, lookup.host, lookup.port);
    if (lookup.tls) {
      if (leftover.length) throw new Error('Proxy sent data before the tunnel was ready');
      socket = tls.connect({ socket: raw, servername: lookup.host });
      await new Promise((resolve, reject) => {
        socket.once('secureConnect', resolve);
        socket.once('error', reject);
      });
    }
    const request = `GET ${lookup.path} HTTP/1.1\r\nHost: ${lookup.host}\r\nAccept: application/json\r\nUser-Agent: relay\r\nConnection: close\r\n\r\n`;
    const responsePromise = readAll(socket, lookup.tls ? Buffer.alloc(0) : leftover);
    socket.write(request);
    const result = parseLookup(await responsePromise);
    return { ok: true, ...result, ms: Date.now() - started, at: Date.now() };
  } catch (error) {
    return { ok: false, error: error.message, ms: Date.now() - started, at: Date.now() };
  } finally {
    clearTimeout(deadline);
    socket.destroy();
    raw.destroy();
  }
}

/** Exit IP of this Mac's own connection, used for devices in Direct mode. */
export async function checkDirect() {
  const started = Date.now();
  try {
    const response = await fetch(`https://${LOOKUP.host}${LOOKUP.path}`, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(10000) });
    if (!response.ok) throw new Error(`IP lookup failed (HTTP ${response.status})`);
    return { ok: true, ...parseBody(await response.json()), ms: Date.now() - started, at: Date.now() };
  } catch (error) {
    return { ok: false, error: error.message, ms: Date.now() - started, at: Date.now() };
  }
}

export async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index], index);
    }
  });
  await Promise.all(workers);
  return results;
}
