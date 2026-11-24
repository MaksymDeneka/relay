import net from 'node:net';

const LOOKUP_HOST = 'ip-api.com';
const LOOKUP_PATH = '/json/?fields=status,message,country,countryCode,regionName,city,isp,query';

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

function readAll(socket, initial) {
  return new Promise((resolve, reject) => {
    const chunks = [initial];
    socket.on('data', (d) => chunks.push(d));
    socket.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    socket.on('close', () => resolve(Buffer.concat(chunks).toString('utf8')));
    socket.on('error', reject);
  });
}

function parseLookup(raw) {
  const body = raw.slice(raw.indexOf('\r\n\r\n') + 4);
  const status = raw.match(/^HTTP\/1\.[01] (\d+)/)?.[1];
  if (status === '407') throw new Error('Proxy rejected the username or password');
  if (status !== '200') throw new Error(`IP lookup failed (HTTP ${status ?? '?'})`);
  const json = JSON.parse(body);
  if (json.status !== 'success') throw new Error(json.message ?? 'IP lookup failed');
  return { ip: json.query, country: json.country, countryCode: json.countryCode, region: json.regionName, city: json.city, isp: json.isp };
}

/** Connect through the proxy and look up the exit IP. Never throws. */
export async function checkProxy(proxy, { timeoutMs = 15000 } = {}) {
  const started = Date.now();
  const socket = net.connect({ host: proxy.host, port: proxy.port });
  socket.setTimeout(timeoutMs, () => socket.destroy(new Error('Timed out')));
  try {
    await new Promise((resolve, reject) => {
      socket.once('connect', resolve);
      socket.once('error', reject);
    });
    let leftover = Buffer.alloc(0);
    let request;
    if (proxy.type === 'http') {
      const auth = proxy.username
        ? `Proxy-Authorization: Basic ${Buffer.from(`${proxy.username}:${proxy.password ?? ''}`).toString('base64')}\r\n`
        : '';
      request = `GET http://${LOOKUP_HOST}${LOOKUP_PATH} HTTP/1.1\r\nHost: ${LOOKUP_HOST}\r\n${auth}Connection: close\r\n\r\n`;
    } else {
      leftover = await socksConnect(socket, proxy, LOOKUP_HOST, 80);
      request = `GET ${LOOKUP_PATH} HTTP/1.1\r\nHost: ${LOOKUP_HOST}\r\nConnection: close\r\n\r\n`;
    }
    const responsePromise = readAll(socket, leftover);
    socket.write(request);
    const result = parseLookup(await responsePromise);
    return { ok: true, ...result, ms: Date.now() - started, at: Date.now() };
  } catch (error) {
    return { ok: false, error: error.message, ms: Date.now() - started, at: Date.now() };
  } finally {
    socket.destroy();
  }
}

/** Exit IP of this Mac's own connection, used for devices in Direct mode. */
export async function checkDirect() {
  const started = Date.now();
  try {
    const response = await fetch(`http://${LOOKUP_HOST}${LOOKUP_PATH}`, { signal: AbortSignal.timeout(10000) });
    const json = await response.json();
    if (json.status !== 'success') throw new Error(json.message ?? 'IP lookup failed');
    return { ok: true, ip: json.query, country: json.country, countryCode: json.countryCode, region: json.regionName, city: json.city, isp: json.isp, ms: Date.now() - started, at: Date.now() };
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
