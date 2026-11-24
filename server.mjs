import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkPassword, clearCookie, LoginLimiter, loginPage, readSession, sessionCookie, validSession } from './lib/auth.mjs';
import { checkDirect, checkProxy, mapLimit } from './lib/check.mjs';
import { Gateway } from './lib/gateway.mjs';
import { readIPv6Exposure } from './lib/ipv6.mjs';
import { isPrivateIPv4, isValidIPv4, lanInterfaces, networkSummary } from './lib/network.mjs';
import { PacketFilter } from './lib/pf.mjs';
import { canRotate, parseProxyList, withNewSession } from './lib/proxies.mjs';
import { SingBox } from './lib/singbox.mjs';
import { Store } from './lib/store.mjs';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(ROOT, 'public');
const env = process.env;
const DATA_DIR = path.resolve(env.RELAY_DATA ?? path.join(ROOT, 'data'));
const PORT = Number(env.RELAY_PORT ?? 8787);
const SING_BOX = env.RELAY_SING_BOX ?? '/opt/homebrew/bin/sing-box';
const ports = {
  redirect: Number(env.RELAY_REDIRECT_PORT ?? 17890),
  dns: Number(env.RELAY_DNS_PORT ?? 15353),
  clash: Number(env.RELAY_API_PORT ?? 19090),
  direct: Number(env.RELAY_DIRECT_PORT ?? 17891),
};
const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;

const store = new Store(DATA_DIR);
store.load();

/**
 * Who may open the dashboard. Both listeners bind to loopback only; Tailscale Serve and
 * Funnel are the way in. data/access.json:
 *   tailnet: { host, allowedLogin }    Serve, owner identified by Tailscale (the Mac)
 *   public:  { origin, port, passwordFile, username? }   Funnel, password + signed cookie (phones)
 */
function loadAccess() {
  let access;
  try {
    access = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'access.json'), 'utf8'));
  } catch (error) {
    // No file: a fresh install, reachable on localhost only. Any other failure locks the
    // dashboard rather than falling back to unauthenticated localhost behind Serve.
    if (error.code === 'ENOENT') return {};
    return { invalid: `data/access.json is unreadable: ${error.message}` };
  }
  const problem = accessProblem(access);
  return problem ? { invalid: `data/access.json: ${problem}` } : access;
}

function accessProblem(access) {
  const text = (value) => typeof value === 'string' && value.trim() !== '';
  const port = (value) => Number.isInteger(value) && value > 0 && value < 65536;
  if (!access || typeof access !== 'object' || Array.isArray(access)) return 'expected an object.';
  // Once the file exists, the owner check is required: a missing or misspelled tailnet block
  // must not leave the localhost fallback open behind Tailscale Serve.
  if (!(text(access.tailnet?.host) && text(access.tailnet?.allowedLogin))) {
    return 'tailnet needs both host and allowedLogin.';
  }
  if (access.public !== undefined) {
    let origin = null;
    try {
      origin = new URL(access.public?.origin);
    } catch {}
    if (origin?.protocol !== 'https:' || !port(access.public.port) || !text(access.public.passwordFile)) {
      return 'public needs an https origin, a port and a passwordFile.';
    }
  }
  if (access.directPorts !== undefined && !(Array.isArray(access.directPorts) && access.directPorts.every(port))) {
    return 'directPorts must be a list of port numbers.';
  }
  return null;
}
const access = loadAccess();
if (access.invalid) console.error(`${access.invalid} The dashboard refuses all requests until it is fixed.`);
const LOCAL_HOSTS = new Set([`localhost:${PORT}`, `127.0.0.1:${PORT}`]);
// Unauthenticated localhost access is opt-in, for a Mac without Tailscale or for development.
const LOCAL_DASHBOARD = env.RELAY_LOCAL_DASHBOARD === '1';
const FORWARD_HEADERS = ['forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'tailscale-user-login', 'tailscale-user-name'];
const forwarded = (req) => FORWARD_HEADERS.some((name) => req.headers[name] !== undefined);
const runtimeDir = path.join(DATA_DIR, 'runtime');
const singbox = new SingBox({ binary: SING_BOX, workDir: runtimeDir, ports, clashSecret: store.data.settings.clashSecret });
const pf = new PacketFilter({ workDir: runtimeDir });
// The phone sign-in port on this Mac's own Tailscale name (plus access.directPorts, e.g. another
// password-protected dashboard) goes direct, not via a proxy.
const publicUrl = access.public?.origin ? new URL(access.public.origin) : null;
const dashboards = publicUrl
  ? { domains: [publicUrl.hostname], ports: [...new Set([Number(publicUrl.port || 443), ...(access.directPorts ?? [])])] }
  : null;
const gateway = new Gateway({ store, singbox, pf, ports, isRoot, dashboards });
const limiter = new LoginLimiter();
const checking = new Set();
let ipv6 = { key: null, value: null };
async function ipv6Status() {
  // arp and ndp are cheap, but the dashboard polls; refresh at most every 30 seconds, and at
  // once when the device list changes.
  const key = JSON.stringify(store.data.devices.map((d) => [d.id, d.ip, d.name]));
  if (ipv6.key !== key || !ipv6.value || Date.now() - ipv6.value.at > 30000) ipv6 = { key, value: await readIPv6Exposure(store.data.devices) };
  return ipv6.value;
}
const rotating = new Set();

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function dashboardUrls() {
  return {
    mac: access.tailnet?.host ? `https://${access.tailnet.host}` : `http://localhost:${PORT}`,
    phones: access.public?.origin ?? null,
  };
}

function newId() {
  return crypto.randomBytes(5).toString('hex');
}

function publicProxy(proxy, devices) {
  const { password, ...rest } = proxy;
  return {
    ...rest,
    hasPassword: Boolean(password),
    rotatable: canRotate(proxy),
    usedBy: devices.filter((d) => d.mode === 'proxy' && d.proxyId === proxy.id).map((d) => d.id),
    checking: checking.has(proxy.id),
  };
}

async function statePayload() {
  const { devices, proxies } = store.data;
  const [network, pfStatus, ipv6Exposure] = await Promise.all([networkSummary(), isRoot ? pf.status() : null, ipv6Status()]);
  return {
    devices,
    proxies: proxies.map((p) => publicProxy(p, devices)),
    network,
    ipv6: ipv6Exposure,
    urls: dashboardUrls(),
    status: {
      root: isRoot,
      singbox: { running: singbox.running, startedAt: singbox.startedAt, lastExit: singbox.lastExit },
      pf: pfStatus ? { enabled: pfStatus.enabled, loaded: pfStatus.loaded } : null,
      error: gateway.lastError,
      appliedAt: gateway.lastAppliedAt,
      ports,
    },
  };
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 4 * 1024 * 1024) throw new HttpError(413, 'Request too large');
    chunks.push(chunk);
  }
  if (!size) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'Invalid JSON');
  }
}

function send(res, status, body, headers = {}) {
  const data = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(data);
}

const STATIC_TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.webmanifest': 'application/manifest+json' };

function serveStatic(req, res, pathname) {
  const file = pathname === '/' ? 'index.html' : pathname.slice(1);
  const full = path.join(PUBLIC, path.normalize(file));
  if (!full.startsWith(PUBLIC + path.sep) || !fs.existsSync(full) || !fs.statSync(full).isFile()) {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    return res.end('Not found');
  }
  res.writeHead(200, {
    'Content-Type': STATIC_TYPES[path.extname(full)] ?? 'application/octet-stream',
    'Cache-Control': 'no-cache',
    'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  });
  fs.createReadStream(full).pipe(res);
}

function validateDevice(input, existingId) {
  const name = String(input.name ?? '').trim().slice(0, 60);
  const ip = String(input.ip ?? '').trim();
  if (!name) throw new HttpError(400, 'Give the device a name.');
  if (!isValidIPv4(ip) || !isPrivateIPv4(ip)) throw new HttpError(400, 'Use the device’s local IPv4 address, like 192.168.0.201.');
  const macIps = lanInterfaces().map((i) => i.address);
  if (macIps.includes(ip)) throw new HttpError(400, 'That is this Mac’s own address. Use the phone’s address.');
  if (store.data.devices.some((d) => d.ip === ip && d.id !== existingId)) throw new HttpError(409, 'Another device already uses that IP.');
  return { name, ip };
}

function validateTarget(device, input) {
  if (input.mode !== undefined) {
    if (!['proxy', 'direct', 'block'].includes(input.mode)) throw new HttpError(400, 'Unknown mode.');
    device.mode = input.mode;
  }
  if (input.proxyId !== undefined) {
    if (input.proxyId !== null && !store.data.proxies.some((p) => p.id === input.proxyId)) {
      throw new HttpError(400, 'That proxy no longer exists.');
    }
    device.proxyId = input.proxyId;
    if (input.proxyId && input.mode === undefined) device.mode = 'proxy';
  }
  if (device.mode === 'proxy' && !device.proxyId) device.mode = 'block';
}

/** Remove a proxy made by New proxy once no device points at it any more. */
function retire(proxyId) {
  const proxy = store.data.proxies.find((p) => p.id === proxyId);
  if (proxy?.rotated && !store.data.devices.some((d) => d.proxyId === proxyId)) {
    store.data.proxies = store.data.proxies.filter((p) => p !== proxy);
  }
}

/** Proxies that other devices route through right now. */
function activeProxies(except) {
  const ids = new Set(store.data.devices.filter((d) => d !== except && d.mode === 'proxy').map((d) => d.proxyId));
  return store.data.proxies.filter((p) => ids.has(p.id));
}

/**
 * Give a device a fresh session of its proxy (or of the first proxy with a session id): a new
 * exit IP. The new session is checked first, and must not exit where another device's proxy
 * does. If the device changed while the check ran, the user's newer choice wins.
 */
async function rotateDevice(device) {
  const current = store.data.proxies.find((p) => p.id === device.proxyId);
  const template = canRotate(current) ? current : store.data.proxies.find(canRotate);
  if (!template) throw new HttpError(400, 'New proxy needs a proxy with sid-NNN in its username. Import one first.');
  if (rotating.has(device.id)) throw new HttpError(409, 'Already getting a new proxy for this device.');
  rotating.add(device.id);
  const rev = device.rev ?? 0;
  try {
    // Other devices' exits must be known and recent to compare against; sticky sessions can
    // move to another IP over time.
    await runChecks(activeProxies(device).filter((p) => !p.lastCheck || Date.now() - p.lastCheck.at > 10 * 60 * 1000));
    let failure = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      const candidate = withNewSession(template);
      if (store.data.proxies.some((p) => p.id === candidate.id)) continue;
      const result = await checkProxy(candidate, { timeoutMs: 10000 });
      // Everything below runs without awaiting, so no other request can interleave with it.
      if (!store.data.devices.includes(device)) throw new HttpError(404, 'Device not found.');
      if ((device.rev ?? 0) !== rev) throw new HttpError(409, 'The device changed while getting a new proxy, so your change was kept.');
      if (!result.ok) {
        failure = `the new session did not work: ${result.error}`;
        continue;
      }
      const others = activeProxies(device);
      if (others.some((p) => !p.lastCheck)) throw new HttpError(409, 'Another device’s proxy is still being checked. Try again in a moment.');
      if (others.some((p) => p.lastCheck.ok && p.lastCheck.ip === result.ip) || store.data.proxies.some((p) => p.id === candidate.id)) {
        failure = 'the provider kept giving an exit IP already in use';
        continue;
      }
      const proxy = { ...candidate, rotated: true, addedAt: Date.now(), lastCheck: result };
      const previous = device.proxyId;
      store.data.proxies.push(proxy);
      device.mode = 'proxy';
      device.proxyId = proxy.id;
      device.rev = rev + 1;
      retire(previous);
      store.save();
      return { device, proxy: publicProxy(proxy, store.data.devices), ...(await applyAndReport()) };
    }
    throw new HttpError(502, `No new proxy: ${failure ?? 'try again'}.`);
  } finally {
    rotating.delete(device.id);
  }
}

async function applyAndReport() {
  try {
    await gateway.apply();
    return { applied: true };
  } catch (error) {
    return { applied: false, error: error.message };
  }
}

async function runChecks(proxyList) {
  const todo = proxyList.filter((p) => !checking.has(p.id));
  todo.forEach((p) => checking.add(p.id));
  try {
    await mapLimit(todo, 12, async (proxy) => {
      const result = await checkProxy(proxy);
      const current = store.data.proxies.find((p) => p.id === proxy.id);
      if (current) current.lastCheck = result;
      checking.delete(proxy.id);
    });
  } finally {
    todo.forEach((p) => checking.delete(p.id));
    store.save();
  }
}

async function handleApi(req, res, url) {
  const { method } = req;
  const route = url.pathname.replace(/^\/api/, '');
  if (method !== 'GET' && req.headers['x-relay'] !== '1') throw new HttpError(403, 'Missing request header.');

  if (route === '/session' && method === 'GET') {
    return send(res, 200, { via: req.via, urls: dashboardUrls() });
  }

  if (route === '/state' && method === 'GET') return send(res, 200, await statePayload());

  if (route === '/live' && method === 'GET') return send(res, 200, await gateway.live());

  if (route === '/logs' && method === 'GET') return send(res, 200, { logs: singbox.logs.slice(-200) });

  if (route === '/apply' && method === 'POST') return send(res, 200, await applyAndReport());

  if (route === '/devices' && method === 'POST') {
    const input = await readJson(req);
    const device = { id: newId(), ...validateDevice(input), mode: 'block', proxyId: null, createdAt: Date.now() };
    validateTarget(device, input);
    store.data.devices.push(device);
    store.save();
    return send(res, 200, { device, ...(await applyAndReport()) });
  }

  const deviceMatch = route.match(/^\/devices\/([a-z0-9]+)(\/check|\/rotate)?$/);
  if (deviceMatch) {
    const device = store.data.devices.find((d) => d.id === deviceMatch[1]);
    if (!device) throw new HttpError(404, 'Device not found.');
    if (deviceMatch[2] && method !== 'POST') throw new HttpError(405, 'Method not allowed');
    if (deviceMatch[2] === '/rotate') return send(res, 200, await rotateDevice(device));
    if (deviceMatch[2] === '/check') {
      if (device.mode === 'direct') return send(res, 200, { result: await checkDirect() });
      if (device.mode === 'block') return send(res, 200, { result: { ok: false, error: 'This device is blocked.' } });
      const proxy = store.data.proxies.find((p) => p.id === device.proxyId);
      if (!proxy) throw new HttpError(400, 'No proxy selected.');
      await runChecks([proxy]);
      return send(res, 200, { result: proxy.lastCheck });
    }
    if (method === 'PATCH') {
      const input = await readJson(req);
      const next = { ...device };
      if (input.name !== undefined || input.ip !== undefined) {
        Object.assign(next, validateDevice({ name: input.name ?? device.name, ip: input.ip ?? device.ip }, device.id));
      }
      validateTarget(next, input);
      // A session made by New proxy belongs to its route: leaving Proxy mode lets it go.
      if (next.mode !== 'proxy' && store.data.proxies.find((p) => p.id === next.proxyId)?.rotated) next.proxyId = null;
      next.rev = (device.rev ?? 0) + 1;
      const previous = device.proxyId;
      Object.assign(device, next);
      if (previous !== device.proxyId) retire(previous);
      store.save();
      return send(res, 200, { device, ...(await applyAndReport()) });
    }
    if (method === 'DELETE') {
      store.data.devices = store.data.devices.filter((d) => d.id !== device.id);
      retire(device.proxyId);
      store.save();
      return send(res, 200, { ok: true, ...(await applyAndReport()) });
    }
  }

  if (route === '/proxies/import' && method === 'POST') {
    const { text, check } = await readJson(req);
    const { proxies, errors } = parseProxyList(text);
    const existing = new Set(store.data.proxies.map((p) => p.id));
    const added = proxies.filter((p) => !existing.has(p.id)).map((p) => ({ ...p, addedAt: Date.now(), lastCheck: null }));
    store.data.proxies.push(...added);
    store.save();
    const report = added.length ? await applyAndReport() : { applied: true };
    if (check && added.length) runChecks(added).catch(() => {});
    return send(res, 200, { added: added.length, duplicates: proxies.length - added.length, errors, ...report });
  }

  if (route === '/proxies/check' && method === 'POST') {
    const { ids } = await readJson(req);
    const list = Array.isArray(ids) ? store.data.proxies.filter((p) => ids.includes(p.id)) : store.data.proxies;
    runChecks(list).catch(() => {});
    return send(res, 202, { started: list.length });
  }

  if (route === '/proxies/delete' && method === 'POST') {
    const { ids } = await readJson(req);
    if (!Array.isArray(ids)) throw new HttpError(400, 'Pass a list of proxy ids.');
    const remove = new Set(ids);
    store.data.proxies = store.data.proxies.filter((p) => !remove.has(p.id));
    const affected = [];
    for (const device of store.data.devices) {
      if (device.proxyId && remove.has(device.proxyId)) {
        device.proxyId = null;
        if (device.mode === 'proxy') device.mode = 'block';
        affected.push(device.name);
      }
    }
    store.save();
    return send(res, 200, { removed: remove.size, blockedDevices: affected, ...(await applyAndReport()) });
  }

  throw new HttpError(404, 'Not found.');
}

const SECURE_HEADERS = {
  'Cache-Control': 'no-store',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'same-origin',
};

function finish(res, status, body, headers = {}) {
  res.writeHead(status, { ...SECURE_HEADERS, 'Content-Type': 'text/plain; charset=utf-8', ...headers });
  res.end(body);
}

async function readForm(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 4096) throw new HttpError(413, 'Request too large');
    chunks.push(chunk);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
}

/** Decide whether a request may proceed. Returns the origin it belongs to, or ends the response. */
async function admit(req, res, url, listener) {
  const host = req.headers.host ?? '';
  let origin;
  if (access.invalid) return finish(res, 503, `${access.invalid} Fix it, then restart Relay.`);
  if (listener === 'public') {
    origin = access.public.origin;
    if (host !== new URL(origin).host) return finish(res, 403, 'Invalid dashboard host.');
    req.via = 'phone';
  } else if (!access.tailnet && LOCAL_DASHBOARD && LOCAL_HOSTS.has(host) && !forwarded(req)) {
    // Opt-in and only without Tailscale settings. Serve passes the client's own Host header
    // through, so a forwarded request with a localhost Host must not count as local.
    origin = `http://${host}`;
    req.via = 'local';
  } else if (!access.tailnet) {
    return finish(res, 403, 'Create data/access.json (see README), or start Relay with RELAY_LOCAL_DASHBOARD=1 for a localhost-only dashboard.');
  } else if (access.tailnet?.host && host === access.tailnet.host && req.headers['tailscale-user-login'] === access.tailnet.allowedLogin) {
    // Tailscale Serve sets this header for tailnet users and strips it from Funnel and client requests.
    origin = `https://${host}`;
    req.via = 'tailnet';
  } else {
    return finish(res, 403, 'This dashboard is restricted to its Tailscale owner.');
  }

  const navigation = ['GET', 'HEAD'].includes(req.method) && ['/', '/login'].includes(url.pathname) && req.headers['sec-fetch-dest'] === 'document';
  if ((req.headers.origin && req.headers.origin !== origin) || (req.headers['sec-fetch-site'] === 'cross-site' && !navigation)) {
    return finish(res, 403, 'Cross-origin requests are not allowed.');
  }
  if (listener !== 'public') return true;

  // Phones: password and a signed 30-day cookie.
  const secret = store.data.settings.sessionSecret;
  if (url.pathname === '/login' && ['GET', 'HEAD'].includes(req.method)) {
    return finish(res, 200, loginPage('', access.public.username), { 'Content-Type': 'text/html; charset=utf-8', 'Strict-Transport-Security': 'max-age=31536000' });
  }
  if (url.pathname === '/login' && req.method === 'POST') {
    if (req.headers.origin !== origin) return finish(res, 403, 'Use the sign-in form.');
    if (!limiter.take()) return finish(res, 429, 'Too many sign-in attempts. Try again in a minute.', { 'Retry-After': '60' });
    if (!req.headers['content-type']?.startsWith('application/x-www-form-urlencoded')) return finish(res, 415, 'Use the sign-in form.');
    const form = await readForm(req);
    if (!checkPassword(form.get('password') ?? '', access.public.passwordFile)) {
      return finish(res, 401, loginPage('Incorrect password.', access.public.username), { 'Content-Type': 'text/html; charset=utf-8' });
    }
    return finish(res, 303, '', { Location: '/', 'Set-Cookie': sessionCookie(secret) });
  }
  if (url.pathname === '/logout' && req.method === 'POST') {
    return finish(res, 303, '', { Location: '/login', 'Set-Cookie': clearCookie() });
  }
  if (url.pathname === '/icon.svg') return true;
  if (!validSession(readSession(req), secret)) {
    if (url.pathname.startsWith('/api/')) return send(res, 401, { error: 'Sign in first.' });
    return finish(res, 303, '', { Location: '/login' });
  }
  return true;
}

function createServer(listener) {
  const server = http.createServer(async (req, res) => {
    if (req.url === '/healthz' && req.method === 'GET') return finish(res, 200, 'ok');
    if (!req.url?.startsWith('/') || req.url.startsWith('//')) return finish(res, 400, 'Invalid path.');
    const url = new URL(req.url, 'http://relay.local');
    try {
      if ((await admit(req, res, url, listener)) !== true) return;
      if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
      if (req.method !== 'GET') throw new HttpError(405, 'Method not allowed');
      return serveStatic(req, res, url.pathname);
    } catch (error) {
      const status = error.status ?? 500;
      if (status === 500) console.error(error);
      if (!res.headersSent) send(res, status, { error: error.message });
      else res.end();
    }
  });
  // Node drops headers past maxHeadersCount (2000) without an error. A forwarded request must
  // never lose its Forwarded/X-Forwarded-*/Tailscale-* headers that way and pass as local.
  server.maxHeadersCount = 0;
  return server;
}

const servers = [createServer('tailnet')];
servers[0].listen(PORT, '127.0.0.1', async () => {
  console.log(`relay dashboard on http://127.0.0.1:${PORT}${access.tailnet?.host ? ` (Tailscale: https://${access.tailnet.host})` : ''}, root: ${isRoot}`);
  if (!isRoot) console.log('Not running as root: the dashboard works, routing stays off.');
  try {
    await gateway.apply();
  } catch (error) {
    console.error(`Startup apply failed: ${error.message}`);
  }
  const unchecked = store.data.proxies.filter((p) => !p.lastCheck);
  if (unchecked.length) runChecks(unchecked).catch(() => {});
});
if (access.public?.origin && access.public?.port && access.public?.passwordFile) {
  const publicServer = createServer('public');
  publicServer.listen(access.public.port, '127.0.0.1', () => console.log(`phone sign-in on ${access.public.origin} (loopback port ${access.public.port})`));
  servers.push(publicServer);
}

// Re-check every 20 s: pf can be reset by the system, and the Mac's LAN address can change.
setInterval(() => gateway.apply().catch((error) => console.error(`Apply failed: ${error.message}`)), 20000).unref();
// Sample connections in the background so "last seen" stays current even with no dashboard open.
setInterval(() => singbox.running && gateway.live().catch(() => {}), 5000).unref();

let stopping = false;
for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, async () => {
    if (stopping) return;
    stopping = true;
    console.log(`Received ${signal}, removing rules and stopping sing-box`);
    for (const server of servers) server.close();
    await gateway.shutdown().catch(() => {});
    process.exit(0);
  });
}
