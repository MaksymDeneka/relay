import crypto from 'node:crypto';

const TYPE_ALIASES = {
  socks: 'socks5',
  socks5: 'socks5',
  socks5h: 'socks5',
  http: 'http',
  https: 'http',
};

export function proxyId({ type, host, port, username, password }) {
  return crypto
    .createHash('sha256')
    .update([type, host.toLowerCase(), port, username ?? '', password ?? ''].join('\u0000'))
    .digest('hex')
    .slice(0, 12);
}

function isPort(value) {
  return /^\d{1,5}$/.test(value) && Number(value) > 0 && Number(value) < 65536;
}

function isHost(value) {
  return /^[a-z0-9.-]+$/i.test(value) && /[a-z0-9]/i.test(value);
}

/** Parse one proxy token: URL form, user:pass@host:port, host:port:user:pass, user:pass:host:port or host:port. */
export function parseProxyToken(token, fallbackType = 'socks5') {
  let type = fallbackType;
  let rest = token.trim();

  const scheme = rest.match(/^([a-z0-9]+):\/\//i);
  if (scheme) {
    const mapped = TYPE_ALIASES[scheme[1].toLowerCase()];
    if (!mapped) return null;
    type = mapped;
    rest = rest.slice(scheme[0].length).replace(/\/+$/, '');
  }

  let host;
  let port;
  let username = '';
  let password = '';

  const at = rest.lastIndexOf('@');
  if (at !== -1) {
    const auth = rest.slice(0, at);
    const endpoint = rest.slice(at + 1);
    const colon = auth.indexOf(':');
    username = safeDecode(colon === -1 ? auth : auth.slice(0, colon));
    password = safeDecode(colon === -1 ? '' : auth.slice(colon + 1));
    const portColon = endpoint.lastIndexOf(':');
    if (portColon === -1) return null;
    host = endpoint.slice(0, portColon);
    port = endpoint.slice(portColon + 1);
  } else {
    const parts = rest.split(':');
    if (parts.length === 2) {
      [host, port] = parts;
    } else if (parts.length >= 4 && isHost(parts[0]) && isPort(parts[1])) {
      host = parts[0];
      port = parts[1];
      username = parts[2];
      password = parts.slice(3).join(':');
    } else if (parts.length === 4 && isHost(parts[2]) && isPort(parts[3])) {
      [username, password, host, port] = parts;
    } else {
      return null;
    }
  }

  if (!host || !isHost(host) || !isPort(port)) return null;
  const proxy = { type, host: host.toLowerCase(), port: Number(port), username, password };
  return { id: proxyId(proxy), ...proxy, label: deriveLabel(proxy), country: deriveCountry(proxy) };
}

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export function deriveLabel({ host, port, username }) {
  const sid = username?.match(/(?:^|[-_])(?:sid|session|sessid)[-_]([a-z0-9]+)/i);
  if (sid) return `sid ${sid[1]}`;
  return `${host}:${port}`;
}

export function deriveCountry({ username }) {
  const match = username?.match(/(?:^|[-_])(?:country|region|cc)[-_]([a-z]{2})(?:[-_]|$)/i);
  return match ? match[1].toUpperCase() : null;
}

/**
 * Parse pasted text. Each line may be a bare proxy, a URL, or a row copied from a
 * spreadsheet like "socks<TAB>host:port:user:pass<TAB>provider".
 */
export function parseProxyList(text) {
  const proxies = [];
  const errors = [];
  const seen = new Set();
  const lines = String(text ?? '').split(/\r?\n/);

  lines.forEach((raw, index) => {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) return;

    const tokens = line.split(/[\t,; ]+/).filter(Boolean);
    let type = 'socks5';
    for (const token of tokens) {
      const mapped = TYPE_ALIASES[token.toLowerCase()];
      if (mapped) type = mapped;
    }

    let parsed = null;
    let used = null;
    for (const token of tokens) {
      if (TYPE_ALIASES[token.toLowerCase()] || /^\d+$/.test(token)) continue;
      parsed = parseProxyToken(token, type);
      if (parsed) {
        used = token;
        break;
      }
    }

    if (!parsed) {
      errors.push({ line: index + 1, text: line.slice(0, 120), error: 'No proxy found on this line' });
      return;
    }

    const note = tokens
      .filter((t) => t !== used && !TYPE_ALIASES[t.toLowerCase()] && !/^\d+$/.test(t))
      .join(' ')
      .slice(0, 60);
    if (note) parsed.provider = note;

    if (seen.has(parsed.id)) return;
    seen.add(parsed.id);
    proxies.push(parsed);
  });

  return { proxies, errors };
}
