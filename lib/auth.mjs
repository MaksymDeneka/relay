import crypto from 'node:crypto';
import fs from 'node:fs';

// On the Mac, Tailscale Serve vouches for the owner; on phones, a Tailscale Funnel URL takes a
// password and issues a signed cookie.
export const COOKIE = '__Host-relay_session';
const SESSION_SECONDS = 30 * 86400;

function equal(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

/**
 * Check a password against a file holding `passwordSalt` and `passwordHash`
 * (scrypt, 32 bytes, hex). Another local dashboard can share the same file, and so the password.
 * The file is read on each attempt, so a password change there applies here too.
 */
export function checkPassword(password, passwordFile) {
  if (typeof password !== 'string' || !password || password.length > 256) return false;
  let config;
  try {
    config = JSON.parse(fs.readFileSync(passwordFile, 'utf8'));
  } catch {
    return false;
  }
  if (!config.passwordSalt || !config.passwordHash) return false;
  return equal(crypto.scryptSync(password, config.passwordSalt, 32).toString('hex'), config.passwordHash);
}

export function createSession(secret, now = Date.now()) {
  const iat = Math.floor(now / 1000);
  const payload = Buffer.from(
    JSON.stringify({ iat, exp: iat + SESSION_SECONDS, nonce: crypto.randomBytes(16).toString('base64url') }),
  ).toString('base64url');
  return `${payload}.${crypto.createHmac('sha256', secret).update(payload).digest('base64url')}`;
}

export function validSession(token, secret, now = Date.now()) {
  const parts = String(token ?? '').split('.');
  if (parts.length !== 2) return false;
  if (!equal(parts[1], crypto.createHmac('sha256', secret).update(parts[0]).digest('base64url'))) return false;
  try {
    const data = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    const t = Math.floor(now / 1000);
    return Number.isInteger(data.exp) && Number.isInteger(data.iat) && data.iat <= t && data.exp > t;
  } catch {
    return false;
  }
}

export function sessionCookie(secret) {
  return `${COOKIE}=${createSession(secret)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_SECONDS}`;
}

export function clearCookie() {
  return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export function readSession(req) {
  return (req.headers.cookie ?? '')
    .split(';')
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${COOKIE}=`))
    ?.slice(COOKIE.length + 1);
}

/** Global cap on password attempts: still effective if forwarded IP headers are forged. */
export class LoginLimiter {
  constructor(max = 5, windowMs = 60000) {
    this.max = max;
    this.windowMs = windowMs;
    this.attempts = [];
  }

  take(now = Date.now()) {
    while (this.attempts.length && this.attempts[0] <= now - this.windowMs) this.attempts.shift();
    if (this.attempts.length >= this.max) return false;
    this.attempts.push(now);
    return true;
  }
}

const escapeHtml = (v) => String(v).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

// The hidden username lets password managers match a credential saved for another dashboard
// on the same host.
export const loginPage = (error = '', username = 'relay') => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#1a1a19"><title>Relay · Sign in</title><link rel="icon" href="/icon.svg" type="image/svg+xml"><style>:root{color-scheme:dark;font:16px Inter,ui-sans-serif,system-ui,sans-serif;background:#1a1a19;color:#f0efec}*{box-sizing:border-box}body{max-width:420px;margin:15vh auto;padding:24px}h1{font-size:26px;margin:0 0 8px}p{color:#b9b9af;line-height:1.5}input,button{width:100%;font:inherit;padding:14px;border-radius:10px;margin:8px 0}input{background:#292927;border:1px solid #555;color:inherit}button{background:#f0efec;color:#1a1a19;border:0;font-weight:600}label{font-size:14px}.err{color:#e8c993}</style></head><body><h1>Relay</h1><p>Sign in once. This device stays signed in for 30 days.</p>${error ? `<p class="err">${error}</p>` : ''}<form method="post" action="/login"><input type="hidden" name="username" value="${escapeHtml(username)}" autocomplete="username"><label for="password">Dashboard password</label><input id="password" name="password" type="password" autocomplete="current-password" required maxlength="256" autofocus><button type="submit">Sign in</button></form></body></html>`;
