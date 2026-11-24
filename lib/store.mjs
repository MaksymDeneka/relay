import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/** Owner of the project folder, so files written by the root daemon stay editable by the user. */
export function projectOwner(dir) {
  try {
    const stat = fs.statSync(path.resolve(dir, '..'));
    return { uid: stat.uid, gid: stat.gid };
  } catch {
    return null;
  }
}

export function chownForUser(file, dir) {
  if (typeof process.getuid !== 'function' || process.getuid() !== 0) return;
  const owner = projectOwner(dir);
  if (!owner) return;
  try {
    fs.chownSync(file, owner.uid, owner.gid);
  } catch {
    // Best effort only.
  }
}

export function writeFileAtomic(file, contents, dir, mode = 0o600) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, contents, { mode });
  fs.renameSync(tmp, file);
  chownForUser(file, dir);
}

function randomSecret() {
  return crypto.randomBytes(24).toString('base64url');
}

export function normalizeState(data = {}) {
  const settings = { ...(data.settings ?? {}) };
  delete settings.passwordHash;
  settings.sessionSecret ??= randomSecret();
  settings.clashSecret ??= randomSecret();

  const proxies = Array.isArray(data.proxies) ? data.proxies : [];
  const devices = Array.isArray(data.devices)
    ? data.devices.map((d) => ({ mode: 'block', proxyId: null, ...d }))
    : [];

  return { settings, proxies, devices };
}

export class Store {
  constructor(dir) {
    this.dir = dir;
    this.file = path.join(dir, 'state.json');
    this.data = null;
  }

  load() {
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    chownForUser(this.dir, this.dir);
    let raw = {};
    try {
      raw = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    this.data = normalizeState(raw);
    this.save();
    return this.data;
  }

  save() {
    writeFileAtomic(this.file, `${JSON.stringify(this.data, null, 2)}\n`, this.dir);
  }
}
