const app = document.getElementById('app');
const dialog = document.getElementById('dialog');
const toasts = document.getElementById('toasts');

const ui = { search: '', selected: new Set(), rotating: new Set() };
let session = { via: 'local' };
let data = null;
let live = { devices: {} };
let els = null;
let timers = [];

/* ---------- helpers ---------- */

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props ?? {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') el.className = value;
    else if (key === 'text') el.textContent = value;
    else if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
    else if (key in el && typeof value !== 'string') el[key] = value;
    else el.setAttribute(key, value === true ? '' : value);
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const child of [children].flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

function fill(el, ...children) {
  el.replaceChildren();
  append(el, children);
}

/**
 * Update table rows in place, swapping only cells whose markup changed. Polling re-renders
 * every few seconds; replacing whole rows would swallow taps that land during a refresh.
 */
function patchRows(tbody, rows) {
  rows = [rows].flat(Infinity).filter(Boolean);
  rows.forEach((row, i) => {
    const old = tbody.rows[i];
    if (!old || old.dataset.key !== row.dataset.key || old.cells.length !== row.cells.length || old.className !== row.className) {
      old ? old.replaceWith(row) : tbody.append(row);
      return;
    }
    [...row.cells].forEach((cell, j) => {
      if (old.cells[j].outerHTML !== cell.outerHTML) old.cells[j].replaceWith(cell);
    });
  });
  while (tbody.rows.length > rows.length) tbody.rows[rows.length].remove();
}

async function api(method, path, body) {
  const response = await fetch(`/api${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-Relay': '1' },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
  });
  const json = await response.json().catch(() => ({}));
  if (response.status === 401) {
    stopPolling();
    location.assign('/login');
    throw new Error(json.error ?? 'Sign in first.');
  }
  if (!response.ok) throw new Error(json.error ?? `HTTP ${response.status}`);
  return json;
}

function toast(message, bad = false) {
  const el = h('div', { class: `toast${bad ? ' bad' : ''}`, text: message });
  toasts.append(el);
  setTimeout(() => el.remove(), bad ? 7000 : 3500);
}

function report(result, okMessage) {
  if (result?.applied === false) toast(`Saved, but routing was not updated: ${result.error}`, true);
  else if (okMessage) toast(okMessage);
}

function bytes(n) {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`;
}

function ago(ts) {
  const s = Math.round((Date.now() - ts) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

const place = (c) => [c.city, c.region && c.region !== c.city ? c.region : null, c.countryCode && c.countryCode !== 'US' ? c.countryCode : null].filter(Boolean).join(', ');
const proxyById = (id) => data?.proxies.find((p) => p.id === id);
const deviceById = (id) => data?.devices.find((d) => d.id === id);
const macAddress = () => data?.network.interfaces.find((i) => i.primary) ?? data?.network.interfaces[0];
const routeName = (d) => (d.mode === 'direct' ? 'Direct' : d.mode === 'block' || !proxyById(d.proxyId) ? 'Blocked' : proxyById(d.proxyId).label);

/* ---------- layout ---------- */

function buildSkeleton() {
  els = {
    status: h('div', { id: 'status', role: 'status', text: 'Loading…' }),
    notices: h('div'),
    deviceActions: h('div', { class: 'actions' }),
    devices: h('tbody'),
    proxyMeta: h('span', { class: 'm' }),
    proxyActions: h('div', { class: 'actions' }),
    search: h('input', { class: 'search hidden', type: 'search', placeholder: 'Search', oninput: (e) => { ui.search = e.target.value; renderProxies(); } }),
    proxies: h('tbody'),
  };
  fill(
    app,
    h(
      'header',
      {},
      h('h1', { text: 'Relay' }),
      h(
        'div',
        { class: 'actions' },
        h('button', { class: 'link', text: 'Setup', onclick: openSetup }),
        h('button', { class: 'link', text: 'Log', onclick: openLog }),
        session.via === 'phone' ? h('button', { class: 'link', text: 'Sign out', onclick: signOut }) : null,
        h('button', { class: 'btn', text: 'Add device', onclick: () => openDeviceDialog() }),
      ),
    ),
    els.status,
    els.notices,
    h(
      'section',
      { class: 'card' },
      h('div', { class: 'card-head' }, h('h2', { text: 'Devices' })),
      h('table', { id: 'devices' }, h('thead', {}, h('tr', {}, ['Device', 'Route', 'Exit', 'Traffic'].map((t) => h('th', { text: t })))), els.devices),
    ),
    h(
      'section',
      { class: 'card' },
      h('div', { class: 'card-head' }, h('h2', { text: 'Proxies' }), els.proxyMeta, h('span', { class: 'spacer' }), els.proxyActions),
      els.search,
      h('table', { id: 'proxies' }, h('thead', {}, h('tr', {}, h('th', {}), ['Proxy', 'Exit', 'Latency', 'Used by'].map((t) => h('th', { text: t })))), els.proxies),
    ),
  );
}

function render() {
  if (!data || !els) return;
  renderStatus();
  renderDevices();
  renderProxies();
}

function renderStatus() {
  const s = data.status;
  const mac = macAddress();
  const routing = s.root && s.singbox.running && s.pf?.loaded && s.pf?.enabled && !s.error;
  const state = !data.devices.length ? 'Idle' : routing ? 'Routing on' : 'Routing off';
  fill(els.status, h('span', { class: `dot ${routing ? 'on' : ''}` }), [state, mac ? `Mac ${mac.address}` : null].filter(Boolean).join(' · '));
  fill(
    els.notices,
    !s.root ? h('div', { class: 'notice' }, 'Not running as root, so nothing is routed. Install the service: ', h('code', { text: 'sudo scripts/install.sh' })) : null,
    s.root && s.error ? h('div', { class: 'notice', text: s.error }) : null,
    ipv6Notice(data.ipv6),
  );
}

/** Relay only routes IPv4. Public IPv6 on the network lets listed phones go around it. */
function ipv6Notice(ipv6) {
  if (ipv6 && !ipv6.available && data.status.root && data.devices.length) {
    return h('div', { class: 'notice', text: 'Could not check this network for public IPv6 (the ARP and NDP tables were unreadable).' });
  }
  if (!ipv6?.exposed) return null;
  const who = ipv6.devices.length ? `${ipv6.devices.map((d) => d.name).join(', ')} ${ipv6.devices.length === 1 ? 'has' : 'have'} a public IPv6 address` : 'Listed phones can get a public IPv6 address';
  return h(
    'div',
    { class: 'notice bad' },
    h('strong', { text: 'IPv6 internet is on in this network. ' }),
    `${who}. IPv6 traffic goes straight to the router, around the proxy. Turn off IPv6 on the router (Tenda: More Features → IPv6).`,
    ipv6.prefixes.length ? h('div', { class: 'm' }, `Seen: ${ipv6.prefixes.join(', ')}`) : null,
  );
}

function renderDevices() {
  if (!data.devices.length) {
    patchRows(els.devices, h('tr', {}, h('td', { colspan: 4, class: 'empty' }, 'No devices yet. Add a phone, then follow ', h('button', { class: 'link', text: 'Setup', onclick: openSetup }), ' on it.')));
    return;
  }
  patchRows(els.devices, data.devices.map(deviceRow));
}

function deviceRow(device) {
  const stats = live.devices?.[device.id];
  const seen = stats?.lastSeen;
  const online = (stats?.connections ?? 0) > 0;
  const proxy = device.mode === 'proxy' ? proxyById(device.proxyId) : null;
  const blocked = device.mode === 'block' || (device.mode === 'proxy' && !proxy);
  // patchRows keeps cells whose markup is unchanged, along with their old handlers, so handlers
  // look the device up when clicked instead of closing over this render's copy.
  const act = (fn) => () => {
    const current = deviceById(device.id);
    if (current) fn(current);
  };

  let exit;
  if (blocked) exit = h('div', { class: 'm', text: 'No internet' });
  else if (device.mode === 'direct') exit = [h('div', { class: 'v', text: 'This Mac' }), h('div', { class: 'm' }, h('button', { class: 'link', text: 'check', onclick: act(checkDevice) }))];
  else if (proxy.checking) exit = h('div', { class: 'm', text: 'Checking…' });
  else if (proxy.lastCheck?.ok) {
    exit = [
      h('div', { class: 'v mono', text: proxy.lastCheck.ip }),
      h('div', { class: 'm' }, `${place(proxy.lastCheck)} · ${ago(proxy.lastCheck.at)} · `, h('button', { class: 'link', text: 'check', onclick: act(checkDevice) })),
    ];
  } else {
    exit = [
      h('div', { class: 'v err', text: proxy.lastCheck ? 'Not working' : 'Not checked' }),
      h('div', { class: 'm' }, proxy.lastCheck ? `${proxy.lastCheck.error} · ` : '', h('button', { class: 'link', text: 'check', onclick: act(checkDevice) })),
    ];
  }

  return h(
    'tr',
    { 'data-key': device.id },
    h(
      'td',
      {},
      h('button', { class: 'who', text: device.name, title: 'Edit or remove', onclick: act(openDeviceDialog) }),
      h('div', { class: 'm' }, h('span', { class: `dot ${online ? 'on' : seen ? 'seen' : ''}` }), `${device.ip} · ${online ? 'online' : seen ? `seen ${ago(seen)}` : 'not seen yet'}`),
    ),
    h(
      'td',
      { 'data-label': 'Route' },
      h('button', { class: `route${blocked ? ' block' : ''}`, text: routeName(device), onclick: act(openPicker) }),
      data.proxies.some((p) => p.rotatable)
        ? h('div', { class: 'm' }, h('button', { class: 'link', text: ui.rotating.has(device.id) ? 'getting new proxy…' : 'new proxy', title: 'New exit IP. Every phone reconnects for a moment.', disabled: ui.rotating.has(device.id), onclick: act(newProxy) }))
        : device.mode === 'proxy' && data.proxies.length > 1
          ? h('div', { class: 'm' }, h('button', { class: 'link', text: 'next proxy', onclick: act(nextProxy) }))
          : null,
    ),
    h('td', { 'data-label': 'Exit' }, exit),
    h(
      'td',
      { 'data-label': 'Traffic' },
      online ? [h('div', { class: 'v', text: `${stats.connections} connection${stats.connections === 1 ? '' : 's'}` }), h('div', { class: 'm', text: `↓ ${bytes(stats.download)} · ↑ ${bytes(stats.upload)}` })] : h('div', { class: 'm', text: '—' }),
    ),
  );
}

function filteredProxies() {
  const q = ui.search.trim().toLowerCase();
  if (!q) return data.proxies;
  return data.proxies.filter((p) => [p.label, p.host, p.provider, p.lastCheck?.ip, p.lastCheck?.city, p.lastCheck?.region, p.usedBy.map((id) => deviceById(id)?.name)].flat().join(' ').toLowerCase().includes(q));
}

function renderProxies() {
  for (const id of [...ui.selected]) if (!proxyById(id)) ui.selected.delete(id);
  const total = data.proxies.length;
  const working = data.proxies.filter((p) => p.lastCheck?.ok).length;
  const checking = data.proxies.some((p) => p.checking);
  els.proxyMeta.textContent = total ? (checking ? `${total} · checking…` : `${total} · ${working} working`) : '';
  els.search.classList.toggle('hidden', total <= 10);

  const n = ui.selected.size;
  fill(
    els.proxyActions,
    n ? h('button', { class: 'link', text: `Clear selection`, onclick: () => { ui.selected.clear(); renderProxies(); } }) : null,
    n ? h('button', { class: 'link', text: `Check ${n}`, onclick: () => startChecks([...ui.selected]) }) : null,
    n ? h('button', { class: 'link danger', text: `Delete ${n}`, onclick: deleteSelected }) : null,
    !n && total ? h('button', { class: 'link', text: 'Check all', disabled: checking, onclick: () => startChecks(null) }) : null,
    !n ? h('button', { class: 'link', text: 'Import', onclick: openImport }) : null,
  );

  if (!total) {
    patchRows(els.proxies, h('tr', {}, h('td', { colspan: 5, class: 'empty' }, 'No proxies yet. ', h('button', { class: 'link', text: 'Import a list', onclick: openImport }), ', one per line.')));
    return;
  }
  const list = filteredProxies();
  const rows = list.slice(0, 300).map((p) => {
    const check = p.lastCheck;
    return h(
      'tr',
      { 'data-key': p.id },
      h('td', { class: 'pick' }, h('input', { type: 'checkbox', checked: ui.selected.has(p.id) ? 'checked' : null, 'aria-label': `Select ${p.label}`, onchange: (e) => { e.target.checked ? ui.selected.add(p.id) : ui.selected.delete(p.id); renderProxies(); } })),
      h('td', {}, h('span', { class: 'who', text: p.label, title: `${p.type === 'http' ? 'HTTP' : 'SOCKS5'} ${p.host}:${p.port}` }), p.type === 'http' ? h('span', { class: 'm', text: '  HTTP' }) : null),
      h('td', { class: 'exit' }, p.checking ? h('span', { class: 'm', text: 'Checking…' }) : check?.ok ? [h('span', { class: 'mono', text: check.ip }), h('span', { class: 'm', text: `  ${place(check)}` })] : check ? h('span', { class: 'm err', text: check.error }) : h('span', { class: 'm', text: '—' })),
      h('td', { class: 'lat m', text: check?.ok ? `${(check.ms / 1000).toFixed(1)} s` : '' }),
      h('td', { class: 'used m', text: p.usedBy.map((id) => deviceById(id)?.name).filter(Boolean).join(', ') }),
    );
  });
  if (!list.length) rows.push(h('tr', {}, h('td', { colspan: 5, class: 'empty', text: 'Nothing matches.' })));
  if (list.length > 300) rows.push(h('tr', {}, h('td', { colspan: 5, class: 'more', text: `${list.length - 300} more. Search to narrow down.` })));
  patchRows(els.proxies, rows);
}

/* ---------- actions ---------- */

async function refresh() {
  try {
    data = await api('GET', '/state');
    render();
  } catch (e) {
    console.warn(e);
  }
}

async function refreshLive() {
  try {
    live = await api('GET', '/live');
    if (data) renderDevices();
  } catch {}
}

let checkPoll = null;
function pollChecks() {
  clearTimeout(checkPoll);
  checkPoll = setTimeout(async () => {
    await refresh();
    if (data?.proxies.some((p) => p.checking)) pollChecks();
  }, 1200);
}

async function startChecks(ids) {
  try {
    await api('POST', '/proxies/check', { ids: ids ?? undefined });
    await refresh();
    pollChecks();
  } catch (e) {
    toast(e.message, true);
  }
}

async function checkDevice(device) {
  if (device.mode === 'proxy') return startChecks([device.proxyId]);
  try {
    const { result } = await api('POST', `/devices/${device.id}/check`);
    toast(result.ok ? `${device.name} exits as ${result.ip}, ${place(result)}` : `${device.name}: ${result.error}`, !result.ok);
  } catch (e) {
    toast(e.message, true);
  }
}

async function setRoute(device, change, message) {
  try {
    report(await api('PATCH', `/devices/${device.id}`, change), message);
    await refresh();
    const proxy = proxyById(deviceById(device.id)?.proxyId);
    if (change.proxyId && proxy && (!proxy.lastCheck || Date.now() - proxy.lastCheck.at > 10 * 60 * 1000)) startChecks([proxy.id]);
  } catch (e) {
    toast(e.message, true);
  }
}

/** A fresh session of the device's proxy: a new exit IP, checked before the switch. */
async function newProxy(device) {
  if (ui.rotating.has(device.id)) return;
  ui.rotating.add(device.id);
  renderDevices();
  try {
    const result = await api('POST', `/devices/${device.id}/rotate`);
    const check = result.proxy.lastCheck;
    report(result, `${device.name} → ${check.ip}, ${place(check)}`);
  } catch (e) {
    toast(e.message, true);
  } finally {
    ui.rotating.delete(device.id);
    await refresh();
  }
}

function nextProxy(device) {
  const list = data.proxies;
  const start = Math.max(0, list.findIndex((p) => p.id === device.proxyId));
  const ordered = [...list.slice(start + 1), ...list.slice(0, start + 1)];
  const next = ordered.find((p) => p.id !== device.proxyId && !p.usedBy.length && (!p.lastCheck || p.lastCheck.ok));
  if (!next) return toast('No other free, working proxy.', true);
  setRoute(device, { mode: 'proxy', proxyId: next.id }, `${device.name} → ${next.label}`);
}

async function deleteSelected() {
  const ids = [...ui.selected];
  const inUse = ids.map(proxyById).filter((p) => p?.usedBy.length);
  const warn = inUse.length ? `\n\n${inUse.length} in use. Those devices will be blocked until you pick another proxy.` : '';
  if (!confirm(`Delete ${ids.length} prox${ids.length === 1 ? 'y' : 'ies'}?${warn}`)) return;
  try {
    const result = await api('POST', '/proxies/delete', { ids });
    ui.selected.clear();
    report(result, `Deleted ${result.removed}`);
  } catch (e) {
    toast(e.message, true);
  }
  refresh();
}

function signOut() {
  const form = h('form', { method: 'post', action: '/logout' });
  document.body.append(form);
  form.submit();
}

/* ---------- dialogs ---------- */

function openDialog(title, body, footer) {
  fill(
    dialog,
    h(
      'div',
      { class: 'dlg' },
      h('div', { class: 'dlg-head' }, h('h3', { text: title }), h('button', { class: 'link', text: 'Close', onclick: () => dialog.close() })),
      h('div', { class: 'dlg-body' }, body),
      footer ? h('div', { class: 'dlg-foot' }, footer) : null,
    ),
  );
  dialog.showModal();
  // showModal focuses the first control (Close); keep the ring off until the keyboard is used.
  if (document.activeElement?.textContent === 'Close') document.activeElement.blur();
}

dialog.addEventListener('click', (e) => {
  if (e.target === dialog) dialog.close();
});

function openPicker(device) {
  const search = h('input', { class: 'input', type: 'search', placeholder: 'Search proxies' });
  const list = h('div', { class: 'options' });
  const choose = (change, message) => {
    dialog.close();
    setRoute(device, change, message);
  };
  const option = (title, meta, tag, current, onclick) =>
    h('button', { class: `option${current ? ' current' : ''}`, onclick }, h('div', { class: 'grow' }, h('div', { class: 'who', text: title }), meta ? h('div', { class: 'm', text: meta }) : null), tag ? h('span', { class: 'tag', text: tag }) : null);

  const draw = () => {
    const q = search.value.trim().toLowerCase();
    const proxies = data.proxies
      .filter((p) => !q || [p.label, p.lastCheck?.ip, p.lastCheck?.city, p.lastCheck?.region].join(' ').toLowerCase().includes(q))
      .sort((a, b) => (b.id === device.proxyId) - (a.id === device.proxyId) || !!a.usedBy.length - !!b.usedBy.length || (b.lastCheck?.ok ? 1 : 0) - (a.lastCheck?.ok ? 1 : 0));
    fill(
      list,
      q ? null : option('Direct', 'This Mac’s own connection, no proxy', null, device.mode === 'direct', () => choose({ mode: 'direct' }, `${device.name}: direct`)),
      q ? null : option('Block', 'No internet', null, device.mode === 'block', () => choose({ mode: 'block' }, `${device.name}: blocked`)),
      proxies.slice(0, 200).map((p) => {
        const current = device.mode === 'proxy' && device.proxyId === p.id;
        const others = p.usedBy.filter((id) => id !== device.id).map((id) => deviceById(id)?.name).filter(Boolean);
        const meta = p.lastCheck?.ok ? `${p.lastCheck.ip} · ${place(p.lastCheck)}` : p.lastCheck ? `Not working: ${p.lastCheck.error}` : 'Not checked';
        return option(p.label, meta, current ? 'current' : others.length ? `used by ${others.join(', ')}` : null, current, () => choose({ mode: 'proxy', proxyId: p.id }, `${device.name} → ${p.label}`));
      }),
    );
  };
  search.addEventListener('input', draw);
  draw();
  openDialog(`Route for ${device.name}`, [data.proxies.length > 8 ? search : null, list]);
  document.activeElement?.blur();
}

function suggestIp() {
  const mac = macAddress();
  const prefix = mac ? mac.address.split('.').slice(0, 3).join('.') : '192.168.0';
  const used = new Set(data.devices.map((d) => d.ip));
  for (let n = 201; n < 250; n++) if (!used.has(`${prefix}.${n}`)) return `${prefix}.${n}`;
  return `${prefix}.200`;
}

function openDeviceDialog(device) {
  const name = h('input', { class: 'input', value: device?.name ?? '', placeholder: 'iPhone 2', maxLength: 60 });
  const ip = h('input', { class: 'input mono', value: device?.ip ?? suggestIp(), inputmode: 'decimal', autocapitalize: 'off', autocorrect: 'off' });
  const error = h('div', { class: 'err' });
  const save = h('button', {
    class: 'btn',
    text: device ? 'Save' : 'Add',
    onclick: async () => {
      error.textContent = '';
      save.disabled = true;
      try {
        const body = { name: name.value, ip: ip.value };
        const result = device ? await api('PATCH', `/devices/${device.id}`, body) : await api('POST', '/devices', body);
        dialog.close();
        report(result, device ? 'Saved' : null);
        await refresh();
        if (!device) openPicker(deviceById(result.device.id));
      } catch (e) {
        error.textContent = e.message;
        save.disabled = false;
      }
    },
  });
  const remove = device
    ? h('button', {
        class: 'link danger',
        text: 'Remove device',
        onclick: async () => {
          if (!confirm(`Remove ${device.name}? If the phone still uses this Mac as its router, it loses internet until its Wi-Fi is set back to Automatic.`)) return;
          dialog.close();
          try {
            report(await api('DELETE', `/devices/${device.id}`), `${device.name} removed`);
          } catch (e) {
            toast(e.message, true);
          }
          refresh();
        },
      })
    : null;
  openDialog(
    device ? device.name : 'Add device',
    [
      h('div', { class: 'field' }, h('label', { text: 'Name' }), name),
      h('div', { class: 'field' }, h('label', { text: 'IP address the phone will use' }), ip, h('div', { class: 'hint', text: 'Pick a free address outside the router’s DHCP range. Only devices listed here are routed.' })),
      error,
    ],
    [remove, h('span', { class: 'spacer' }), save],
  );
  name.focus();
}

function openImport() {
  const text = h('textarea', { class: 'input', placeholder: 'host:port:user:pass\nsocks5://user:pass@host:port\nhttp://user:pass@host:port', spellcheck: 'false' });
  const result = h('div', { class: 'hint' });
  const go = h('button', {
    class: 'btn',
    text: 'Import',
    onclick: async () => {
      go.disabled = true;
      try {
        const res = await api('POST', '/proxies/import', { text: text.value, check: true });
        const parts = [`${res.added} added`, res.duplicates ? `${res.duplicates} already listed` : null, res.errors.length ? `${res.errors.length} lines not understood` : null].filter(Boolean).join(' · ');
        report(res, parts);
        await refresh();
        if (res.added) pollChecks();
        if (!res.errors.length) dialog.close();
        else fill(result, h('div', { class: 'err', text: parts }), res.errors.slice(0, 6).map((e) => h('div', { class: 'mono', text: `line ${e.line}: ${e.text}` })));
      } catch (e) {
        fill(result, h('div', { class: 'err', text: e.message }));
      }
      go.disabled = false;
    },
  });
  openDialog('Import proxies', [h('div', { class: 'hint', text: 'One per line. Rows copied from a spreadsheet work too. New proxies are checked right away.' }), text, result], [h('span', { class: 'spacer' }), go]);
  text.focus();
}

function openSetup() {
  const mac = macAddress();
  if (!mac) return openDialog('Setup', h('div', { class: 'hint', text: 'This Mac has no LAN address right now.' }));
  const mask = mac.netmask ?? '255.255.255.0';
  openDialog('Connect a phone', [
    h('div', { class: 'kv' }, h('span', { text: 'Router' }), h('span', { class: 'mono', text: mac.address }), h('span', { text: 'DNS' }), h('span', { class: 'mono', text: mac.address }), h('span', { text: 'Subnet mask' }), h('span', { class: 'mono', text: mask }), data.urls?.phones ? [h('span', { text: 'Dashboard' }), h('span', { class: 'mono', text: data.urls.phones })] : null),
    h(
      'ol',
      { class: 'steps' },
      h('li', { text: 'Add the phone here with a free IP address.' }),
      h('li', { text: 'iPhone: Settings → Wi-Fi → ⓘ next to the network.' }),
      h('li', { text: `Configure IP → Manual: the phone’s IP, mask ${mask}, router ${mac.address}.` }),
      h('li', { text: `Configure DNS → Manual: only ${mac.address}.` }),
      h('li', { text: 'Turn off Limit IP Address Tracking.' }),
      h('li', { text: 'To stop, set Configure IP and DNS back to Automatic.' }),
    ),
  ]);
}

async function openLog() {
  const pre = h('pre', { class: 'log', text: 'Loading…' });
  openDialog('sing-box log', pre);
  const load = async () => {
    try {
      const { logs } = await api('GET', '/logs');
      const atBottom = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 30;
      pre.textContent = logs.map((l) => l.line).join('\n') || 'No output yet.';
      if (atBottom) pre.scrollTop = pre.scrollHeight;
    } catch {}
  };
  await load();
  pre.scrollTop = pre.scrollHeight;
  const timer = setInterval(() => (dialog.open && dialog.contains(pre) ? load() : clearInterval(timer)), 3000);
}

/* ---------- lifecycle ---------- */

function stopPolling() {
  timers.forEach(clearInterval);
  timers = [];
}

async function start() {
  stopPolling();
  try {
    session = await api('GET', '/session');
  } catch {
    return;
  }
  buildSkeleton();
  await refresh();
  refreshLive();
  if (data?.proxies.some((p) => p.checking)) pollChecks();
  timers.push(setInterval(refresh, 6000), setInterval(refreshLive, 3000));
}

start();
