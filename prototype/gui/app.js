/* IP Sentinel dashboard: talks to sentinel_gui.py over its token-protected JSON API.
   All API-derived text is inserted with textContent (via h()), never innerHTML. */
(() => {
  'use strict';

  // ---------------------------------------------------------------- constants
  const TOKEN = document.querySelector('meta[name="sentinel-token"]')?.getAttribute('content') || '';
  const POLL_MS = 5000;
  const MAX_BACKOFF_MS = 30000;
  const MAX_TABLE_ROWS = 1000;
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const ROUTES = {
    overview: 'Overview',
    workspace: 'Workspace',
    ledger: 'Chain',
    verify: 'Verify',
    export: 'Export',
    activity: 'Activity',
  };
  const STATUS_LABEL = { new: 'New', modified: 'Modified', unchanged: 'Unchanged' };
  const LEVEL_LABEL = { info: 'Info', success: 'Success', warning: 'Warning', error: 'Error' };

  // ---------------------------------------------------------------- app state
  const app = {
    state: null,
    activity: [],
    freshSince: null,
    scan: null,
    scanFilter: 'all',
    scanQuery: '',
    scanAlert: null,
    blockCache: new Map(),
    expanded: new Set(),
    pendingReveal: null,
    justCommitted: null,
    audit: null,
    proofs: [],
    activityFilter: 'all',
    failures: 0,
    conn: 'connecting',
    sessionExpired: false,
    wsDirty: false,
  };
  const signatures = {};
  let pollTimer = null;
  let proofSeq = 0;

  // ---------------------------------------------------------------- DOM helpers
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  function h(tag, props, ...children) {
    const el = document.createElement(tag);
    if (props) {
      for (const [key, value] of Object.entries(props)) {
        if (value === null || value === undefined || value === false) continue;
        if (key === 'class') el.className = value;
        else if (key === 'dataset') Object.assign(el.dataset, value);
        else if (key.startsWith('on') && typeof value === 'function') el.addEventListener(key.slice(2), value);
        else el.setAttribute(key, value === true ? '' : String(value));
      }
    }
    return append(el, children);
  }

  function append(el, children) {
    for (const child of children.flat(Infinity)) {
      if (child === null || child === undefined || child === false) continue;
      el.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return el;
  }

  function fill(el, ...children) {
    el.replaceChildren();
    return append(el, children);
  }

  function icon(name, cls = '') {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('class', `icon ${cls}`.trim());
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS(SVG_NS, 'use');
    use.setAttribute('href', `#i-${name}`);
    svg.append(use);
    return svg;
  }

  /** True when `value` differs from the last value recorded under `key`. */
  function changed(key, value) {
    const sig = JSON.stringify(value);
    if (signatures[key] === sig) return false;
    signatures[key] = sig;
    return true;
  }

  const store = {
    get(key, fallback) {
      try {
        const v = localStorage.getItem(key);
        return v === null ? fallback : v;
      } catch {
        return fallback;
      }
    },
    set(key, value) {
      try { localStorage.setItem(key, value); } catch { /* storage unavailable */ }
    },
  };

  // ---------------------------------------------------------------- formatting
  const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  const clockFmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  const relFmt = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

  function toDate(iso) {
    const d = iso ? new Date(iso) : null;
    return d && !Number.isNaN(d.getTime()) ? d : null;
  }
  const fmtDate = (iso) => { const d = toDate(iso); return d ? dateFmt.format(d) : '—'; };
  const fmtClock = (iso) => { const d = toDate(iso); return d ? clockFmt.format(d) : '—'; };

  function fmtRelative(iso) {
    const d = toDate(iso);
    if (!d) return '—';
    const sec = Math.round((d.getTime() - Date.now()) / 1000);
    const abs = Math.abs(sec);
    if (abs < 45) return 'just now';
    const units = [['minute', 60], ['hour', 3600], ['day', 86400], ['week', 604800], ['month', 2629800], ['year', 31557600]];
    let [unit, size] = units[0];
    for (const [u, s] of units) if (abs >= s) { unit = u; size = s; }
    return relFmt.format(Math.round(sec / size), unit);
  }

  /** <time> element; mode 'relative' keeps itself fresh via refreshRelativeTimes(). */
  function timeEl(iso, mode = 'date') {
    const text = mode === 'clock' ? fmtClock(iso) : mode === 'relative' ? fmtRelative(iso) : fmtDate(iso);
    const el = h('time', { datetime: iso || null, title: iso ? `${fmtDate(iso)} · ${iso}` : null }, text);
    if (mode === 'relative' && iso) el.dataset.rel = iso;
    return el;
  }

  function refreshRelativeTimes() {
    for (const el of $$('[data-rel]')) el.textContent = fmtRelative(el.dataset.rel);
  }

  function fmtBytes(n) {
    if (!Number.isFinite(n)) return '—';
    if (n < 1024) return `${n} B`;
    const units = ['KB', 'MB', 'GB', 'TB'];
    let v = n / 1024;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
    return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
  }

  const plural = (n, word, many = `${word}s`) => `${Number(n).toLocaleString()} ${n === 1 ? word : many}`;

  function shortPath(p, keep = 2) {
    if (!p) return '';
    const parts = p.split('/').filter(Boolean);
    return parts.length <= keep ? p : `…/${parts.slice(-keep).join('/')}`;
  }

  // ---------------------------------------------------------------- shared UI pieces
  function swatch(hash) {
    const wrap = h('span', { class: 'swatch', 'aria-hidden': 'true' });
    const isZero = !hash || /^0+$/.test(hash);
    for (let i = 0; i < 4; i += 1) {
      const cell = document.createElement('i');
      if (isZero) {
        cell.className = 'is-zero';
      } else {
        const hue = parseInt(hash.slice(i * 3, i * 3 + 3), 16) % 360;
        cell.style.background = `hsl(${hue}, var(--swatch-s), var(--swatch-l))`;
      }
      wrap.append(cell);
    }
    return wrap;
  }

  function hashChip(hash, { large = false, label = 'Hash' } = {}) {
    if (!hash) return h('span', { class: 'muted' }, '—');
    const text = large ? hash.match(/.{1,8}/g).join(' ') : hash.slice(0, 12);
    return h('button', {
      type: 'button',
      class: large ? 'hash-chip is-lg' : 'hash-chip',
      'data-copy': hash,
      title: `${hash}\nClick to copy`,
      'aria-label': `${label}: ${hash.slice(0, 12)}…, copy full hash`,
    }, swatch(hash), h('span', { class: 'hash-text' }, text), icon('copy', 'icon-xs'));
  }

  const statusBadge = (status) => h('span', { class: `badge badge-${status}` }, STATUS_LABEL[status] || status);
  const levelBadge = (level) => h('span', { class: `badge badge-${level}` }, LEVEL_LABEL[level] || level);

  function pathLabel(rel) {
    const i = rel.lastIndexOf('/');
    return h('span', { class: 'path', title: rel },
      i >= 0 ? h('span', { class: 'path-dir' }, rel.slice(0, i + 1)) : null,
      h('span', { class: 'path-file' }, rel.slice(i + 1)));
  }

  function emptyState(iconName, title, text, ...actions) {
    return h('div', { class: 'empty' },
      h('span', { class: 'empty-icon' }, icon(iconName)),
      h('h3', null, title),
      text ? h('p', null, text) : null,
      actions.length ? h('div', { class: 'ov-ws-actions' }, actions) : null);
  }

  function callout(tone, title, message, actions = []) {
    const iconName = { success: 'check', danger: 'x', warning: 'alert', info: 'info' }[tone] || 'info';
    return h('div', { class: 'callout', 'data-tone': tone, role: tone === 'danger' ? 'alert' : 'status' },
      icon(iconName),
      h('div', null,
        h('strong', null, title),
        message ? h('p', null, message) : null,
        actions.length ? h('div', { class: 'callout-actions' }, actions) : null));
  }

  function fileTable(files, { showModified = true } = {}) {
    const shown = files.slice(0, MAX_TABLE_ROWS);
    const head = h('tr', null,
      h('th', { scope: 'col' }, 'Status'),
      h('th', { scope: 'col' }, 'Path'),
      h('th', { scope: 'col', class: 'num' }, 'Size'),
      showModified ? h('th', { scope: 'col' }, 'Modified') : null,
      h('th', { scope: 'col' }, 'SHA-256'));
    const rows = shown.map((f) => h('tr', null,
      h('td', { class: 'c-status' }, statusBadge(f.status)),
      h('td', { class: 'c-path' }, pathLabel(f.relative_path)),
      h('td', { class: 'c-size num' }, fmtBytes(f.size_bytes)),
      showModified ? h('td', { class: 'c-mod' }, f.modified_at ? timeEl(f.modified_at, 'relative') : '') : null,
      h('td', { class: 'c-hash' }, hashChip(f.sha256_hash, { label: f.relative_path }))));
    if (!rows.length) {
      rows.push(h('tr', { class: 'data-empty' }, h('td', { colspan: showModified ? 5 : 4 }, 'No files match this filter.')));
    }
    return h('div', null,
      h('div', { class: 'table-wrap' }, h('table', { class: 'data files' }, h('thead', null, head), h('tbody', null, rows))),
      files.length > shown.length
        ? h('div', { class: 'table-note' }, `Showing the first ${MAX_TABLE_ROWS.toLocaleString()} of ${files.length.toLocaleString()} files. Use the filter to narrow the list.`)
        : null);
  }

  // ---------------------------------------------------------------- toasts & busy state
  function toast(tone, message, action) {
    const iconName = { success: 'check', error: 'x', warning: 'alert', info: 'info' }[tone] || 'info';
    let timer = null;
    const dismiss = () => {
      clearTimeout(timer);
      el.classList.add('is-leaving');
      setTimeout(() => el.remove(), 200);
    };
    const el = h('div', { class: 'toast', 'data-tone': tone, role: tone === 'error' ? 'alert' : 'status' },
      icon(iconName),
      h('div', { class: 'toast-msg' }, message),
      action ? h('a', { class: 'toast-action', href: action.href, onclick: dismiss }, action.label) : null,
      h('button', { type: 'button', class: 'toast-close', 'aria-label': 'Dismiss notification', onclick: dismiss }, icon('x', 'icon-xs')));
    const host = $('#toasts');
    host.append(el);
    const all = $$('.toast', host);
    if (all.length > 4) all[0].remove();
    timer = setTimeout(dismiss, tone === 'error' ? 7000 : 4200);
  }

  /** Run `fn` with the given buttons in a busy state. `onError(err)` may return true when it handled the error. */
  async function withBusy(buttons, fn, onError) {
    const list = [buttons].flat().filter(Boolean);
    for (const b of list) {
      b.disabled = true;
      b.classList.add('is-busy');
      b.setAttribute('aria-busy', 'true');
      b.prepend(h('span', { class: 'spinner', 'aria-hidden': 'true' }));
    }
    try {
      return await fn();
    } catch (err) {
      if (onError && onError(err)) return undefined;
      if (err instanceof ApiError) {
        if (err.status !== 401) toast('error', err.message);
      } else {
        console.error(err);
        toast('error', err?.message || String(err));
      }
      return undefined;
    } finally {
      for (const b of list) {
        b.classList.remove('is-busy');
        b.removeAttribute('aria-busy');
        b.querySelector(':scope > .spinner')?.remove();
        b.disabled = false;
      }
      syncControls();
    }
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = h('textarea', { class: 'sr-only', readonly: true });
      ta.value = text;
      document.body.append(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    toast('success', 'Hash copied to clipboard.');
  }

  // ---------------------------------------------------------------- API
  class ApiError extends Error {
    constructor(status, code, message) {
      super(message);
      this.status = status;
      this.code = code;
    }
  }

  async function request(path, { method = 'GET', body } = {}) {
    const headers = { 'X-Sentinel-Token': TOKEN };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    let res;
    try {
      res = await fetch(path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        cache: 'no-store',
        credentials: 'same-origin',
      });
    } catch {
      noteFailure();
      throw new ApiError(0, 'network', 'Cannot reach the IP Sentinel server. Is it still running?');
    }
    noteSuccess();
    if (!res.ok) {
      let data = {};
      try { data = await res.json(); } catch { /* non-JSON error body */ }
      if (res.status === 401) setSessionExpired();
      throw new ApiError(res.status, data.code || 'error', data.error || `Request failed (${res.status})`);
    }
    return res;
  }

  const getJson = async (path, opts) => (await request(path, opts)).json();

  // ---------------------------------------------------------------- connection & polling
  function setConnection(conn) {
    if (app.conn === conn) return;
    app.conn = conn;
    const label = { connecting: 'Connecting…', online: 'Connected', reconnecting: 'Reconnecting…', offline: 'Disconnected' }[conn];
    $('#conn').dataset.state = conn;
    $('#connText').textContent = label;
    $('#conn').title = label;
    $('#liveIndicator').dataset.state = conn;
    $('#liveText').textContent = { online: 'Live', connecting: 'Connecting', reconnecting: 'Reconnecting', offline: 'Offline' }[conn];
  }

  function noteSuccess() {
    app.failures = 0;
    setConnection('online');
  }

  function noteFailure() {
    app.failures += 1;
    setConnection(app.failures >= 3 ? 'offline' : 'reconnecting');
  }

  function setSessionExpired() {
    if (app.sessionExpired) return;
    app.sessionExpired = true;
    clearTimeout(pollTimer);
    setConnection('offline');
    renderBanners();
  }

  async function refresh() {
    const [state, activity] = await Promise.all([getJson('/api/state'), getJson('/api/activity')]);
    applyState(state);
    applyActivity(activity.events || []);
  }

  const refreshQuiet = () => refresh().catch(() => {});

  function schedulePoll(ms) {
    clearTimeout(pollTimer);
    pollTimer = setTimeout(poll, ms);
  }

  async function poll() {
    if (app.sessionExpired) return;
    if (document.visibilityState !== 'visible') return; // resumed by visibilitychange
    try {
      await refresh();
      schedulePoll(POLL_MS);
    } catch {
      if (!app.sessionExpired) schedulePoll(Math.min(POLL_MS * 2 ** Math.max(app.failures - 1, 0), MAX_BACKOFF_MS));
    }
  }

  // ---------------------------------------------------------------- state application
  function integrityFlags(integrity) {
    const bad = new Set();
    const brokenBelow = new Set(); // block n whose link down to n-1 is broken
    const messages = new Map();
    for (const err of integrity?.errors || []) {
      const m = /^block (\d+):\s*(.*)$/.exec(err);
      if (!m) continue;
      const n = Number(m[1]);
      bad.add(n);
      messages.set(n, [...(messages.get(n) || []), m[2]]);
      if (err.includes('previous_block_hash')) brokenBelow.add(n);
      else brokenBelow.add(n + 1); // the newer block now points at contents that no longer match
    }
    return { bad, brokenBelow, messages };
  }

  function applyState(state) {
    const prev = app.state;
    app.state = state;

    if (app.scan && app.scan.workspace !== state.workspace) app.scan = null;

    if (prev) {
      if (prev.integrity.valid && !state.integrity.valid) {
        toast('error', `Integrity check failed: ${state.integrity.errors[0] || 'the ledger changed on disk'}`, { label: 'Verify', href: '#/verify' });
      } else if (!prev.integrity.valid && state.integrity.valid) {
        toast('success', 'Ledger integrity restored.');
      }
      if (JSON.stringify(prev.integrity) !== JSON.stringify(state.integrity)) app.blockCache.clear();
    }
    for (const [i, blk] of app.blockCache) {
      if (state.blocks[i]?.block_hash !== blk.block_hash) app.blockCache.delete(i);
    }
    renderAll();

    if (app.pendingReveal !== null) {
      const n = app.pendingReveal;
      app.pendingReveal = null;
      revealBlock(n);
    }
  }

  function applyActivity(events) {
    const last = app.activity.length ? app.activity[app.activity.length - 1].time : null;
    if (last && events.length && events[events.length - 1].time !== last) app.freshSince = last;
    app.activity = events;
    renderActivity();
    renderOverviewActivity();
  }

  // ---------------------------------------------------------------- rendering
  function renderAll() {
    renderChrome();
    renderBanners();
    renderOverview();
    renderWorkspace();
    renderChain();
    renderVerify();
    renderExport();
    syncControls();
  }

  function syncControls() {
    const s = app.state;
    const scanBtn = $('#scanBtn');
    if (!scanBtn.classList.contains('is-busy')) scanBtn.disabled = !s || !s.workspace || !s.workspace_exists;
    const exportBtn = $('#exportBtn');
    if (!exportBtn.classList.contains('is-busy')) exportBtn.disabled = !s || s.chain_length === 0;
  }

  function renderChrome() {
    const s = app.state;
    if (!s) return;

    // Integrity pill
    const pill = $('#integrityPill');
    let tone = 'ok';
    let iconName = 'check';
    let label = 'Chain intact';
    if (!s.integrity.valid) { tone = 'danger'; iconName = 'x'; label = 'Tampered'; }
    else if (s.chain_length === 0) { tone = 'neutral'; iconName = 'shield'; label = 'Empty ledger'; }
    if (changed('integrityPill', [tone, label, s.integrity.blocks_checked])) {
      pill.dataset.tone = tone;
      pill.title = s.integrity.valid ? `${plural(s.integrity.blocks_checked, 'block')} verified` : s.integrity.errors.join('\n');
      fill(pill, icon(iconName, 'icon-sm'), h('span', null, label));
    }

    // Workspace pill
    const wsPill = $('#wsPill');
    if (!s.workspace) {
      wsPill.dataset.tone = 'neutral';
      $('#wsPillText').textContent = 'No workspace';
      wsPill.title = 'Choose a workspace folder';
    } else {
      wsPill.dataset.tone = s.workspace_exists ? 'workspace' : 'warning';
      $('#wsPillText').textContent = s.workspace_exists ? s.workspace.split('/').filter(Boolean).pop() : 'Folder missing';
      wsPill.title = s.workspace;
    }

    // Sidebar
    const chainCount = $('#navCountChain');
    chainCount.hidden = s.chain_length === 0;
    chainCount.textContent = String(s.chain_length);
    $('#navCountVerify').hidden = s.integrity.valid;
    const storage = $('#storagePath');
    storage.textContent = `ledger ${shortPath(s.server.storage_dir)}`;
    storage.title = s.server.storage_dir;
  }

  function renderBanners() {
    const s = app.state;
    const items = [];
    if (app.sessionExpired) {
      items.push(h('div', { class: 'banner', role: 'alert' },
        icon('alert'),
        h('div', { class: 'banner-msg' }, h('strong', null, 'Session expired. '), 'The dashboard server restarted, so this page lost its access token.'),
        h('button', { type: 'button', class: 'btn btn-sm', onclick: () => location.reload() }, 'Reload')));
    } else if (TOKEN.startsWith('{{')) {
      items.push(h('div', { class: 'banner', role: 'alert' },
        icon('alert'),
        h('div', { class: 'banner-msg' }, h('strong', null, 'Not connected. '), 'Open this page through ', h('span', { class: 'mono' }, 'python3 sentinel_gui.py'), ', not from the file system.')));
    }
    if (s && !s.integrity.valid) {
      items.push(h('div', { class: 'banner', role: 'alert' },
        icon('alert'),
        h('div', { class: 'banner-msg' }, h('strong', null, 'Ledger integrity check failed: '), h('span', { class: 'mono' }, s.integrity.errors[0] || 'unknown error'),
          s.integrity.errors.length > 1 ? ` (+${s.integrity.errors.length - 1} more)` : ''),
        h('a', { class: 'btn btn-sm', href: '#/verify' }, 'Open Verify')));
    }
    if (changed('banners', [app.sessionExpired, s?.integrity])) fill($('#banners'), items);
  }

  // Overview -------------------------------------------------------------
  function renderOverview() {
    const s = app.state;
    if (!s) return;
    const last = s.last_commit;

    $('#statBlocks').textContent = s.chain_length.toLocaleString();
    fill($('#statBlocksSub'), s.chain_length ? ['Genesis ', timeEl(s.blocks[0].timestamp, 'relative')] : 'Nothing committed yet');

    $('#statFiles').textContent = s.files_in_head.toLocaleString();
    $('#statFilesSub').textContent = `${plural(s.files_ever_tracked, 'file')} ever tracked`;

    fill($('#statLast'), last ? timeEl(last.timestamp, 'relative') : 'Never');
    fill($('#statLastSub'), last ? [`Block #${last.index} · `, last.author] : 'Commit your first block');
    $('#statLastSub').title = last ? `${fmtDate(last.timestamp)} by ${last.author}` : '';

    const card = $('#statIntegrityCard');
    if (!s.integrity.valid) {
      card.dataset.tone = 'danger';
      $('#statIntegrity').textContent = 'FAIL';
      $('#statIntegritySub').textContent = plural(s.integrity.errors.length, 'problem') + ' found';
    } else {
      card.dataset.tone = s.chain_length ? 'ok' : '';
      $('#statIntegrity').textContent = s.chain_length ? 'PASS' : '—';
      $('#statIntegritySub').textContent = s.chain_length ? `${plural(s.integrity.blocks_checked, 'block')} verified` : 'Nothing to verify yet';
    }

    if (changed('headHash', [s.head_block_hash, s.chain_length])) {
      fill($('#headHash'), s.head_block_hash
        ? hashChip(s.head_block_hash, { large: true, label: 'Head block hash' })
        : h('p', { class: 'muted' }, 'No blocks yet. The head hash appears after your first commit.'));
      $('#headHashAside').textContent = s.chain_length ? `Block #${s.chain_length - 1}` : '';
    }

    renderOverviewWorkspace();
    renderOverviewBlocks();
  }

  function renderOverviewWorkspace() {
    const s = app.state;
    if (!changed('ovWorkspace', [s.workspace, s.workspace_exists])) return;
    const host = $('#ovWorkspace');
    if (!s.workspace) {
      const input = h('input', { class: 'input mono', type: 'text', placeholder: '/Users/you/Projects/battery-cell', 'aria-label': 'Workspace folder path', autocomplete: 'off', spellcheck: 'false' });
      const btn = h('button', { type: 'submit', class: 'btn btn-primary' }, 'Set workspace');
      const form = h('form', { class: 'ov-ws', novalidate: true },
        h('p', { class: 'muted' }, 'Choose the folder that holds your designs, drafts and notes.'),
        h('div', { class: 'input-row' }, input, btn));
      form.addEventListener('submit', (e) => { e.preventDefault(); setWorkspace(input.value, btn); });
      fill(host, form);
      return;
    }
    fill(host, h('div', { class: 'ov-ws' },
      h('div', { class: 'ov-ws-path' }, icon('folder', 'icon-sm'), h('span', null, s.workspace)),
      s.workspace_exists ? null : callout('warning', 'Folder not found', 'The workspace folder was moved or deleted. Choose another one.'),
      h('div', { class: 'ov-ws-actions' },
        h('button', { type: 'button', class: 'btn btn-primary', disabled: !s.workspace_exists, onclick: () => { location.hash = '#/workspace'; runScan(); } }, icon('scan'), 'Scan now'),
        h('a', { class: 'btn', href: '#/workspace' }, 'Change folder'))));
  }

  function renderOverviewBlocks() {
    const s = app.state;
    const flags = integrityFlags(s.integrity);
    if (!changed('ovBlocks', [s.blocks.map((b) => b.block_hash), [...flags.bad]])) return;
    const host = $('#ovBlocks');
    if (!s.blocks.length) {
      fill(host, emptyState('link', 'No blocks yet', 'Scan your workspace and commit the genesis block.',
        h('a', { class: 'btn btn-primary', href: '#/workspace' }, 'Go to workspace')));
      return;
    }
    const recent = s.blocks.slice(-5).reverse();
    fill(host, h('ol', { class: 'mini-chain' }, recent.map((b) => h('li', { class: flags.bad.has(b.index) ? 'mini-block is-bad' : 'mini-block' },
      h('a', { class: 'mini-node', href: `#/ledger/${b.index}`, 'aria-label': `Open block ${b.index}` }, String(b.index)),
      h('div', { class: 'mini-main' },
        h('div', { class: 'mini-title' }, b.index === 0 ? 'Genesis block' : `Block #${b.index}`, h('span', { class: 'muted' }, ` · ${plural(b.file_count, 'file')}`)),
        h('div', { class: 'mini-sub' }, timeEl(b.timestamp, 'relative'), ' · ', b.author)),
      hashChip(b.block_hash, { label: `Block ${b.index} hash` })))));
  }

  function renderOverviewActivity() {
    const recent = app.activity.slice(-6).reverse();
    if (!changed('ovActivity', recent.map((e) => e.time))) return;
    const host = $('#ovActivity');
    if (!recent.length) {
      fill(host, h('p', { class: 'muted' }, 'No activity yet.'));
      return;
    }
    fill(host, h('ul', { class: 'feed' }, recent.map((e) => h('li', null,
      timeEl(e.time, 'clock'),
      h('span', { class: `lvl lvl-${e.level}`, title: LEVEL_LABEL[e.level] || e.level }),
      h('span', { class: 'msg', title: e.message }, e.message)))));
  }

  // Workspace ------------------------------------------------------------
  function renderWorkspace() {
    const s = app.state;
    if (!s) return;
    const input = $('#wsInput');
    if (document.activeElement !== input && !app.wsDirty) input.value = s.workspace || '';
    renderScanAlert();
    renderScanArea();
  }

  function renderScanAlert() {
    const a = app.scanAlert;
    if (!changed('scanAlert', a ? [a.tone, a.title, a.message] : null)) return;
    if (!a) {
      fill($('#scanAlert'));
      return;
    }
    const actions = [];
    if (a.action?.href) actions.push(h('a', { class: 'btn btn-sm', href: a.action.href }, a.action.label));
    if (a.action?.run) actions.push(h('button', { type: 'button', class: 'btn btn-sm', onclick: a.action.run }, a.action.label));
    fill($('#scanAlert'), callout(a.tone, a.title, a.message, actions));
  }

  function renderScanArea() {
    const s = app.state;
    const scan = app.scan;
    const head = s.chain_length ? s.blocks[s.chain_length - 1] : null;
    const emptyHost = $('#scanEmpty');
    const results = $('#scanResults');
    const commitCard = $('#commitCard');

    if (changed('scanEmpty', [s.workspace, s.workspace_exists, Boolean(scan), head?.index ?? null])) {
      let content = null;
      if (!s.workspace) {
        content = emptyState('folder', 'Choose a folder to protect',
          'Enter the path of the folder that holds your designs, drafts and notes, then press Set workspace.');
      } else if (!s.workspace_exists) {
        content = callout('warning', 'Workspace folder not found', `${s.workspace} no longer exists. Choose another folder.`);
      } else if (!scan) {
        const scanCta = h('button', { type: 'button', class: 'btn btn-primary', onclick: () => runScan() }, icon('scan'), 'Scan workspace');
        content = emptyState('scan', 'Ready to scan',
          head ? `Scan to see what changed since block #${head.index} (${fmtDate(head.timestamp)}).` : 'Scan to list your files. Your first commit becomes the genesis block.',
          scanCta);
      }
      fill(emptyHost, content ? h('article', { class: 'card' }, content) : null);
    }

    results.hidden = !scan;
    commitCard.hidden = !scan || !scan.files.length;
    if (!scan) return;

    const sum = scan.summary;
    if (changed('scanSummary', [scan.scanned_at])) {
      fill($('#scanSummary'),
        h('div', { class: 'summary-item' }, h('span', { class: 'k' }, 'Files'), h('span', { class: 'v' }, sum.total.toLocaleString())),
        h('div', { class: 'summary-item' }, h('span', { class: 'k' }, 'Total size'), h('span', { class: 'v' }, fmtBytes(sum.total_bytes))),
        h('span', { class: 'summary-sep', 'aria-hidden': 'true' }),
        h('div', { class: 'summary-badges' },
          h('span', { class: 'badge badge-new' }, `${sum.new} new`),
          h('span', { class: 'badge badge-modified' }, `${sum.modified} modified`),
          h('span', { class: 'badge badge-unchanged' }, `${sum.unchanged} unchanged`)),
        h('span', { class: 'summary-meta' }, 'Scanned ', timeEl(scan.scanned_at, 'relative')));
    }

    for (const chip of $$('#scanFilters .chip')) {
      const f = chip.dataset.filter;
      chip.setAttribute('aria-pressed', String(f === app.scanFilter));
      $('.count', chip).textContent = String(f === 'all' ? sum.total : sum[f]);
    }

    const query = app.scanQuery.trim().toLowerCase();
    if (changed('scanTable', [scan.scanned_at, app.scanFilter, query])) {
      const files = scan.files.filter((f) => (app.scanFilter === 'all' || f.status === app.scanFilter)
        && (!query || f.relative_path.toLowerCase().includes(query)));
      fill($('#scanTable'), fileTable(files));
    }

    // Commit panel. The server refuses to extend a ledger that fails verification,
    // so say so up front instead of letting the user discover it after confirming.
    const n = scan.files.length;
    const tampered = !s.integrity.valid;
    $('#commitBtnText').textContent = `Commit ${plural(n, 'file')} to ledger`;
    $('#commitBtn').disabled = tampered;
    $('#commitHint').classList.toggle('is-danger', tampered);
    const nothingChanged = head && sum.new === 0 && sum.modified === 0;
    $('#commitHint').textContent = tampered
      ? 'Committing is disabled: the ledger failed its integrity check, and new blocks can’t be added on top of a tampered history. See the Verify page.'
      : nothingChanged
        ? `No changes since block #${head.index}. Committing records a fresh snapshot of the same files.`
        : head
          ? `Creates block #${head.index + 1}, linked to block #${head.index}.`
          : 'Creates the genesis block (#0) of your ledger.';
  }

  // Chain ----------------------------------------------------------------
  function renderChain() {
    const s = app.state;
    if (!s) return;
    if (!changed('chain', [s.blocks.map((b) => [b.block_hash, b.previous_block_hash, b.author, b.file_count]), s.integrity.errors])) return;
    const host = $('#chain');
    if (!s.blocks.length) {
      fill(host, h('li', null, h('article', { class: 'card' }, emptyState('link', 'The ledger is empty',
        'Scan your workspace and commit to create the genesis block. Every later block links to the one before it.',
        h('a', { class: 'btn btn-primary', href: '#/workspace' }, 'Go to workspace')))));
      return;
    }
    const flags = integrityFlags(s.integrity);
    const fresh = app.justCommitted && Date.now() - app.justCommitted.at < 4000 ? app.justCommitted.index : null;
    fill(host, [...s.blocks].reverse().map((b) => chainItem(b, flags, b.index === fresh)));
    for (const n of app.expanded) renderBlockBody(n);
  }

  function chainItem(b, flags, isNew) {
    const s = app.state;
    const isGenesis = b.index === 0;
    const isHead = b.index === s.chain_length - 1;
    const isBad = flags.bad.has(b.index);
    const linkBroken = flags.brokenBelow.has(b.index);
    const expanded = app.expanded.has(b.index);
    const cls = ['chain-item', isHead && 'is-head', isBad && 'is-bad', linkBroken && 'link-broken', isNew && 'is-new'].filter(Boolean).join(' ');
    const counts = b.counts || {};

    return h('li', { class: cls, id: `block-${b.index}`, dataset: { index: b.index } },
      h('div', { class: 'rail', 'aria-hidden': 'true' },
        h('span', { class: 'node' }, String(b.index)),
        h('span', { class: 'rail-line' }),
        h('span', { class: 'rail-break', title: 'Broken link' }, icon('x', 'icon-xs'))),
      h('article', { class: 'block-card' },
        h('button', {
          type: 'button',
          class: 'block-head',
          'aria-expanded': String(expanded),
          'aria-controls': `block-body-${b.index}`,
          onclick: () => toggleBlock(b.index),
        },
        h('div', { class: 'block-title' },
          h('span', { class: 'block-no' }, `Block #${b.index}`),
          isGenesis ? h('span', { class: 'tag' }, 'Genesis') : null,
          isHead ? h('span', { class: 'tag tag-accent' }, 'Head') : null,
          isBad ? h('span', { class: 'tag tag-danger' }, 'Tampered') : null),
        h('div', { class: 'block-meta' },
          timeEl(b.timestamp), h('span', { class: 'sep' }, '·'), timeEl(b.timestamp, 'relative'),
          h('span', { class: 'sep' }, '·'), h('span', null, b.author),
          h('span', { class: 'sep' }, '·'), h('span', null, plural(b.file_count, 'file'))),
        icon('chevron', 'chevron')),
        h('div', { class: 'block-badges' },
          ['new', 'modified', 'unchanged'].filter((k) => counts[k]).map((k) => h('span', { class: `badge badge-${k}` }, `${counts[k]} ${k}`))),
        h('dl', { class: 'block-hashes' },
          h('div', null,
            h('dt', null, 'Block hash'),
            h('dd', null, hashChip(b.block_hash, { label: `Block ${b.index} hash` }))),
          h('div', null,
            h('dt', null, isGenesis ? 'Genesis marker' : `Links to block #${b.index - 1}`),
            h('dd', null,
              hashChip(b.previous_block_hash, { label: `Block ${b.index} previous hash` }),
              linkBroken
                ? h('span', { class: 'link-state broken' }, icon('x', 'icon-xs'), 'Broken')
                : isGenesis ? null : h('span', { class: 'link-state ok' }, icon('check', 'icon-xs'), 'Linked')))),
        isBad ? h('ul', { class: 'block-errors' }, (flags.messages.get(b.index) || []).map((m) => h('li', null, m))) : null,
        h('div', { class: 'block-body', id: `block-body-${b.index}`, hidden: !expanded })));
  }

  async function toggleBlock(n, forceOpen = false) {
    const item = $(`#block-${n}`);
    const open = forceOpen || !app.expanded.has(n);
    if (open) app.expanded.add(n);
    else app.expanded.delete(n);
    if (item) {
      $('.block-head', item).setAttribute('aria-expanded', String(open));
      $('.block-body', item).hidden = !open;
    }
    if (open) await renderBlockBody(n);
  }

  async function renderBlockBody(n) {
    const body = $(`#block-body-${n}`);
    if (!body) return;
    body.hidden = false;
    const cached = app.blockCache.get(n);
    if (cached) {
      fill(body, fileTable(cached.entries));
      return;
    }
    fill(body, h('div', { class: 'block-loading' }, h('span', { class: 'spinner' }), 'Loading entries…'));
    try {
      const { block } = await getJson(`/api/blocks/${n}`);
      app.blockCache.set(n, block);
      const target = $(`#block-body-${n}`);
      if (target && app.expanded.has(n)) fill(target, fileTable(block.entries));
    } catch (err) {
      const target = $(`#block-body-${n}`);
      if (target) fill(target, h('div', { class: 'block-loading' }, icon('alert', 'icon-sm'), err.message));
    }
  }

  function revealBlock(n) {
    if (!app.state) { app.pendingReveal = n; return; }
    const item = $(`#block-${n}`);
    if (!item) return;
    toggleBlock(n, true);
    for (const el of $$('.chain-item.is-target')) el.classList.remove('is-target');
    item.classList.add('is-target');
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    requestAnimationFrame(() => item.scrollIntoView({ block: 'start', behavior: reduce ? 'auto' : 'smooth' }));
    setTimeout(() => item.classList.remove('is-target'), 2600);
  }

  // Verify ---------------------------------------------------------------
  function renderVerify() {
    const s = app.state;
    if (!s) return;
    if (changed('audit', [s.integrity, app.audit?.checked_at])) {
      const integrity = s.integrity;
      const tone = !integrity.valid ? 'danger' : s.chain_length ? 'ok' : 'neutral';
      const title = !integrity.valid
        ? `FAIL: ${plural(integrity.errors.length, 'problem')} found`
        : s.chain_length ? 'PASS: chain intact' : 'Nothing to verify yet';
      const sub = [];
      sub.push(`${plural(integrity.blocks_checked, 'block')} checked · re-checked live every ${POLL_MS / 1000}s`);
      if (app.audit) {
        sub.push(h('br'), `Last manual audit `, timeEl(app.audit.checked_at, 'relative'), `: ${app.audit.valid ? 'passed' : 'failed'}`);
      }
      const errors = integrity.errors.length
        ? h('ul', { class: 'audit-errors' }, integrity.errors.map((e) => {
          const m = /^block (\d+):/.exec(e);
          return h('li', null, m ? h('a', { href: `#/ledger/${m[1]}` }, `block ${m[1]}`) : null, m ? e.slice(m[0].length - 1) : e);
        }))
        : null;
      fill($('#auditResult'), h('div', { class: 'audit-result', 'data-tone': tone },
        h('span', { class: 'audit-mark' }, icon(tone === 'danger' ? 'x' : tone === 'ok' ? 'shield-check' : 'shield')),
        h('div', { style: null },
          h('div', { class: 'audit-title' }, title),
          h('div', { class: 'audit-sub' }, sub),
          errors)));
    }
    renderProofs();
  }

  function renderProofs() {
    const host = $('#proofResults');
    if (!changed('proofs', app.proofs.map((p) => [p.id, p.state]))) return;
    fill(host, app.proofs.map((p) => {
      let tone = 'neutral';
      let mark = h('span', { class: 'spinner' });
      let verdict;
      if (p.state === 'hashing') verdict = 'Hashing in your browser…';
      else if (p.state === 'looking') verdict = 'Searching the ledger…';
      else if (p.state === 'error') { tone = 'warning'; mark = icon('alert'); verdict = p.error; }
      else if (p.matches.length) {
        tone = 'ok';
        mark = icon('check');
        const first = p.matches[0];
        verdict = [
          h('strong', null, `Recorded in ${plural(p.matches.length, 'block')}. `),
          'First recorded in ', h('a', { href: `#/ledger/${first.block_index}` }, `block #${first.block_index}`),
          ' on ', timeEl(first.timestamp), ' as ', h('span', { class: 'mono' }, first.relative_path), '.',
        ];
      } else {
        tone = 'danger';
        mark = icon('x');
        verdict = [h('strong', null, 'Not found in the ledger. '), 'This exact content was never committed.'];
      }
      return h('div', { class: 'proof', 'data-tone': tone },
        h('span', { class: 'proof-mark' }, mark),
        h('div', null,
          h('div', { class: 'proof-top' },
            h('span', { class: 'proof-name' }, p.name),
            p.size !== null ? h('span', { class: 'proof-size' }, fmtBytes(p.size)) : null),
          p.hash ? h('div', { class: 'proof-hash' }, hashChip(p.hash, { label: p.name })) : null,
          h('div', { class: 'proof-verdict' }, verdict),
          p.matches?.length > 1
            ? h('div', { class: 'proof-blocks' }, p.matches.map((m) => h('a', { href: `#/ledger/${m.block_index}`, title: `${m.relative_path} · ${m.status}` }, `#${m.block_index}`)))
            : null));
    }));
  }

  // Export ---------------------------------------------------------------
  function renderExport() {
    const s = app.state;
    if (!s || !changed('export', [s.chain_length, s.head_block_hash, s.integrity.valid, s.files_in_head])) return;
    fill($('#exportMeta'),
      h('dt', null, 'Blocks'), h('dd', null, s.chain_length.toLocaleString()),
      h('dt', null, 'Head hash'), h('dd', null, hashChip(s.head_block_hash, { label: 'Head block hash' })),
      h('dt', null, 'Files in latest snapshot'), h('dd', null, s.files_in_head.toLocaleString()),
      h('dt', null, 'Integrity'), h('dd', null, s.integrity.valid
        ? h('span', { class: 'badge badge-success' }, s.chain_length ? 'Chain intact' : 'Empty')
        : h('span', { class: 'badge badge-error' }, 'Fails verification')));
    $('#exportHint').textContent = !s.chain_length
      ? 'Commit at least one block first.'
      : s.integrity.valid ? 'Generated fresh on each download.' : 'This ledger fails verification; the package will record that.';
  }

  // Activity -------------------------------------------------------------
  function renderActivity() {
    const counts = { all: app.activity.length, info: 0, success: 0, warning: 0, error: 0 };
    for (const e of app.activity) counts[e.level] = (counts[e.level] || 0) + 1;
    for (const chip of $$('#activityFilters .chip')) {
      const lvl = chip.dataset.level;
      chip.setAttribute('aria-pressed', String(lvl === app.activityFilter));
      $('.count', chip).textContent = String(counts[lvl] || 0);
    }
    const last = app.activity[app.activity.length - 1]?.time || null;
    if (!changed('activity', [app.activity.length, last, app.activityFilter])) return;
    const events = app.activity.filter((e) => app.activityFilter === 'all' || e.level === app.activityFilter).reverse();
    const host = $('#activityLog');
    if (!events.length) {
      fill(host, h('li', { class: 'data-empty' }, h('span', { class: 'muted' }, 'No events for this filter yet.')));
      return;
    }
    fill(host, events.map((e) => h('li', { class: app.freshSince && e.time > app.freshSince ? 'is-fresh' : null },
      timeEl(e.time, 'clock'),
      h('span', null, levelBadge(e.level)),
      h('span', { class: 'msg' }, e.message))));
  }

  // ---------------------------------------------------------------- actions
  async function setWorkspace(path, btn) {
    const value = (path || '').trim();
    if (!value) {
      toast('warning', 'Enter a folder path first.');
      return;
    }
    await withBusy(btn, async () => {
      const state = await getJson('/api/workspace', { method: 'POST', body: { path: value } });
      app.wsDirty = false;
      app.scan = null;
      app.scanAlert = null;
      $('#wsInput').value = state.workspace || '';
      applyState(state);
      toast('success', `Workspace set to ${state.workspace}`);
      refreshQuiet();
    });
  }

  async function runScan() {
    const buttons = [$('#scanBtn'), ...$$('#scanEmpty .btn-primary')];
    await withBusy(buttons, async () => {
      const result = await getJson('/api/scan', { method: 'POST' });
      app.scan = result;
      app.scanAlert = null;
      app.scanFilter = 'all';
      renderWorkspace();
      refreshQuiet();
    });
  }

  function openCommitDialog() {
    if (!app.scan || !app.state?.integrity.valid) return;
    const authorInput = $('#authorInput');
    const author = authorInput.value.trim();
    if (!author) {
      authorInput.setAttribute('aria-invalid', 'true');
      authorInput.focus();
      toast('warning', 'Add an author name so the block records who committed it.');
      return;
    }
    authorInput.removeAttribute('aria-invalid');
    const s = app.state;
    const head = s.chain_length ? s.blocks[s.chain_length - 1] : null;
    const sum = app.scan.summary;
    $('#commitDialogTitle').textContent = head ? `Commit block #${head.index + 1}?` : 'Commit the genesis block?';
    fill($('#commitDialogSummary'),
      h('dt', null, 'Files'), h('dd', null, `${sum.total.toLocaleString()} (${sum.new} new, ${sum.modified} modified, ${sum.unchanged} unchanged)`),
      h('dt', null, 'Author'), h('dd', null, author),
      h('dt', null, 'Links to'), h('dd', null, head ? hashChip(head.block_hash, { label: `Block ${head.index} hash` }) : 'Genesis marker (64 zeros)'));
    $('#commitDialog').showModal();
    $('#dlgConfirm').focus();
  }

  async function confirmCommit() {
    const dialog = $('#commitDialog');
    const author = $('#authorInput').value.trim();
    const expected = app.scan.files.map((f) => ({ relative_path: f.relative_path, sha256_hash: f.sha256_hash }));
    await withBusy($('#dlgConfirm'), async () => {
      const { block } = await getJson('/api/commit', { method: 'POST', body: { author, expected } });
      store.set('sentinel.author', author);
      dialog.close();
      app.scan = null;
      app.justCommitted = { index: block.index, at: Date.now() };
      app.scanAlert = {
        tone: 'success',
        title: `Block #${block.index} committed`,
        message: `${plural(block.file_count, 'file')} recorded by ${block.author}. Block hash ${block.block_hash.slice(0, 16)}…`,
        action: { label: `View block #${block.index}`, href: `#/ledger/${block.index}` },
      };
      toast('success', `Block #${block.index} committed to the ledger.`, { label: 'View', href: `#/ledger/${block.index}` });
      await refreshQuiet();
    }, (err) => {
      if (!(err instanceof ApiError)) return false;
      if (err.code === 'workspace_changed') {
        dialog.close();
        app.scanAlert = {
          tone: 'warning',
          title: 'Files changed since your scan',
          message: 'Nothing was committed. Rescan and review the changes before committing.',
          action: { label: 'Rescan', run: () => runScan() },
        };
        renderScanAlert();
        return true;
      }
      if (err.code === 'ledger_tampered') {
        dialog.close();
        app.scanAlert = {
          tone: 'danger',
          title: 'The ledger failed verification',
          message: 'New blocks can’t be added on top of a tampered ledger. Investigate on the Verify page.',
          action: { label: 'Open Verify', href: '#/verify' },
        };
        renderScanAlert();
        return true;
      }
      return false;
    });
  }

  async function runAudit(btn) {
    await withBusy(btn, async () => {
      const result = await getJson('/api/verify', { method: 'POST' });
      app.audit = result;
      if (result.valid) toast('success', `Audit passed: ${plural(result.blocks_checked, 'block')} verified.`);
      else toast('error', `Audit failed: ${result.errors[0]}`);
      await refreshQuiet();
      renderVerify();
    });
  }

  function hexDigest(buffer) {
    return Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, '0')).join('');
  }

  async function lookupProof(proof) {
    proof.state = 'looking';
    renderProofs();
    try {
      const res = await getJson(`/api/lookup?sha256=${encodeURIComponent(proof.hash)}`);
      proof.matches = res.matches;
      proof.state = 'done';
    } catch (err) {
      proof.state = 'error';
      proof.error = err.message;
    }
    renderProofs();
  }

  async function proveFiles(fileList) {
    const files = Array.from(fileList || []);
    if (!files.length) return;
    if (!window.crypto?.subtle) {
      toast('error', 'This browser cannot hash files here (Web Crypto is unavailable).');
      return;
    }
    for (const file of files) {
      const proof = { id: ++proofSeq, name: file.name, size: file.size, state: 'hashing', hash: null, matches: [] };
      app.proofs.unshift(proof);
      app.proofs = app.proofs.slice(0, 20);
      renderProofs();
      try {
        proof.hash = hexDigest(await crypto.subtle.digest('SHA-256', await file.arrayBuffer()));
      } catch (err) {
        proof.state = 'error';
        proof.error = `Could not read this file: ${err?.message || err}`;
        renderProofs();
        continue;
      }
      await lookupProof(proof);
    }
    refreshQuiet();
  }

  async function provePastedHash(raw) {
    const value = raw.trim().toLowerCase();
    const input = $('#hashInput');
    if (!/^[0-9a-f]{64}$/.test(value)) {
      input.setAttribute('aria-invalid', 'true');
      toast('warning', 'A SHA-256 hash is exactly 64 hexadecimal characters (0-9, a-f).');
      return;
    }
    input.removeAttribute('aria-invalid');
    const proof = { id: ++proofSeq, name: 'Pasted SHA-256', size: null, state: 'looking', hash: value, matches: [] };
    app.proofs.unshift(proof);
    app.proofs = app.proofs.slice(0, 20);
    await lookupProof(proof);
    input.value = '';
    refreshQuiet();
  }

  async function downloadPackage(btn) {
    await withBusy(btn, async () => {
      const res = await request('/api/export');
      const blob = await res.blob();
      const disposition = res.headers.get('Content-Disposition') || '';
      const name = /filename="([^"]+)"/.exec(disposition)?.[1] || 'ip-sentinel-proof.json';
      const url = URL.createObjectURL(blob);
      const a = h('a', { href: url, download: name, hidden: true });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
      toast('success', `Downloaded ${name}`);
      refreshQuiet();
    });
  }

  // ---------------------------------------------------------------- routing & drawer
  function currentRoute() {
    const m = /^#\/([a-z]+)(?:\/(\d+))?\/?$/.exec(location.hash);
    const name = m && ROUTES[m[1]] ? m[1] : 'overview';
    return { name, param: m && m[2] !== undefined && name === 'ledger' ? Number(m[2]) : null };
  }

  function onRoute() {
    const { name, param } = currentRoute();
    for (const sec of $$('[data-view]')) sec.hidden = sec.dataset.view !== name;
    document.body.dataset.route = name;
    for (const link of $$('.nav-link')) {
      if (link.dataset.route === name) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    }
    $('#viewTitle').textContent = ROUTES[name];
    document.title = `${ROUTES[name]} · IP Sentinel`;
    closeDrawer(false);
    if (param !== null) revealBlock(param);
    else window.scrollTo({ top: 0 });
  }

  function openDrawer() {
    $('#sidebar').classList.add('is-open');
    $('#backdrop').classList.add('is-open');
    $('#menuBtn').setAttribute('aria-expanded', 'true');
    setTimeout(() => $('.nav-link[aria-current="page"]', $('#sidebar'))?.focus(), 50);
  }

  function closeDrawer(returnFocus = true) {
    const sidebar = $('#sidebar');
    if (!sidebar.classList.contains('is-open')) return;
    sidebar.classList.remove('is-open');
    $('#backdrop').classList.remove('is-open');
    $('#menuBtn').setAttribute('aria-expanded', 'false');
    if (returnFocus) $('#menuBtn').focus();
  }

  // ---------------------------------------------------------------- theme
  const themeMedia = window.matchMedia('(prefers-color-scheme: light)');
  let themePref = store.get('sentinel.theme', 'dark');

  function applyTheme() {
    const resolved = themePref === 'system' ? (themeMedia.matches ? 'light' : 'dark') : themePref;
    document.documentElement.dataset.theme = resolved;
    for (const b of $$('[data-theme-choice]')) b.setAttribute('aria-pressed', String(b.dataset.themeChoice === themePref));
  }

  // ---------------------------------------------------------------- wiring
  function bind() {
    // Global: copy-on-click for every hash chip
    document.addEventListener('click', (e) => {
      const chip = e.target.closest('[data-copy]');
      if (chip) {
        e.preventDefault();
        copyText(chip.dataset.copy);
      }
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeDrawer();
    });

    window.addEventListener('hashchange', onRoute);
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible' && !app.sessionExpired) {
        clearTimeout(pollTimer);
        poll();
      }
    });

    $('#menuBtn').addEventListener('click', openDrawer);
    $('#backdrop').addEventListener('click', () => closeDrawer());

    for (const b of $$('[data-theme-choice]')) {
      b.addEventListener('click', () => {
        themePref = b.dataset.themeChoice;
        store.set('sentinel.theme', themePref);
        applyTheme();
      });
    }
    themeMedia.addEventListener?.('change', () => { if (themePref === 'system') applyTheme(); });

    // Workspace
    $('#wsInput').addEventListener('input', () => { app.wsDirty = true; });
    $('#wsForm').addEventListener('submit', (e) => {
      e.preventDefault();
      setWorkspace($('#wsInput').value, $('#wsSetBtn'));
    });
    $('#scanBtn').addEventListener('click', () => runScan());
    for (const chip of $$('#scanFilters .chip')) {
      chip.addEventListener('click', () => {
        app.scanFilter = chip.dataset.filter;
        renderScanArea();
      });
    }
    $('#scanSearch').addEventListener('input', (e) => {
      app.scanQuery = e.target.value;
      renderScanArea();
    });

    // Commit
    const authorInput = $('#authorInput');
    authorInput.value = store.get('sentinel.author', '');
    authorInput.addEventListener('input', () => authorInput.removeAttribute('aria-invalid'));
    $('#commitForm').addEventListener('submit', (e) => {
      e.preventDefault();
      openCommitDialog();
    });
    $('#dlgCancel').addEventListener('click', () => $('#commitDialog').close());
    $('#dlgConfirm').addEventListener('click', () => confirmCommit());
    $('#commitDialog').addEventListener('click', (e) => {
      if (e.target === e.currentTarget) e.currentTarget.close(); // click on backdrop
    });

    // Verify
    $('#auditBtn').addEventListener('click', (e) => runAudit(e.currentTarget));
    const dropzone = $('#dropzone');
    const fileInput = $('#fileInput');
    dropzone.addEventListener('click', () => fileInput.click());
    dropzone.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        fileInput.click();
      }
    });
    fileInput.addEventListener('change', () => {
      proveFiles(fileInput.files);
      fileInput.value = '';
    });
    for (const type of ['dragenter', 'dragover']) {
      dropzone.addEventListener(type, (e) => {
        e.preventDefault();
        dropzone.classList.add('is-over');
      });
    }
    for (const type of ['dragleave', 'dragend']) {
      dropzone.addEventListener(type, () => dropzone.classList.remove('is-over'));
    }
    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('is-over');
      proveFiles(e.dataTransfer?.files);
    });
    // Dropping a file anywhere else would navigate away from the dashboard.
    window.addEventListener('dragover', (e) => e.preventDefault());
    window.addEventListener('drop', (e) => e.preventDefault());
    $('#hashForm').addEventListener('submit', (e) => {
      e.preventDefault();
      provePastedHash($('#hashInput').value);
    });
    $('#hashInput').addEventListener('input', (e) => e.target.removeAttribute('aria-invalid'));

    // Export
    $('#exportBtn').addEventListener('click', (e) => downloadPackage(e.currentTarget));

    // Activity
    for (const chip of $$('#activityFilters .chip')) {
      chip.addEventListener('click', () => {
        app.activityFilter = chip.dataset.level;
        renderActivity();
      });
    }

    setInterval(refreshRelativeTimes, 30000);
  }

  function init() {
    applyTheme();
    $('#connHost').textContent = location.host;
    bind();
    onRoute();
    renderBanners();
    if (TOKEN.startsWith('{{')) {
      setConnection('offline');
      return;
    }
    poll();
  }

  init();
})();
