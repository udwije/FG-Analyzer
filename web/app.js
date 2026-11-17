const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const num = n => Number(n || 0).toLocaleString();
const short = n => n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? (n / 1e3).toFixed(n >= 1e4 ? 0 : 1) + 'k' : String(n);
const bytes = n => { if (!n) return '0 B'; const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++ } return `${n.toFixed(i ? 1 : 0)} ${u[i]}` };
const pc = (a, b) => b ? Math.round(100 * a / b) : 0;
// Signed out (session expired, password changed elsewhere): go to the sign-in page and come back here afterwards.
const _fetch = window.fetch.bind(window);
window.fetch = async (...a) => {
  const r = await _fetch(...a);
  if (r.status === 401 && !String(a[0]).includes('/api/login')) location.href = '/login.html?next=' + encodeURIComponent(location.pathname + location.hash);
  return r;
};
async function errText(r) { const t = (await r.text()).trim(); try { return JSON.parse(t).error || t } catch { return t || r.statusText } }
async function api(url, opt) { const r = await fetch(url, opt); if (!r.ok) throw new Error(await errText(r)); return r.json() }

// ------------------------------------------------------------ palette
const PAL = ['#0e7490', '#9aa5b1', '#c2417a', '#6d5bd0', '#0f9d8a', '#2f9e6e', '#e4572e', '#f59e0b'];
const RISK = { 5: ['Critical', '#b42318'], 4: ['High', '#e4572e'], 3: ['Elevated', '#f08a3c'], 2: ['Medium', '#f2b04a'], 1: ['Low', '#2f9e6e'] };
const RISKN = { critical: 5, high: 4, elevated: 3, medium: 2, low: 1 };
const riskPill = n => RISK[n] ? `<span class="rk"><i style="background:${RISK[n][1]}"></i>${RISK[n][0]}</span>` : '';
const isIP = v => /^[0-9a-f:.]+(\/\d+)?$/i.test(v) && /[.:]/.test(v);
const destKey = v => isIP(v) ? 'dst' : 'host';

// ------------------------------------------------------------ filter state
const FIELDS = [
  { k: 'user', l: 'User', dim: 'user', ph: 'alice, bob' },
  { k: 'src', l: 'Source IP', dim: 'src_ip', ph: '10.1.1.5, 10.2.0.0/16, !10.2.3.4' },
  { k: 'dst', l: 'Destination IP', dim: 'dst_ip', ph: '8.8.8.8, 1.1.1.0/24' },
  { k: 'host', l: 'Host / URL', dim: 'hostname', ph: '*.youtube.com' },
  { k: 'category', l: 'Category', dim: 'category', ph: 'Social' },
  { k: 'app', l: 'Application', dim: 'application', ph: 'Facebook' },
  { k: 'risk', l: 'App risk', dim: 'risk', ph: 'high' },
  { k: 'action', l: 'Action', dim: 'action', ph: 'blocked,block' },
  { k: 'fw', l: 'Firewall', dim: 'fw', ph: 'FG200G, FG90G' },
  { k: 'subtype', l: 'Subtype (exact)', dim: 'subtype', ph: 'webfilter' },
  { k: 'tool', l: 'AI tool', dim: 'tool', ph: 'ChatGPT' },
  { k: 'service', l: 'Service', dim: 'service', ph: 'HTTPS' },
  { k: 'policy', l: 'Policy', dim: 'policy', ph: 'LAN-to-WAN' },
  { k: 'level', l: 'Severity', dim: 'level', ph: 'warning' },
  { k: 'msg', l: 'Event message', dim: 'msg', ph: 'Admin login failed' },
];
const DEF = { range: '6', from: '', to: '', type: '', scope: '', outcome: '', q: '' };
FIELDS.forEach(f => DEF[f.k] = '');
const KEYS = Object.keys(DEF), PLAIN = ['action', 'outcome', 'subtype', 'type', 'scope'];
const AIV = ['dashboard', 'policy', 'investigate'];
// v5.10: which AI logs the AI tabs read. Security events (web filter + application control) by default; firewalls that only
// log traffic (no web filter or app control profile on the policy) need "traffic" or "all".
const AISRCS = [['ai', 'Security events', 'Web filter and application control events tagged as AI'], ['aitraffic', 'Traffic logs', 'Sessions to AI tools from the traffic log (has data volumes)'], ['aiall', 'All AI logs', 'Both: every log tagged with an AI tool']];
let AISRC = (() => { try { const v = localStorage.getItem('fortilog.aisrc'); return AISRCS.some(x => x[0] === v) ? v : 'ai' } catch { return 'ai' } })();
let ATTR = null, ATTRK = ''; // v5.13: traffic attribution (people / servers / unknown devices)
let F = { ...DEF }, view = 'global', page = 0, ctl = null, D = null, Dkey = '', INV = null, G = null, Gkey = '', lastRel = '24';

// Main periods. Anything longer (up to 90 days) is a custom From / To window.
const RANGES = [['1', 'Last hour'], ['6', 'Last 6 hours'], ['24', 'Last 24 hours'], ['168', 'Last 7 days'], ['custom', 'Custom range…']];
const opts = (list, sel) => list.map(([v, t]) => `<option value="${v}"${v === sel ? ' selected' : ''}>${t}</option>`).join('');
$('#frow').innerHTML =
  `<label>Range<select id="f-range">${opts(RANGES, F.range)}</select></label>
   <label class="cust">From<input type="datetime-local" id="f-from"></label><label class="cust">To<input type="datetime-local" id="f-to"></label>
   <label>Log type<select id="f-type">${opts([['', 'All types'], ['traffic', 'Traffic'], ['utm', 'Security (UTM)'], ['event', 'System events']], '')}</select></label>
   <label title="The AI tabs always show AI events">Scope<select id="f-scope">${opts([['', 'All logs'], ['ai', 'AI events'], ['aitraffic', 'AI traffic'], ['aiall', 'All AI logs']], '')}</select></label>
   <label>Outcome<select id="f-outcome">${opts([['', 'Any'], ['blocked', 'Blocked'], ['allowed', 'Allowed / monitored']], '')}</select></label>` +
  FIELDS.map(f => `<label>${f.l}<input id="f-${f.k}" placeholder="${esc(f.ph)}" autocomplete="off" list="dl-${f.k}"></label><datalist id="dl-${f.k}"></datalist>`).join('');
$('#rangeseg').innerHTML = [['1', '1 hour'], ['6', '6 hours'], ['24', '24 hours'], ['168', '7 days'], ['custom', 'Custom…']].map(([v, t]) => `<button data-r="${v}">${t}</button>`).join('');
const SPLIT = FIELDS.map(f => f.k).filter(k => !['msg', 'subtype'].includes(k)); // filters that take a list

const localInput = d => new Date(d - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
function toInputs() {
  KEYS.forEach(k => { const el = $('#f-' + k); if (el) el.value = F[k] });
  $$('.cust').forEach(x => x.hidden = F.range !== 'custom');
  $$('#rangeseg button').forEach(b => b.classList.toggle('on', b.dataset.r === F.range));
}
function fromInputs() {
  KEYS.forEach(k => { const el = $('#f-' + k); if (el) F[k] = el.value.trim() });
  if (F.range === 'custom' && (!F.from || !F.to)) { const n = new Date(); F.to = localInput(n); F.from = localInput(new Date(n - 864e5)) }
  if (F.range !== 'custom') lastRel = F.range;
}
function qs(extra = {}) {
  const p = new URLSearchParams(), ai = AIV.includes(view);
  if (F.range === 'custom' && F.from && F.to) { p.set('from', new Date(F.from).toISOString()); p.set('to', new Date(F.to).toISOString()) }
  else p.set('hours', F.range === 'custom' ? '24' : F.range);
  KEYS.forEach(k => { if (!['range', 'from', 'to'].includes(k) && F[k]) p.set(k, F[k]) });
  if (ai) p.set('scope', AISRC); // AI dashboards: the AI data source chosen in the AI bar
  if (view === 'advanced') p.set('view', 'all');
  Object.entries(extra).forEach(([k, v]) => p.set(k, v));
  return p;
}
function writeHash() {
  const p = new URLSearchParams();
  KEYS.forEach(k => { if (F[k] !== DEF[k]) p.set(k, F[k]) });
  if (view !== 'global') p.set('v', view);
  history.replaceState(null, '', '#' + p);
}
function readHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  KEYS.forEach(k => { if (p.has(k)) F[k] = p.get(k) });
  if (['dashboard', 'policy', 'investigate', 'mapping', 'devices', 'alerts', 'wan', 'sites', 'advanced', 'logs', 'reports', 'settings'].includes(p.get('v'))) view = p.get('v');
  if (!RANGES.some(r => r[0] === F.range)) F.range = '24'; // older links (3 or 30 days)
  if (F.range === 'custom' && (!F.from || !F.to)) F.range = '24';
  if (F.range !== 'custom') lastRel = F.range;
}
function renderChips() {
  const label = { type: 'Log type', scope: 'Scope', outcome: 'Outcome', q: 'Search', ...Object.fromEntries(FIELDS.map(f => [f.k, f.l.replace(' (exact)', '')])) };
  $('#chips').innerHTML = Object.keys(label).filter(k => F[k]).map(k => {
    const items = SPLIT.includes(k) ? listOf(F[k]) : [F[k]];
    return items.map((it, i) => {
      const neg = it.startsWith('!');
      return `<span class="chip${neg ? ' neg' : ''}">${esc(label[k])}${neg ? ' not' : ''}: <b>${esc(it.replace(/^!/, '').replace(/^=/, ''))}</b><button data-clear="${k}" data-item="${SPLIT.includes(k) ? i : ''}" title="Remove">&times;</button></span>`;
    }).join('');
  }).join('');
}
const listOf = v => String(v || '').split(',').map(x => x.trim()).filter(Boolean);
function apply(reset = true) { fromInputs(); if (reset) page = 0; toInputs(); writeHash(); renderChips(); refresh() }
// drill-down: include (=value) or exclude (!=value) from any chart, table row or detail field
// Ctrl+click (Cmd+click on a Mac) adds the value to the filter instead of replacing it: several IPs, users, apps...
function drill(k, v, exclude, addTo) {
  if (!v) return;
  if (PLAIN.includes(k)) {
    if (addTo && k === 'action' && F.action && !F.action.startsWith('!') && !exclude) F.action = [...new Set([...listOf(F.action), v])].join(',');
    else F[k] = (exclude && k === 'action' ? '!' : '') + v;
  } else {
    const item = (exclude ? '!=' : '=') + v;
    F[k] = addTo && SPLIT.includes(k) && F[k] ? [...listOf(F[k]).filter(x => x !== item), item].join(', ') : item;
  }
  toInputs(); apply();
}
function setCustom(a, b) { F.range = 'custom'; F.from = localInput(new Date(a * 1000)); F.to = localInput(new Date(b * 1000)); toInputs(); apply() }

$('#frow').addEventListener('change', e => { if (e.target.tagName === 'SELECT') apply() });
$('#frow').addEventListener('keydown', e => { if (e.key === 'Enter') apply() });
$('#f-q').addEventListener('keydown', e => { if (e.key === 'Enter') apply() });
document.addEventListener('keydown', e => { if (e.key === '/' && !/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName)) { e.preventDefault(); $('#f-q').focus() } });
$('#apply').onclick = () => apply();
$('#clear').onclick = () => { F = { ...DEF, range: lastRel }; toInputs(); apply() };
$('#chips').onclick = e => {
  const k = e.target.dataset.clear; if (!k) return;
  const i = e.target.dataset.item;
  if (i !== '' && i != null) { const l = listOf(F[k]); l.splice(+i, 1); F[k] = l.join(', ') } else F[k] = DEF[k];
  toInputs(); apply();
};
$('#togglefilters').onclick = () => { const h = $('#fpanel').hidden = !$('#fpanel').hidden; $('#togglefilters').setAttribute('aria-expanded', String(!h)) };
$('#rangeseg').onclick = e => {
  const r = e.target.dataset.r; if (!r) return;
  if (r === 'custom') { // open the From / To boxes; nothing is loaded until Apply
    F.range = 'custom';
    if (!F.from || !F.to) { const n = new Date(); F.to = localInput(n); F.from = localInput(new Date(n - 30 * 864e5)) }
    toInputs(); $('#fpanel').hidden = false; $('#togglefilters').setAttribute('aria-expanded', 'true'); $('#f-from').focus(); return;
  }
  F.range = r; F.from = F.to = ''; toInputs(); apply();
};
$('#prevp').onclick = () => shift(-1); $('#nextp').onclick = () => shift(1);
$('#latest').onclick = () => { F.range = lastRel; F.from = F.to = ''; toInputs(); apply() };
function shift(dir) { const X = PER; if (!X) return; const a = new Date(X.from) / 1000, b = Math.min(new Date(X.to) / 1000, Date.now() / 1000), span = b - a; setCustom(a + dir * span, b + dir * span) }

const facetCache = new Map();
$('#frow').addEventListener('focusin', async e => {
  const f = FIELDS.find(x => 'f-' + x.k === e.target.id); if (!f) return;
  const p = qs(); [...p.keys()].forEach(k => { if (!['hours', 'from', 'to', 'type', 'scope'].includes(k)) p.delete(k) }); p.set('field', f.dim);
  const key = p.toString(), hit = facetCache.get(key);
  let rows = hit && Date.now() - hit.t < 3e5 ? hit.rows : null;
  if (!rows) { try { rows = await api('/api/facets?' + key); facetCache.set(key, { t: Date.now(), rows }) } catch { return } }
  $('#dl-' + f.k).innerHTML = rows.map(r => `<option value="${esc(r.name)}">${num(r.count)} events</option>`).join('');
});

const store = { get() { try { return JSON.parse(localStorage.getItem('fortilog.views') || '{}') } catch { return {} } }, set(v) { try { localStorage.setItem('fortilog.views', JSON.stringify(v)) } catch { } } };
function renderViews() { $('#views').innerHTML = '<option value="">Saved views…</option>' + Object.keys(store.get()).map(n => `<option>${esc(n)}</option>`).join('') }
$('#saveview').onclick = () => { const n = prompt('Name this view'); if (!n) return; fromInputs(); const v = store.get(); v[n] = { ...F }; store.set(v); renderViews(); $('#views').value = n };
$('#delview').onclick = () => { const n = $('#views').value; if (!n) return; const v = store.get(); delete v[n]; store.set(v); renderViews() };
$('#views').onchange = () => { const v = store.get()[$('#views').value]; if (v) { F = { ...DEF, ...v }; toInputs(); apply() } };

// one delegated handler: anything with data-k / data-v filters the whole dashboard
document.addEventListener('click', e => {
  if (e.target.closest('#drawer, #frow, #fpanel, #chips')) return;
  const t = e.target.closest('[data-k][data-v]'); if (!t || t.dataset.v === '') return;
  drill(t.dataset.k, t.dataset.v, e.shiftKey || e.target.classList.contains('x'), e.ctrlKey || e.metaKey);
});

// ------------------------------------------------------------ small chart helpers
function spark(vals, w = 120, h = 28, color = '#0e7490') {
  if (!vals || !vals.length) return '';
  const n = Math.min(30, vals.length), k = vals.length / n, v = Array.from({ length: n }, (_, i) => vals.slice(Math.floor(i * k), Math.floor((i + 1) * k) || undefined).reduce((a, b) => a + b, 0));
  const mx = Math.max(1, ...v), pts = v.map((y, i) => `${(i * w / Math.max(1, n - 1)).toFixed(1)},${(h - 2 - y / mx * (h - 4)).toFixed(1)}`);
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"><polyline fill="none" stroke="${color}" stroke-width="1.6" points="${pts.join(' ')}"/></svg>`;
}
function ring(p, color, label, sub) {
  return `<div class="ring"><svg viewBox="0 0 36 36"><circle cx="18" cy="18" r="15.9" fill="none" stroke="#e1e8ee" stroke-width="4"/><circle cx="18" cy="18" r="15.9" fill="none" stroke="${color}" stroke-width="4" pathLength="100" stroke-dasharray="${p} ${100 - p}" transform="rotate(-90 18 18)"/><text x="18" y="21" text-anchor="middle">${p}%</text></svg><div><b>${label}</b><small>${sub}</small></div></div>`;
}
function donut(parts, centre, sub) {
  const tot = parts.reduce((a, p) => a + p.value, 0) || 1, S = 210, R = 100, r = 62, c = S / 2; let a = -Math.PI / 2, paths = '';
  parts.forEach(p => {
    if (!p.value) return; const f = p.value / tot, b = a + f * 2 * Math.PI, big = f > .5 ? 1 : 0, P = (rad, ang) => `${(c + rad * Math.cos(ang)).toFixed(2)} ${(c + rad * Math.sin(ang)).toFixed(2)}`;
    const attrs = p.k ? ` data-k="${p.k}" data-v="${esc(p.v)}"` : '';
    paths += f > .9999 ? `<circle cx="${c}" cy="${c}" r="${(R + r) / 2}" fill="none" stroke="${p.color}" stroke-width="${R - r}"${attrs}/>`
      : `<path d="M${P(R, a)} A${R} ${R} 0 ${big} 1 ${P(R, b)} L${P(r, b)} A${r} ${r} 0 ${big} 0 ${P(r, a)}Z" fill="${p.color}"${attrs}><title>${esc(p.name)}: ${num(p.value)}</title></path>`;
    a = b;
  });
  return `<svg viewBox="0 0 ${S} ${S}">${paths}<text x="${c}" y="${c + 4}" font-size="26" font-family="var(--serif)" font-weight="600" fill="currentColor">${esc(centre)}</text><text x="${c}" y="${c + 22}" font-size="12" fill="#5d7083">${esc(sub)}</text></svg>
  <div class="dleg">${parts.map(p => `<div${p.k ? ` data-k="${p.k}" data-v="${esc(p.v)}"` : ''}><i style="background:${p.color}"></i>${esc(p.name)} (${pc(p.value, tot)}%)</div>`).join('')}</div>`;
}
function bars(rows, o = {}) {
  const val = o.bytes ? 'bytes' : 'count', max = Math.max(1, ...(rows || []).map(x => x[val]));
  return (rows || []).map(x => {
    const k = typeof o.key === 'function' ? o.key(x.name) : o.key;
    return `<div class="barrow${k ? '' : ' nok'}"${k ? ` data-k="${k}" data-v="${esc(x.name)}"` : ''}><div class="barname" title="${esc(x.name)}">${esc(x.name)}</div>
    <div class="track"><div class="fill" style="width:${Math.max(1.5, 100 * x[val] / max)}%${o.color ? `;background:${o.color(x)}` : ''}">${o.bytes || o.color ? '' : `<div class="blk" style="width:${pc(x.blocked, x.count)}%"></div>`}</div></div>
    <b title="${num(x.blocked)} blocked">${o.bytes ? bytes(x.bytes) : short(x.count)}</b>${k ? '<button class="x" title="Exclude">&minus;</button>' : '<span></span>'}</div>`;
  }).join('') || '<span class="muted">No data for this filter</span>';
}
const table = (head, rows, empty = 'No data for this filter') => rows.length ? `<table><thead><tr>${head.map(h => `<th${h[1] ? ' class="n"' : ''}>${h[0]}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>` : `<span class="muted">${empty}</span>`;
function delta(c, p, goodUp) {
  if (!p) return `<span class="dl">${c ? 'no previous data' : 'no change'}</span>`;
  const x = (c - p) / p * 100; if (Math.abs(x) < .5) return '<span class="dl">no change vs previous period</span>';
  const cls = goodUp == null ? '' : (x > 0) === goodUp ? 'gd' : 'bd';
  const m = Math.abs(x) > 999 ? '>999' : Math.abs(x).toFixed(0);
  return `<span class="dl ${cls}">${x > 0 ? '▲' : '▼'} ${m}% vs previous period</span>`;
}
function kpi(l, v, n, dl, sp, k, val) { return `<div class="tile"${k ? ` data-k="${k}" data-v="${val}"` : ''}><div class="l">${l}</div><div class="v">${v}</div><div class="n">${n}</div>${dl || ''}${sp || ''}</div>` }

// stacked allowed/blocked timeline with hover tooltip and drag-to-zoom
function timeline(d, el) {
  const S = d.series || [], step = d.step;
  const t0 = d.origin != null ? +d.origin : Math.floor(new Date(d.from) / 1000 / step) * step, t1 = Math.ceil((new Date(d.to) / 1000 - t0) / step) * step + t0;
  const n = Math.max(1, Math.min(700, Math.round((t1 - t0) / step))), tot = Array(n).fill(0), blk = Array(n).fill(0);
  S.forEach(b => { const i = Math.floor((b.t - t0) / step); if (i >= 0 && i < n) { tot[i] = b.total; blk[i] = b.blocked } });
  const W = Math.max(320, Math.round(el.clientWidth) || 1000), H = 230, L = 46, R = 8, T = 10, B = 26, pw = W - L - R, ph = H - T - B, bw = pw / n;
  const mx = Math.max(1, ...tot), p = 10 ** Math.floor(Math.log10(mx)), nm = Math.ceil(mx / p * 2) / 2 * p, span = t1 - t0;
  const fmt = s => { const dt = new Date(s * 1000), tm = dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); return span > 36 * 3600 ? dt.toLocaleDateString([], { month: 'short', day: 'numeric' }) + (span <= 7 * 86400 ? ' ' + tm : '') : tm };
  let g = '';
  [0, .5, 1].forEach(f => { const y = T + ph - f * ph; g += `<line x1="${L}" x2="${W - R}" y1="${y}" y2="${y}" class="grid"/><text x="${L - 6}" y="${y + 4}" text-anchor="end">${short(Math.round(nm * f))}</text>` });
  const NT = W < 600 ? 3 : 6; for (let i = 0; i <= NT; i++) { const idx = Math.round(i * (n - 1) / NT); g += `<text x="${L + idx * bw + bw / 2}" y="${H - 8}" text-anchor="${i === 0 ? 'start' : i === NT ? 'end' : 'middle'}">${fmt(t0 + idx * step)}</text>` }
  let bs = '';
  for (let i = 0; i < n; i++) {
    if (!tot[i]) continue; const x = L + i * bw, w = Math.max(1, bw - 1), ht = tot[i] / nm * ph, hb = blk[i] / nm * ph;
    bs += `<rect x="${x}" y="${T + ph - ht}" width="${w}" height="${ht - hb}" class="allowed"/>` + (hb ? `<rect x="${x}" y="${T + ph - hb}" width="${w}" height="${hb}" class="blocked"/>` : '');
  }
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}">${g}${bs}<rect class="sel" y="${T}" height="${ph}" width="0"/><rect class="ov" x="${L}" y="${T}" width="${pw}" height="${ph}" fill="transparent"/></svg><div class="tip2" hidden></div>`;
  const svg = el.firstChild, ov = el.querySelector('.ov'), sel = el.querySelector('.sel'), tip = el.querySelector('.tip2');
  const at = e => { const r = svg.getBoundingClientRect(); return Math.max(0, Math.min(n - 1, Math.floor(((e.clientX - r.left) / r.width * W - L) / bw))) };
  let a = null; const drawSel = (i, j) => { const lo = Math.min(i, j), hi = Math.max(i, j); sel.setAttribute('x', L + lo * bw); sel.setAttribute('width', (hi - lo + 1) * bw) };
  ov.onmousedown = e => { a = at(e); drawSel(a, a); e.preventDefault() };
  ov.onmousemove = e => { const i = at(e); if (a !== null) drawSel(a, i); const r = el.getBoundingClientRect(); tip.hidden = false; tip.style.left = Math.min(e.clientX - r.left + 12, r.width - 190) + 'px'; tip.innerHTML = `<b>${new Date((t0 + i * step) * 1000).toLocaleString()}</b><br>${num(tot[i])} events · <span class="rd">${num(blk[i])} blocked</span>` };
  ov.onmouseleave = () => { tip.hidden = true; a = null; sel.setAttribute('width', 0) };
  ov.onmouseup = e => { const i = at(e), s = a; a = null; sel.setAttribute('width', 0); if (s !== null && s !== i) setCustom(t0 + Math.min(s, i) * step, t0 + (Math.max(s, i) + 1) * step) };
}

// ------------------------------------------------------------ period bar (shared by every analysis view)
const fd = (s, o) => new Date(s).toLocaleDateString([], o);
let PER = null; // whatever the current view loaded: {from, to, ...}
// mini: [[value, label]...]; bar: {k, items:[{name,count}]}
function renderPeriod(X, mini, bar) {
  PER = X; if (!X) return;
  const a = new Date(X.from), b = new Date(X.to), long = (b - a) > 36 * 36e5, f = () => long ? fd(a, { day: 'numeric', month: 'short', year: 'numeric' }) : a.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
  const rel = F.range !== 'custom';
  $('#plabel').innerHTML = `<b>${rel ? RANGES.find(r => r[0] === F.range)[1] : (long ? fd(a, { day: 'numeric', month: 'short' }) + ' – ' + fd(b, { day: 'numeric', month: 'short', year: 'numeric' }) : f())}</b><small>${rel ? 'Compared with the period before' : 'Custom window'}</small>`;
  $('#nextp').disabled = rel;
  $('#mini').innerHTML = mini.map(([v, l]) => `<div><b>${v}</b><small>${l}</small></div>`).join('');
  const items = bar ? bar.items || [] : [], tot = items.reduce((s, c) => s + c.count, 0) || 1;
  $('#catbar').hidden = $('#catlegend').hidden = !items.length;
  $('#catbar').innerHTML = items.map((c, i) => `<i style="width:${100 * c.count / tot}%;background:${PAL[i % 8]}" data-k="${bar.k}" data-v="${esc(c.name)}" title="${esc(c.label || c.name)}"></i>`).join('');
  $('#catlegend').innerHTML = items.map((c, i) => `<span data-k="${bar.k}" data-v="${esc(c.name)}"><i style="background:${PAL[i % 8]}"></i>${esc(c.label || c.name)} <b>${pc(c.count, tot)}%</b></span>`).join('');
}
const aiPeriod = () => renderPeriod(D, [[num(D.total), 'AI events'], [num(D.usersGroups), 'People'], [num(D.sourcesGroups), 'Source IPs'], [D.apps[0] ? esc(D.apps[0].name) : '–', 'Top AI tool']], { k: 'category', items: D.category });

// ------------------------------------------------------------ All logs (global)
const TYPEL = { traffic: 'Traffic', utm: 'Security (UTM)', event: 'System events' };
const SEVC = { emergency: '#7a1010', alert: '#b42318', critical: '#b42318', error: '#e4572e', warning: '#f08a3c', notice: '#f2b04a', information: '#0e7490', debug: '#9aa5b1' };
// ranked list: rank, name, bar (red part = blocked), value, share. o.key = filter key (or function of the name);
// o.val = 'count' | 'bytes' | 'sent'; o.color = bar colour; o.total = for the share column.
function rlist(rows, o = {}) {
  rows = rows || []; const val = o.val || 'count', max = Math.max(1, ...rows.map(x => x[val] || 0));
  const fmt = val === 'count' ? num : bytes;
  return rows.length ? `<ol class="rl">${rows.map((x, i) => {
    const k = typeof o.key === 'function' ? o.key(x.name) : o.key, w = Math.max(1.5, 100 * (x[val] || 0) / max);
    const bl = val === 'count' && !o.color ? pc(x.blocked, x.count) : 0;
    return `<li${k ? ` data-k="${k}" data-v="${esc(x.name)}"` : ' class="nok"'} title="${esc(x.name)} · ${num(x.count)} events${x.blocked ? ' · ' + num(x.blocked) + ' blocked' : ''}">
      <span class="ri">${i + 1}</span><span class="rn">${esc(o.label ? o.label(x.name) : x.name)}</span>
      <span class="rb"><i style="width:${w}%${o.color ? ';background:' + o.color : ''}">${bl ? `<em style="width:${bl}%"></em>` : ''}</i></span>
      <b>${fmt(x[val] || 0)}</b>${o.total ? `<small>${pc(x[val] || 0, o.total)}%</small>` : ''}${k ? '<button class="x" title="Exclude (or Shift+click)">&minus;</button>' : ''}</li>`;
  }).join('')}</ol>` : '<span class="muted">No data for this filter</span>';
}

// All logs: one compact summary row, the timeline next to the firewalls, then four rows of four ranked lists.
function renderGlobal() {
  const X = G, P = X.prev || {}, tot = X.total || 1, fws = mergeFirewalls(X), live = fws.filter(f => f.state === 'live').length;
  const down = Math.max(0, (X.bytes || 0) - (X.sent || 0)), up = X.sent || 0, zt = zoneTotals(X);
  // "Right now": the newest COMPLETE bucket (the current one is still filling and would show a fraction of the rate)
  const nowS = Date.now() / 1000, done = X.series.filter(b => b.t + X.step <= nowS), last = done.length ? done[done.length - 1] : null, perMin = last ? Math.round(last.total / (X.step / 60)) : 0;
  renderPeriod(X, [[num(X.total), 'Events'], [`${live}/${fws.length}`, 'Firewalls live'], [num(X.sourcesGroups), 'Source IPs'], [pc(X.userKnown, X.total) + '%', 'User known']],
    { k: 'type', items: (X.types || []).map(t => ({ ...t, label: TYPEL[t.name] || t.name })) });
  const sm = G.summaries || {}, lf = X.listsFrom ? new Date(X.listsFrom) : null;
  $('#gheadline').innerHTML = X.mode === 'summary'
    ? `<span class="mode ok">Fast summaries</span> Top lists count from ${lf ? lf.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : 'the hour'}, refreshed every 5 minutes; totals and the chart every minute. Add any filter other than firewall or log type for exact raw-log detail.`
    : `<span class="mode">Raw logs</span> Exact detail from every log line${(new Date(X.to) - new Date(X.from)) < 3 * 36e5 ? ' (periods under 3 hours)' : ''}.${!sm.complete && sm.covered_from ? ` Summaries are being built back to ${new Date(sm.covered_from * 1000).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })}; longer periods get fast once they are done.` : ''}`;
  const k = (l, v, n, d, cls = '', kk, kv) => `<div class="kp ${cls}"${kk ? ` data-k="${kk}" data-v="${kv}"` : ''}><small>${l}</small><b>${v}</b><span>${n}</span>${d || ''}</div>`;
  $('#gkpis').innerHTML =
    k('Events', short(X.total), 'all log types', delta(X.total, P.total, null)) +
    k('Right now', num(perMin) + '/min', 'last complete ' + (X.step >= 3600 ? (X.step / 3600) + ' h' : (X.step / 60) + ' min')) +
    k('Blocked or denied', short(X.blocked), pc(X.blocked, X.total) + '% of events', delta(X.blocked, P.blocked, null), 'red', 'outcome', 'blocked') +
    (zt.has ? k('Internet ↓', bytes(zt.inetDown), 'downloaded from the internet', '', 'teal') + k('Internet ↑', bytes(zt.inetUp), 'uploaded to the internet', '', 'violet') +
      k('Internal only', bytes(zt.internal), `LAN to LAN · ${pc(zt.internal, X.bytes)}% of all data`, '', 'brown')
      : k('Download', bytes(down), 'data received', '', 'teal') + k('Upload', bytes(up), 'data sent out', '', 'violet')) +
    k('Firewalls', `${live} / ${fws.length}`, live < fws.length ? 'some are quiet' : 'all sending', '', live < fws.length ? 'warn' : 'ok') +
    k('Source IPs', num(X.sourcesGroups), 'distinct') + k('People', num(ATTR && ATTR.people != null ? ATTR.people : X.usersGroups), ATTR && ATTR.staff_list ? 'staff seen (verified)' : 'distinct usernames') +
    k('User known', pc(X.userKnown, X.total) + '%', `${pc(X.userNPS, X.total)}% from NPS`);
  timeline(X, $('#gtimeline'));
  const ST = { live: '<i class="sd ok"></i>', quiet: '<i class="sd bad"></i>', none: '<i class="sd"></i>' };
  $('#gfw').innerHTML = fws.length ? `<table class="fwt"><thead><tr><th>Firewall</th><th class="n">Events</th><th class="n">Share</th><th class="n">Blocked</th><th>Last log</th></tr></thead><tbody>${fws.map(f =>
    `<tr${f.count ? ` data-k="fw" data-v="${esc(f.name)}"` : ''} title="${esc(f.ip || '')}"><td>${ST[f.state]}<b>${esc(f.name)}</b></td><td class="n">${short(f.count)}</td><td class="n">${pc(f.count, tot)}%</td><td class="n">${pc(f.blocked, f.count)}%</td><td>${f.lastTxt}</td></tr>`).join('')}</tbody></table>`
    : '<span class="muted">No firewall has sent logs yet.</span>';
  const tt = X.types || [], ttot = tt.reduce((a, t) => a + t.count, 0) || 1;
  $('#gtypes').innerHTML = `<div class="catbar big">${tt.map((t, i) => `<i style="width:${100 * t.count / ttot}%;background:${PAL[i % 8]}" data-k="type" data-v="${esc(t.name)}" title="${esc(TYPEL[t.name] || t.name)}"></i>`).join('')}</div>
    <div class="clegend">${tt.map((t, i) => `<span data-k="type" data-v="${esc(t.name)}"><i style="background:${PAL[i % 8]}"></i>${esc(TYPEL[t.name] || t.name)} <b>${pc(t.count, ttot)}%</b> ${short(t.count)}</span>`).join('')}</div>` +
    rlist((X.subtypes || []).slice(0, 8), { key: 'subtype', total: tot });
  $('#glevels').innerHTML = rlist(X.levels, { key: 'level', total: tot });
  $('#gactions').innerHTML = rlist(X.actions, { key: 'action', total: tot });
  $('#gusernote').textContent = X.userKnown < X.total ? `${pc(X.total - X.userKnown, X.total)}% of events have no username` : '';
  $('#gsources').innerHTML = rlist(X.sources, { key: 'src', total: tot });
  $('#gusers').innerHTML = rlist(X.users, { key: 'user', total: tot });
  $('#gdests').innerHTML = rlist(X.dests, { key: destKey, total: tot });
  $('#gapps').innerHTML = rlist(X.apps, { key: 'app', total: tot });
  $('#gmblocked').innerHTML = rlist(X.mostBlocked, { key: destKey, color: '#e4572e' });
  $('#gbsources').innerHTML = rlist(X.blockedSources, { key: 'src', color: '#e4572e' });
  $('#gpolicies').innerHTML = rlist(X.policies, { key: 'policy', total: tot });
  $('#gservices').innerHTML = rlist(X.services, { key: 'service', total: tot });
  // v5.12: internet traffic only (internal backups and file shares made these lists misleading); download and upload apart
  const inet = (l, all) => (l || []).length ? [l, true] : [all, false];
  const [wd, wi] = inet(X.whereInet, X.whereData), [ul, ui] = inet(X.uploadersInet, X.uploaders);
  $('#gwheredata').innerHTML = rlistUD(wd, destKey); $('#gwherenote').textContent = wi ? 'Internet destinations (outbound)' : 'All destinations';
  $('#guploaders').innerHTML = rlistUD(ul, 'src', 'sent'); $('#gupnote').textContent = ui ? 'Your devices, data sent to the internet' : 'Devices by data sent (all traffic)';
  // "Reserved" is FortiGate's country for private addresses: internal traffic, not a destination country
  $('#gcountries').innerHTML = rlist((X.countries || []).filter(c => c.name !== 'Reserved'), { val: 'bytes', color: '#0f9d8a' });
  $('#gai').innerHTML = rlist(X.aiTools, { key: 'tool', color: '#c2417a' }) + ((X.aiTools || []).length ? '<p class="hint" style="margin-top:8px"><a href="#" id="goai">Open the AI overview</a></p>' : '');
  if ($('#goai')) $('#goai').onclick = e => { e.preventDefault(); setView('dashboard') };
  const mt = (X.messages || []).reduce((a, m) => a + m.count, 0) || 1;
  $('#gmsgs').innerHTML = X.messages ? rlist(X.messages, { key: 'msg', total: mt }) : '<span class="muted">Clear the log type filter to see system events.</span>';
  renderGlobalMore(X);
}
// one row per firewall: events in the period (by name) + live status from the collector (by sending IP)
function mergeFirewalls(X) {
  const rows = new Map();
  (X.firewalls || []).forEach(f => rows.set(f.name, { ...f }));
  (X.collectors || []).forEach(c => {
    let r = rows.get(c.name) || [...rows.values()].find(x => x.name === c.ip);
    if (!r && c.configured) { r = { name: c.name, count: 0, blocked: 0, bytes: 0 }; rows.set(c.name, r) }
    if (r) { r.ip = c.ip; r.recv = c.last }
  });
  return [...rows.values()].map(r => {
    const lastEv = r.last ? new Date(r.last) / 1000 : 0, last = Math.max(r.recv || 0, lastEv);
    r.lastTxt = last ? ago(last) : 'never';
    r.state = !last ? 'none' : Date.now() / 1000 - last < 600 ? 'live' : 'quiet';
    return r;
  }).sort((a, b) => b.count - a.count);
}

// ------------------------------------------------------------ Overview
function renderOverview() {
  const P = D.prev || {}, ac = D.appctrl, top = D.apps[0], series = D.series.map(s => s.total), blk = D.series.map(s => s.blocked);
  const sent = (D.aiToolData || []).reduce((s, x) => s + x.sent, 0), newT = (D.toolUsage || []).filter(t => t.isNew);
  $('#headline').innerHTML = `<div><p>${num(D.total)} AI events from ${num(D.usersGroups)} people on ${num(D.sourcesGroups)} devices.${top ? ` ${esc(top.name)} is the most used AI tool with ${pc(top.count, D.total)}% of them.` : ''} ${pc(D.blocked, D.total)}% were blocked by policy.${sent ? ` ${bytes(sent)} was uploaded to AI tools.` : ''}</p><small>${delta(D.total, P.total, null)}${newT.length ? ` · new this period: ${newT.slice(0, 4).map(t => esc(t.name)).join(', ')}` : ''}</small></div>
   <div class="rings">${ring(pc(D.userKnown, D.total), '#0e7490', 'User known', D.userNPS ? num(D.userNPS) + ' from NPS' : 'events with a username')}${ring(pc(D.blocked, D.total), '#6d5bd0', 'Blocked', 'by policy')}${ring(pc((D.toolUsage || []).length ? newT.length : 0, (D.toolUsage || []).length), '#e4572e', 'New tools', 'first seen in this period')}</div>`;
  $('#tiles').innerHTML = kpi('Events', num(D.total), 'matching filters', delta(D.total, P.total, null), spark(series)) +
    kpi('Blocked', num(D.blocked), pc(D.blocked, D.total) + '% of events', delta(D.blocked, P.blocked, null), spark(blk, 120, 28, '#e4572e'), 'outcome', 'blocked') +
    kpi('AI tools', num((D.toolUsage || []).length), 'seen in this period') + kpi('People', num(D.usersGroups), 'distinct usernames') + kpi('Source IPs', num(D.sourcesGroups), 'devices') +
    kpi('Uploaded to AI', bytes(sent), 'data sent, from traffic logs');
  $('#attention').innerHTML = D.findings.length ? D.findings.map(f => `<div class="fnd"><span class="sev ${f.sev}">${f.sev === 'high' ? 'High' : 'Medium'}</span><div><b>${esc(f.title)}</b><p>${esc(f.detail)}</p><p class="act"><b>Action:</b> ${esc(f.action)}</p></div></div>`).join('')
    : '<div class="fnd"><span class="sev ok">Clear</span><div><b>Nothing needs attention in this period</b><p>No high-risk, unidentified or bypass traffic crossed the thresholds.</p></div></div>';
  timeline(D, $('#timeline'));
  const tot = D.total || 1, cat = i => PAL[i % 8];
  const AK = D.appKey || 'app';
  $('#apps').innerHTML = table([['AI tool'], ['Share'], ['Events', 1], ['Blocked', 1], ['Risk'], ['Trend']], D.apps.slice(0, 10).map((a, i) =>
    `<tr data-k="${AK}" data-v="${esc(a.name)}"><td><i class="dot" style="background:${cat(i)}"></i>${esc(a.name)}</td><td><span class="share" style="width:${Math.max(3, 90 * a.count / D.apps[0].count)}px"></span>${pc(a.count, tot)}%</td><td class="n">${num(a.count)}</td><td class="n">${num(a.blocked)}</td><td>${riskPill(a.risk)}</td><td>${spark(a.spark, 90, 22, cat(i))}</td></tr>`));
  $('#usernote').textContent = D.userKnown < D.total ? `${num(D.total - D.userKnown)} of ${num(D.total)} events have no username.` : 'Click a row to filter.';
  $('#users').innerHTML = table([['User'], ['Events', 1], ['Blocked', 1]], (D.users || []).map(u => `<tr data-k="user" data-v="${esc(u.name)}"><td>${esc(u.name)}</td><td class="n">${num(u.count)}</td><td class="n">${num(u.blocked)}</td></tr>`));
  $('#sources').innerHTML = bars(D.sources, { key: 'src' });
  $('#hosts').innerHTML = table([['Hostname'], ['Events', 1], ['Share', 1]], (D.hosts || []).map(h => `<tr data-k="host" data-v="${esc(h.name)}"><td>${esc(h.name)}</td><td class="n">${num(h.count)}</td><td class="n">${pc(h.count, tot)}%</td></tr>`));
  const tu = D.toolUsage || [], mu = Math.max(1, ...tu.map(t => t.users));
  $('#adoption').innerHTML = table([['AI tool'], ['People'], ['People', 1], ['Devices', 1], ['Events', 1], ['Blocked', 1], ['First seen'], ['Last seen']], tu.map(t =>
    `<tr data-k="tool" data-v="${esc(t.name)}"><td>${esc(t.name)}${t.isNew ? ' <span class="newb">New</span>' : ''}</td><td><span class="share" style="width:${Math.max(3, 120 * t.users / mu)}px"></span></td><td class="n">${num(t.users)}</td><td class="n">${num(t.sources)}</td><td class="n">${num(t.count)}</td><td class="n">${num(t.blocked)}</td><td>${ldt(t.firstEver || t.first)}</td><td>${ldt(t.last)}</td></tr>`), 'No AI tools in this period.');
  const sentBars = (rows, key) => bars((rows || []).map(x => ({ ...x, bytes: x.sent })), { bytes: 1, key });
  $('#aidata').innerHTML = sentBars(D.aiToolData, 'tool');
  $('#aiuploaders').innerHTML = sentBars(D.aiUploaders, 'user');
  $('#aiupsrc').innerHTML = sentBars(D.aiUploadSources, 'src');
  const H = {}; let hm = 1; D.heat.forEach(([d, h, c]) => { H[d * 24 + h] = c; hm = Math.max(hm, c) });
  const days = [[1, 'Mon'], [2, 'Tue'], [3, 'Wed'], [4, 'Thu'], [5, 'Fri'], [6, 'Sat'], [0, 'Sun']];
  $('#heat').innerHTML = `<div class="heat"><div></div>${Array.from({ length: 24 }, (_, h) => `<div class="h">${h % 3 ? '' : String(h).padStart(2, '0')}</div>`).join('')}${days.map(([d, n]) => `<div class="d">${n}</div>${Array.from({ length: 24 }, (_, h) => { const c = H[d * 24 + h] || 0; return `<div title="${n} ${String(h).padStart(2, '0')}:00 · ${num(c)} events" style="background:${c ? `rgba(14,116,144,${(.12 + .88 * c / hm).toFixed(2)})` : '#eef3f6'}"></div>` }).join('')}`).join('')}</div>`;
  $('#wheredata').innerHTML = bars(D.whereData, { bytes: 1, key: destKey });
  $('#countries').innerHTML = bars(D.countries, { bytes: 1 });
  renderAIMore();
}

// ------------------------------------------------------------ Policy and risk
function renderPolicy() {
  const P = D.prev || {}, allowed = D.total - D.blocked, pa = P.total - P.blocked, share = D.total ? 100 * allowed / D.total : 0, pshare = P.total ? 100 * pa / P.total : 0;
  const dpts = P.total ? (share - pshare) : 0, wb = D.apps.filter(a => a.blocked > 0).length;
  $('#ptiles').innerHTML = kpi('Allowed share', share.toFixed(1) + '%', num(allowed) + ' events', P.total ? `<span class="dl ${dpts >= 0 ? 'gd' : 'bd'}">${dpts >= 0 ? '▲' : '▼'} ${Math.abs(dpts).toFixed(1)} pts vs previous period</span>` : '') +
    kpi('Blocked events', num(D.blocked), pc(D.blocked, D.total) + '% of events', delta(D.blocked, P.blocked, null), '', 'outcome', 'blocked') +
    kpi('Tools with blocks', num(wb), 'of ' + D.apps.length + ' AI tools') +
    kpi('High risk, not blocked', num(D.riskNB), 'elevated, high or critical', delta(D.riskNB, P.riskNB, false)) +
    kpi('Not identified, not blocked', num(D.genericNB), 'generic SSL, TLS or QUIC') + kpi('Events', num(D.total), 'matching filters', delta(D.total, P.total, null));
  timeline(D, $('#ptimeline'));
  $('#outcome').innerHTML = donut([{ name: 'Allowed', value: allowed, color: '#2f9e6e', k: 'outcome', v: 'allowed' }, { name: 'Blocked', value: D.blocked, color: '#e4572e', k: 'outcome', v: 'blocked' }], num(D.total), 'events');
  $('#risk').innerHTML = bars([...D.risk].sort((a, b) => (RISKN[b.name] || 0) - (RISKN[a.name] || 0)), { key: 'risk', color: x => (RISK[RISKN[x.name]] || [0, '#9aa5b1'])[1] });
  $('#tools').innerHTML = table([['Tool'], ['Highest risk'], ['Allowed', 1], ['Blocked', 1], ['Blocked share', 1]], D.apps.map(a => `<tr data-k="${D.appKey || 'app'}" data-v="${esc(a.name)}"><td>${esc(a.name)}</td><td>${riskPill(a.risk)}</td><td class="n">${num(a.count - a.blocked)}</td><td class="n">${num(a.blocked)}</td><td class="n">${pc(a.blocked, a.count)}%</td></tr>`));
  const gn = n => /^(ssl|tls|quic|unknown)([_.+ -]|$)/i.test(n), rkOf = n => (D.apps.find(a => a.name === n) || {}).risk || 0;
  $('#review').innerHTML = table([['Application'], ['Reason'], ['Risk'], ['Not blocked', 1]], (D.needsReview || []).map(a => `<tr data-k="app" data-v="${esc(a.name)}"><td>${esc(a.name)}</td><td>${gn(a.name) ? 'Not identified' : 'Elevated or high risk'}</td><td>${riskPill(a.risk || rkOf(a.name))}</td><td class="n">${num(a.count)}</td></tr>`), 'Nothing to review.');
  $('#mblocked').innerHTML = table([['Destination'], ['Blocked', 1]], (D.mostBlocked || []).map(h => `<tr data-k="${destKey(h.name)}" data-v="${esc(h.name)}"><td>${esc(h.name)}</td><td class="n">${num(h.count)}</td></tr>`), 'No blocked events.');
}

// ------------------------------------------------------------ IP and user investigation
function renderInvestigate() {
  const subj = F.src || F.user, label = F.src ? 'IP address' : 'user';
  const dl = [...(D.sources || []).map(x => x.name), ...(D.users || []).map(x => x.name)];
  $('#invhead').innerHTML = `<div class="subject"><h3>AI use by IP or user</h3><input id="subject" list="dl-subject" placeholder="Enter an IP address or username" value="${esc((subj || '').replace(/^[=!]/, ''))}"><datalist id="dl-subject">${dl.map(v => `<option value="${esc(v)}">`).join('')}</datalist><button id="gosubject" class="primary">Investigate</button>${F.src ? '<button id="mapthis">Map a user to this IP</button>' : ''}</div>
   <p class="hint" style="margin:8px 0 0">Choose an IP or user to see their daily AI visits, tools and usernames, and who NPS says held the IP. The period and other filters above still apply. <a href="#" id="alllogs">See all of their activity in the Log explorer</a>.</p>`;
  $('#alllogs').onclick = e => { e.preventDefault(); F.scope = ''; setView('logs') };
  const go = () => { const v = $('#subject').value.trim(); if (!v) return; if (isIP(v)) { F.src = v; F.user = '' } else { F.user = v; F.src = '' } apply() };
  if ($('#mapthis')) $('#mapthis').onclick = () => { setView('mapping'); fillForm(F.src.replace(/^[=!]/, ''), '', D.from, D.to) };
  $('#gosubject').onclick = go; $('#subject').onkeydown = e => { if (e.key === 'Enter') go() };
  if (!subj) {
    $('#invbody').innerHTML = `<div class="card" style="margin-top:12px"><h3>Busiest sources</h3><p class="hint">Pick one to start.</p><div class="pick">${(D.sources || []).map(s => `<button data-k="src" data-v="${esc(s.name)}">${esc(s.name)} <span class="muted">${short(s.count)}</span></button>`).join('')}${(D.users || []).map(s => `<button data-k="user" data-v="${esc(s.name)}">${esc(s.name)} <span class="muted">${short(s.count)}</span></button>`).join('')}</div></div>`;
    return;
  }
  const dd = INV ? INV.daily : [], days = new Set(dd.map(r => r.day)).size, known = (INV ? INV.identities : []).filter(i => i.user !== '(none)');
  const apps = D.apps.slice(0, 8), others = D.total - apps.reduce((s, a) => s + a.count, 0), ses = INV ? INV.sessions || [] : [];
  $('#invbody').innerHTML = `<div class="tiles">${kpi(label[0].toUpperCase() + label.slice(1), esc((subj || '').replace(/^[=!]/, '')), 'selected')}${kpi('Total visits', num(D.total), 'log events')}${kpi('Active days', days, 'in this period')}${kpi('Known users', known.length, known.length ? esc(known[0].user) : 'not identified')}${kpi('AI tools', D.apps.length, D.apps[0] ? esc(D.apps[0].name) : '')}${kpi('Hostnames', num(D.hostsGroups), 'destinations')}</div>
   <div class="grid"><article class="card"><h3>Visits over time</h3><div id="itimeline" class="chartwrap"></div></article><article class="card"><h3>AI tools used</h3><div id="iapps" class="donutwrap"></div></article>
   <article class="card"><h3>Daily destination details</h3><div style="max-height:420px;overflow:auto">${table([['Date'], ['Application'], ['Destination'], ['Events', 1], ['Blocked', 1]], dd.slice(0, 200).map(r => `<tr><td>${r.day}</td><td>${esc(r.app)}</td><td>${esc(r.host)}</td><td class="n">${num(r.count)}</td><td class="n">${num(r.blocked)}</td></tr>`))}</div></article>
   <article class="card"><h3>Observed identities</h3>${table([['Username'], ['Events', 1], ['Source'], ['First seen'], ['Last seen']], (INV ? INV.identities : []).map(i => `<tr><td>${esc(i.user)}</td><td class="n">${num(i.count)}</td><td>${i.user === '(none)' ? '' : srcLabel(i)}</td><td>${new Date(i.first).toLocaleString()}</td><td>${new Date(i.last).toLocaleString()}</td></tr>`))}</article>
   <article class="card wide"><h3>${F.src ? 'Who had this IP (NPS)' : 'Where this user was (NPS)'}</h3><p class="hint">Wireless sign-ins from the NPS server that overlap the selected period.</p>${sessTable(ses, 'No NPS sessions in this period.')}</article></div>`;
  timeline(D, $('#itimeline'));
  $('#iapps').innerHTML = donut([...apps.map((a, i) => ({ name: a.name, value: a.count, color: PAL[i % 8], k: D.appKey || 'app', v: a.name })), ...(others > 0 ? [{ name: 'Other', value: others, color: '#cbd5df' }] : [])], num(D.total), 'AI events');
}

// ------------------------------------------------------------ User mapping (IP to user, for DHCP networks)
let MAP = null, MAPMSG = '';
const jpost = (u, b, m = 'POST') => fetch(u, { method: m, headers: { 'Content-Type': 'application/json' }, body: b === undefined ? undefined : JSON.stringify(b) }).then(async r => { if (!r.ok) throw new Error((await r.text()).trim() || r.statusText); return r.json() });
const ldt = s => new Date(s).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
let NPSQ = { ip: '', user: '' };
async function loadMapping(signal) {
  const sq = qs({ ip: NPSQ.ip, user: NPSQ.user });
  const [ov, list, users, nst, ses] = await Promise.all([api('/api/mapping/overview?' + qs(), { signal }), api('/api/mappings', { signal }), api('/api/facets?field=user&hours=720').catch(() => []),
    api('/api/nps/status', { signal }).catch(() => null), api('/api/nps/sessions?' + sq, { signal }).catch(() => [])]);
  MAP = { ov, list, nst, ses }; $('#dl-muser').innerHTML = users.map(u => `<option value="${esc(u.name)}">`).join('');
}
const srcLabel = i => { const fw = i.count - (i.mapped || 0) - (i.nps || 0), p = []; if (fw > 0) p.push('Firewall'); if (i.nps) p.push('NPS'); if (i.mapped) p.push('Manual'); return p.length === 1 ? { Firewall: 'Firewall (FSSO / log)', NPS: 'NPS (wireless)', Manual: 'Manual mapping' }[p[0]] : p.join(' + ') };
const ago = t => { if (!t) return 'never'; const s = Math.max(0, Date.now() / 1000 - t); return s < 90 ? Math.round(s) + ' s ago' : s < 5400 ? Math.round(s / 60) + ' min ago' : s < 172800 ? Math.round(s / 3600) + ' h ago' : Math.round(s / 86400) + ' days ago' };
function sessTable(ses, empty) {
  return `<div class="scrollbox">${table([['IP address'], ['User'], ['Device MAC'], ['From'], ['Until'], ['How it ended'], ['Learned from'], ['Events', 1]], ses.map(x =>
    `<tr><td class="f" data-k="src" data-v="${esc(x.ip)}">${esc(x.ip)}</td><td class="f" data-k="user" data-v="${esc(x.user)}">${esc(x.user)}</td><td>${esc(x.mac)}</td><td>${ldt(x.start)}</td><td>${x.open ? '<span class="pill ok">active</span>' : ldt(x.end)}</td><td>${esc(x.open ? '' : x.reason || 'idle timeout')}</td><td>${x.origin === 'mac' ? 'FortiGate MAC' : 'NPS' + (x.nas ? ' · ' + esc(x.nas) : '')}</td><td class="n">${(x.events < 0 ? '–' : num(x.events))}</td></tr>`), empty)}</div>`;
}
function fillForm(ip, user, from, to) {
  $('#m-ip').value = ip || ''; $('#m-user').value = user || '';
  $('#m-from').value = from ? localInput(new Date(from)) : ''; $('#m-to').value = to ? localInput(new Date(to)) : '';
  (user || !ip ? $('#m-user') : $('#m-user')).focus(); $('#m-ip').scrollIntoView({ block: 'center', behavior: 'smooth' });
}
function renderMapping() {
  const O = MAP.ov, nps = O.userNPS || 0, man = O.userMapped || 0, fw = O.userKnown - nps - man, unk = O.total - O.userKnown, un = O.unmapped || [];
  renderPeriod(O, [[num(O.total), 'Events'], [pc(O.userKnown, O.total) + '%', 'User known'], [pc(nps, O.total) + '%', 'From NPS'], [num(un.length >= 60 ? '60+' : un.length), 'IPs without user']]);
  $('#mtiles').innerHTML = kpi('Events', num(O.total), 'matching filters') + kpi('Username from firewall', pc(fw, O.total) + '%', num(fw) + ' events (FSSO / log)') +
    kpi('From NPS (wireless)', pc(nps, O.total) + '%', num(nps) + ' events') + kpi('Mapped by you', pc(man, O.total) + '%', num(man) + ' events') +
    kpi('Still unknown', pc(unk, O.total) + '%', num(unk) + ' events') + kpi('IPs without a username', un.length >= 60 ? '60+' : un.length, 'in this period');
  const n = MAP.nst;
  $('#npsstatus').innerHTML = !n ? '<span class="muted">NPS status unavailable.</span>' : !n.enabled ? '<div class="notice">NPS mapping is off. Turn it on and give the NPS log folder in Settings.</div>' :
    `<div class="nstat"><span><b>${num(n.open_sessions)}</b> active sessions</span><span><b>${num(n.records)}</b> NPS records read (${num(n.used)} used, ${num(n.ignored)} ignored)</span><span>Last record <b>${n.last_record && !n.last_record.startsWith('0001') ? ldt(n.last_record) : 'none yet'}</b></span><span>${(n.files || []).length} log file(s)</span></div>
     ${(n.files || []).length ? `<details class="imp"><summary>Files</summary>${table([['File'], ['Size', 1], ['Read up to', 1], ['Modified']], n.files.map(f => `<tr><td>${esc(f.path)}</td><td class="n">${bytes(f.size)}</td><td class="n">${bytes(f.offset)}</td><td>${ldt(f.modified)}</td></tr>`))}</details>` : `<div class="notice">No NPS log files found in: ${esc((n.paths || []).join(', '))}</div>`}
     ${n.last_error ? `<p class="err">Last problem (${ldt(n.last_error_at)}): ${esc(n.last_error)}</p>` : ''}`;
  $('#n-ip').value = NPSQ.ip; $('#n-user').value = NPSQ.user;
  $('#npssessions').innerHTML = sessTable(MAP.ses || [], 'No NPS sessions in this period.');
  $('#m-msg').textContent = MAPMSG;
  $('#unmapped').innerHTML = table([['IP address'], ['Events', 1], ['Days', 1], ['First seen'], ['Last seen'], ['Seen with (firewall)'], ['']], un.map(u => `<tr><td>${esc(u.ip)}</td><td class="n">${num(u.events)}</td><td class="n">${u.days}</td><td>${ldt(u.first)}</td><td>${ldt(u.last)}</td>
    <td>${u.observed.map(o => `<button class="chipbtn" data-act="use" data-ip="${esc(u.ip)}" data-user="${esc(o.user)}" data-from="${u.first}" data-to="${u.last}" title="The firewall reported ${esc(o.user)} on this IP for ${num(o.events)} events, ${ldt(o.first)} to ${ldt(o.last)}. Click to map the events without a username to ${esc(o.user)}.">${esc(o.user)} <small>${num(o.events)}</small></button>`).join('') || '<span class="muted">nobody</span>'}</td>
    <td><button data-act="map" data-ip="${esc(u.ip)}" data-from="${u.first}" data-to="${u.last}">Map</button></td></tr>`), 'Every event in this period has a username.');
  $('#maplist').innerHTML = table([['IP address'], ['User'], ['From'], ['To'], ['Events', 1], ['Note'], ['Added'], ['']], MAP.list.map(m => `<tr><td>${esc(m.ip)}</td><td>${esc(m.user)}</td><td>${ldt(m.from)}</td><td>${ldt(m.to)}</td><td class="n">${(m.rows < 0 ? '–' : num(m.rows))}</td><td>${esc(m.note)}</td><td>${ldt(m.created)}</td><td><button data-act="del" data-id="${m.id}" data-rows="${m.rows}">Delete</button></td></tr>`), 'No manual mappings yet.');
}
$('#n-find').onclick = () => { NPSQ = { ip: $('#n-ip').value.trim(), user: $('#n-user').value.trim() }; refresh() };
$('#n-clear').onclick = () => { NPSQ = { ip: '', user: '' }; refresh() };
['#n-ip', '#n-user'].forEach(i => $(i).addEventListener('keydown', e => { if (e.key === 'Enter') $('#n-find').click() }));
$('#mapping').addEventListener('click', async e => {
  const b = e.target.closest('button[data-act]'); if (!b) return; const d = b.dataset;
  if (d.act === 'use') fillForm(d.ip, d.user, d.from, new Date(+new Date(d.to) + 6e4));
  if (d.act === 'map') fillForm(d.ip, '', d.from, new Date(+new Date(d.to) + 6e4));
  if (d.act === 'del' && confirm(`Remove this mapping? ${+d.rows >= 0 ? num(d.rows) + ' events go' : 'Its events go'} back to having no username.`)) {
    try { const r = await jpost('/api/mappings?id=' + d.id, undefined, 'DELETE'); MAPMSG = `Removed. ${num(r.reverted)} events were reverted.` } catch (x) { MAPMSG = x.message }
    D = G = null; refresh();
  }
});
$('#m-day').onclick = () => { const f = $('#m-from').value; if (!f) { $('#m-msg').textContent = 'Choose a From time first.'; return } const a = new Date(f); a.setHours(0, 0, 0, 0); $('#m-from').value = localInput(a); $('#m-to').value = localInput(new Date(+a + 864e5)) };
$('#m-save').onclick = async () => {
  const ip = $('#m-ip').value.trim(), user = $('#m-user').value.trim(), f = $('#m-from').value, t = $('#m-to').value;
  if (!ip || !user || !f || !t) { $('#m-msg').textContent = 'Enter the IP address, username, and both times.'; return }
  try { const r = await jpost('/api/mappings', { ip, user, from: new Date(f).toISOString(), to: new Date(t).toISOString(), note: $('#m-note').value }); MAPMSG = r.rows ? `Saved. ${num(r.rows)} existing events were mapped to ${r.user}. New logs in this window are mapped automatically.` : `Saved, but no existing events without a username matched that IP and time range. New logs in this window will be mapped automatically.`; ['#m-ip', '#m-user', '#m-from', '#m-to', '#m-note'].forEach(i => $(i).value = '') }
  catch (x) { $('#m-msg').textContent = x.message; return }
  D = G = null; INV = null; refresh();
};
$('#m-import').onclick = async () => {
  try { const r = await jpost('/api/mappings/import', { Text: $('#m-csv').value }); MAPMSG = `Imported ${r.added} mappings covering ${num(r.rows)} events.` + (r.errors.length ? ' Problems: ' + r.errors.join('; ') : ''); if (!r.errors.length) $('#m-csv').value = '' } catch (x) { MAPMSG = x.message }
  D = G = null; INV = null; refresh();
};

// ------------------------------------------------------------ Log explorer
const COLS = ['Time', 'Firewall', 'Type', 'Action', 'User', 'Source IP', 'Destination', 'Host / URL / message', 'Category', 'Application', 'AI tool', 'Risk', 'Policy', 'Bytes'];
$('#loghead').innerHTML = '<tr>' + COLS.map(c => `<th>${c}</th>`).join('') + '</tr>';
let rowsCache = [];
const blockedSet = new Set(['blocked', 'block', 'deny', 'dropped', 'reset', 'reset-client', 'reset-server', 'reject', 'blocked-url']);
const cell = (k, v) => `<td data-k="${k}" data-v="${esc(v)}" class="f" title="Click: filter · Shift+click: exclude">${esc(v)}</td>`;
const UBADGE = { manual: '<span class="mapped" title="Added by a manual mapping">mapped</span>', nps: '<span class="mapped nps" title="From the NPS (wireless) session for this IP">NPS</span>' };
async function loadLogs(signal) {
  const size = +$('#psize').value, r = await api('/api/logs?' + qs({ limit: size, offset: page * size }), { signal });
  rowsCache = r.rows;
  $('#logrows').innerHTML = r.rows.map((x, i) => {
    const det = x.hostname || x.url ? `${esc(x.hostname)}<span class="muted">${esc(x.url.length > 60 ? x.url.slice(0, 60) + '…' : x.url)}</span>` : `<span class="muted">${esc(x.msg)}</span>`;
    return `<tr><td class="t" data-i="${i}" title="Open details">${new Date(x.time).toLocaleString()}</td>${cell('fw', x.fw)}
    <td data-k="subtype" data-v="${esc(x.subtype)}" class="f" title="${esc(x.type)} / ${esc(x.subtype)}${x.level ? ' · ' + esc(x.level) : ''}">${esc(x.subtype === 'app-ctrl' ? 'App control' : x.subtype === 'webfilter' ? 'Web filter' : x.subtype || x.type)}</td>
    <td data-k="action" data-v="${esc(x.action)}" class="f">${x.action ? `<span class="pill ${blockedSet.has(x.action) ? 'bad' : 'ok'}">${esc(x.action)}</span>` : ''}</td>
    <td data-k="user" data-v="${esc(x.user)}" class="f" title="Click: filter · Shift+click: exclude">${esc(x.user)}${UBADGE[x.user_source] || ''}</td>${cell('src', x.src_ip)}${cell('dst', x.dst_ip)}
    <td data-k="${x.hostname ? 'host' : 'msg'}" data-v="${esc(x.hostname || x.msg)}" class="f wrap" title="${esc(x.hostname + x.url || x.msg)}">${det}</td>
    ${cell('category', x.category)}${cell('app', x.application)}${cell('tool', x.tool)}${cell('risk', x.risk)}<td>${x.policy_id || ''}</td><td class="r">${x.bytes ? bytes(x.bytes) : ''}</td></tr>`;
  }).join('') || `<tr><td colspan="${COLS.length}" class="muted">No matching logs</td></tr>`;
  $('#rowinfo').textContent = r.rows.length ? `Rows ${page * size + 1}–${page * size + r.rows.length}` : '';
  $('#prev').disabled = page === 0; $('#next').disabled = !r.more;
}
$('#logrows').addEventListener('click', e => { const t = e.target.closest('td.t'); if (t) openDrawer(rowsCache[+t.dataset.i]) });
$('#prev').onclick = () => { page = Math.max(0, page - 1); refresh() };
$('#next').onclick = () => { page++; refresh() };
$('#psize').onchange = () => { page = 0; refresh() };
$('#export').onclick = () => { location.href = '/api/export.csv?' + qs() };
$('#print').onclick = () => window.print();

const FIELD_FILTER = { srcip: 'src', dstip: 'dst', hostname: 'host', user: 'user', unauthuser: 'user', catdesc: 'category', app: 'app', apprisk: 'risk', action: 'action',
  devname: 'fw', type: 'type', subtype: 'subtype', level: 'level', service: 'service', logdesc: 'msg', policyname: 'policy' };
let currentRaw = '';
// v5.15: readable log detail. The fields of the raw line are grouped (what happened, who, where to, traffic, security,
// admin / VPN), named in plain words and formatted (bytes, durations, times); everything else is under "All other fields"
// and the raw line at the bottom. Every value that is a dashboard filter has an "only" / "not" button.
const DFIELDS = [
  ['What happened', [['logdesc', 'Event'], ['msg', 'Message'], ['action', 'Action'], ['utmaction', 'Security action'], ['policyname', 'Policy'], ['policyid', 'Policy ID'],
    ['service', 'Service'], ['app', 'Application'], ['appcat', 'App category'], ['catdesc', 'Web category'], ['reason', 'Reason'], ['status', 'Status']]],
  ['Who', [['user', 'User'], ['unauthuser', 'User (unauthenticated)'], ['group', 'Group'], ['srcip', 'Source IP'], ['srcport', 'Source port'], ['srcmac', 'MAC address'],
    ['srcname', 'Device name'], ['devtype', 'Device type'], ['osname', 'Operating system'], ['srcintf', 'Incoming interface'], ['srccountry', 'Source country']]],
  ['Where to', [['hostname', 'Host name'], ['url', 'URL'], ['dstip', 'Destination IP'], ['dstport', 'Destination port'], ['dstname', 'Destination name'],
    ['dstcountry', 'Destination country'], ['dstintf', 'Outgoing interface'], ['referralurl', 'Referred from']]],
  ['Traffic', [['sentbyte', 'Uploaded'], ['rcvdbyte', 'Downloaded'], ['sentdelta', 'Uploaded since last log'], ['rcvddelta', 'Downloaded since last log'], ['duration', 'Duration'],
    ['proto', 'Protocol'], ['sentpkt', 'Packets sent'], ['rcvdpkt', 'Packets received'], ['sessionid', 'Session ID'], ['trandisp', 'NAT'], ['transip', 'NAT address'], ['transport', 'NAT port']]],
  ['Security', [['apprisk', 'App risk'], ['crscore', 'Client reputation score'], ['crlevel', 'Reputation level'], ['attack', 'Attack'], ['severity', 'Attack severity'], ['virus', 'Virus'],
    ['filename', 'File'], ['dtype', 'Detection'], ['profile', 'Security profile'], ['eventtype', 'Event type']]],
  ['Admin and VPN', [['ui', 'Signed in through'], ['method', 'Method'], ['tunneltype', 'Tunnel type'], ['remip', 'Remote IP'], ['cfgpath', 'Changed setting'], ['cfgobj', 'Object'],
    ['cfgattr', 'Change'], ['vpntunnel', 'VPN tunnel'], ['xauthuser', 'VPN user']]],
];
const DSKIP = new Set(['date', 'time', 'eventtime', 'tz', 'devname', 'devid', 'vd', 'logid', 'type', 'subtype', 'level']);
const DBYTES = new Set(['sentbyte', 'rcvdbyte', 'sentdelta', 'rcvddelta']);
const USRC = { log: 'from the firewall (FSSO / VPN)', nps: 'from NPS (wireless sign-in)', manual: 'manual mapping', assigned: 'permanent assignment' };
const dur = s => { s = +s || 0; const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60; return h ? `${h} h ${m} min` : m ? `${m} min ${x} s` : `${x} s` };
function dval(k, v) {
  if (DBYTES.has(k)) return `${bytes(+v)} <small class="muted">(${num(+v)} bytes)</small>`;
  if (k === 'duration') return esc(dur(v));
  if (k === 'action' || k === 'utmaction') return `<span class="pill ${blockedSet.has(v) ? 'bad' : 'ok'}">${esc(v)}</span>`;
  if (k === 'apprisk') { const r = RISKN[v]; return r ? riskPill(r) : esc(v) }
  if (k === 'url' || k === 'referralurl') return `<span class="brk">${esc(v)}</span>`;
  return esc(v);
}
function openDrawer(row) {
  currentRaw = row.raw;
  const kv = {}, order = [];
  row.raw.replace(/(\w+)=("(?:[^"\\]|\\.)*"|\S*)/g, (_, k, v) => { if (!(k in kv)) order.push(k); kv[k] = v.startsWith('"') ? v.slice(1, -1).replace(/\\(["\\])/g, '$1') : v });
  const used = new Set(), blocked = blockedSet.has(row.action);
  const filt = (k, v) => FIELD_FILTER[k] && v ? `<span class="dacts"><button data-k="${FIELD_FILTER[k]}" data-v="${esc(v)}" title="Show only this">only</button><button data-k="${FIELD_FILTER[k]}" data-v="${esc(v)}" data-not="1" title="Leave this out">not</button></span>` : '';
  const line = (k, label, v) => `<div class="drow"><span class="dl">${esc(label)}</span><span class="dv">${dval(k, v)}</span>${filt(k, v)}</div>`;
  const kind = row.subtype === 'app-ctrl' ? 'Application control' : row.subtype === 'webfilter' ? 'Web filter' : (SUBN[row.subtype] || row.subtype || row.type);
  const title = kv.logdesc || kv.msg || (row.hostname ? row.hostname : [row.src_ip, row.dst_ip].filter(Boolean).join(' → ')) || 'Log';
  let html = `<div class="dhead ${blocked ? 'bad' : ''}"><div class="dtitle">${esc(title)}</div>
    <div class="dmeta">${row.action ? `<span class="pill ${blocked ? 'bad' : 'ok'}">${esc(row.action)}</span>` : ''}<span class="pill">${esc(kind)}</span>
      ${row.level ? `<span class="pill">${esc(row.level)}</span>` : ''}<span class="fwtag">${esc(row.fw)}</span></div>
    <div class="dtime">${new Date(row.time).toLocaleString([], { dateStyle: 'full', timeStyle: 'medium' })}</div>
    ${row.user ? `<div class="duser">User <b>${esc(row.user)}</b> <small class="muted">${esc(USRC[row.user_source] || '')}</small></div>` : ''}
    ${row.tool ? `<div class="duser">AI tool <b>${esc(row.tool)}</b></div>` : ''}</div>`;
  for (const [sec, fields] of DFIELDS) {
    const rows = fields.filter(([k]) => kv[k] !== undefined && kv[k] !== '' && kv[k] !== 'N/A').map(([k, l]) => { used.add(k); return line(k, l, kv[k]) });
    if (rows.length) html += `<section class="dsec"><h4>${sec}</h4>${rows.join('')}</section>`;
  }
  const rest = order.filter(k => !used.has(k) && !DSKIP.has(k));
  if (rest.length) html += `<details class="dsec"><summary>All other fields (${rest.length})</summary>${rest.map(k => line(k, k, kv[k])).join('')}</details>`;
  html += `<details class="dsec"><summary>Raw log line</summary><pre class="draw">${esc(row.raw)}</pre></details>`;
  $('#dbody').innerHTML = html;
  $('#drawer').hidden = false;
}
$('#dbody').onclick = e => { const b = e.target.closest('button[data-k]'); if (b) { drill(b.dataset.k, b.dataset.v, e.shiftKey || !!b.dataset.not); $('#drawer').hidden = true } };
$('#closedrawer').onclick = () => $('#drawer').hidden = true;
$('#copyraw').onclick = () => { try { navigator.clipboard.writeText(currentRaw); $('#copyraw').textContent = 'Copied' } catch { } setTimeout(() => $('#copyraw').textContent = 'Copy raw', 1200) };
document.addEventListener('keydown', e => { if (e.key === 'Escape') $('#drawer').hidden = true });


// ------------------------------------------------------------ v5.10: shared chart helpers
// time axis of a series: [{t, ...}] with step seconds -> n buckets from t0 (local origin when the server sends one)
function axis(d) {
  const step = d.step, t0 = d.origin != null ? +d.origin : Math.floor(new Date(d.from) / 1000 / step) * step;
  const n = Math.max(1, Math.min(700, Math.ceil((new Date(d.to) / 1000 - t0) / step)));
  return { step, t0, n, idx: t => Math.floor((t - t0) / step) };
}
// stacked bars: parts = [{name, color, vals:[n]}]; fmt formats the y axis and tooltips
function stackChart(el, ax, parts, fmt, h = 220) {
  const W = Math.max(320, Math.round(el.clientWidth) || 900), H = h, L = 74, R = 8, T = 10, B = 26, pw = W - L - R, ph = H - T - B, bw = pw / ax.n;
  const tot = Array.from({ length: ax.n }, (_, i) => parts.reduce((a, p) => a + (p.vals[i] || 0), 0)), mx = Math.max(1, ...tot);
  const span = ax.n * ax.step, lab = s => { const dt = new Date(s * 1000); return span > 36 * 3600 ? dt.toLocaleDateString([], { month: 'short', day: 'numeric' }) : dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) };
  let g = '';
  [0, .25, .5, .75, 1].forEach(f => { const y = T + ph - f * ph; g += `<line x1="${L}" x2="${W - R}" y1="${y}" y2="${y}" class="grid"/><text x="${L - 6}" y="${y + 4}" text-anchor="end">${fmt(mx * f)}</text>` });
  const NT = W < 600 ? 3 : 6; for (let i = 0; i <= NT; i++) { const k = Math.round(i * (ax.n - 1) / NT); g += `<text x="${L + k * bw + bw / 2}" y="${H - 8}" text-anchor="${i === 0 ? 'start' : i === NT ? 'end' : 'middle'}">${lab(ax.t0 + k * ax.step)}</text>` }
  let b = '';
  for (let i = 0; i < ax.n; i++) {
    let y = T + ph; const when = new Date((ax.t0 + i * ax.step) * 1000).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
    parts.forEach(p => { const v = p.vals[i] || 0, hh = v / mx * ph; if (hh > 0) { y -= hh; b += `<rect x="${L + i * bw + .5}" y="${y}" width="${Math.max(1, bw - 1)}" height="${hh}" fill="${p.color}"><title>${esc(when)} · ${esc(p.name)}: ${fmt(v)}</title></rect>` } });
  }
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" style="height:${H}px;cursor:default">${g}${b}</svg>`;
}
// weekday x hour grid; cells: {d*24+h: [count, blocked]}
function heatGrid(cells, unit = 'events') {
  let hm = 1; Object.values(cells).forEach(c => hm = Math.max(hm, c[0]));
  const days = [[1, 'Mon'], [2, 'Tue'], [3, 'Wed'], [4, 'Thu'], [5, 'Fri'], [6, 'Sat'], [0, 'Sun']];
  return `<div class="heat"><div></div>${Array.from({ length: 24 }, (_, h) => `<div class="h">${h % 3 ? '' : String(h).padStart(2, '0')}</div>`).join('')}${days.map(([d, n]) => `<div class="d">${n}</div>${Array.from({ length: 24 }, (_, h) => {
    const c = cells[d * 24 + h] || [0, 0]; return `<div title="${n} ${String(h).padStart(2, '0')}:00 · ${num(c[0])} ${unit}${c[1] ? ' · ' + num(c[1]) + ' blocked' : ''}" style="background:${c[0] ? `rgba(14,116,144,${(.12 + .88 * c[0] / hm).toFixed(2)})` : '#eef3f6'}"></div>`
  }).join('')}`).join('')}</div>`;
}

// ------------------------------------------------------------ v5.10: more All logs widgets
function renderGlobalMore(X) {
  renderDataCharts(X); renderZones(X);
  const cells = {}; (X.heat || []).forEach(([d, h, c, b]) => cells[d * 24 + h] = [c, b]);
  $('#gheat').innerHTML = heatGrid(cells);
  const tot = X.total || 1;
  $('#gcats').innerHTML = rlist(X.categories, { key: 'category' }) + ((X.categories || []).length ? '' : '<p class="hint">Web categories come from web filter logs.</p>');
  $('#griskapps').innerHTML = rlist(X.riskApps, { key: 'app' });
  const ue = (X.usersInet || []).length;
  $('#gusersdata').innerHTML = rlistUD(ue ? X.usersInet : X.usersData, 'user'); $('#gusersnote').textContent = ue ? 'Internet traffic (outbound)' : 'All traffic';
  const prot = (X.subtypes || []).filter(s => s.blocked > 0).sort((a, b) => b.blocked - a.blocked).slice(0, 10).map(s => ({ name: s.name, count: s.blocked, blocked: s.blocked }));
  $('#gprot').innerHTML = rlist(prot, { key: 'subtype', color: '#e4572e', label: n => SUBN[n] || n });
}
// ------------------------------------------------------------ v5.12: traffic direction, download and upload apart
const ZN = { internet: ['To the internet', '#0e7490', 'your users and devices: browsing, cloud, updates'], inbound: ['From the internet', '#3b82c4', 'published services, VPN, scans'],
  internal: ['Internal only', '#8a6d3b', 'LAN to LAN, between sites, servers, backups'],   firewall: ['Firewalls themselves', '#9aa5b1', 'management, VPN termination, scans of the firewall'],
  infra: ['Network devices', '#c3a4d8', 'routing, multicast, switches, APs and controllers'], transit: ['Seen twice (site-to-site)', '#d9c27a', 'internal sessions also logged by the receiving firewall; counted once'],
  other: ['Other', '#c3ccd5', 'no address in the log'], pending: ['Not classified yet', '#dfe5eb', 'summarised before v5.12; being recalculated'] };
function zoneTotals(X) {
  const z = Object.fromEntries((X.zones || []).map(x => [x.name, x])), g = n => z[n] || { bytes: 0, sent: 0 };
  const known = ['internet', 'inbound', 'internal', 'firewall'].reduce((a, n) => a + g(n).bytes, 0);
  return { has: known > 0 && g('pending').bytes < known, inetDown: g('internet').bytes + g('inbound').bytes - g('internet').sent - g('inbound').sent,
    inetUp: g('internet').sent + g('inbound').sent, internal: g('internal').bytes, z };
}
function renderZones(X) {
  const rows = (X.zones || []).filter(z => z.bytes > 0), tot = rows.reduce((a, z) => a + z.bytes, 0) || 1, mx = Math.max(1, ...rows.map(z => Math.max(z.bytes - z.sent, z.sent)));
  $('#gzones').innerHTML = rows.length ? `<div class="zbar">${rows.map(z => `<i style="width:${100 * z.bytes / tot}%;background:${(ZN[z.name] || ZN.other)[1]}" title="${esc((ZN[z.name] || ZN.other)[0])}: ${bytes(z.bytes)}"></i>`).join('')}</div>
    <div class="zt">${rows.map(z => { const n = ZN[z.name] || ZN.other, d = z.bytes - z.sent; return `<div><i style="background:${n[1]}"></i><span><b>${n[0]}</b><small>${n[2]}</small></span>
      <span class="b"><em class="d" style="width:${Math.max(.5, 100 * d / mx)}%"></em><em class="u" style="width:${Math.max(.5, 100 * z.sent / mx)}%"></em></span>
      <span class="v">↓ ${bytes(d)}<br>↑ ${bytes(z.sent)}</span><b class="p">${pc(z.bytes, tot)}%</b></div>` }).join('')}</div>`
    : '<span class="muted">No traffic logs in this period.</span>';
}
let DZ = (() => { try { return localStorage.getItem('fortilog.dz') || 'inet' } catch { return 'inet' } })();
const DZS = [['inet', 'Internet'], ['internal', 'Internal only'], ['firewall', 'Firewalls'], ['all', 'All traffic']];
function renderDataCharts(X) {
  const zs = X.zseries || {}, has = Object.keys(zs).some(k => ['internet', 'inbound', 'internal'].includes(k));
  if (!has) DZ = 'all';
  $('#dzseg').innerHTML = DZS.map(([k, l]) => `<button type="button" data-dz="${k}" class="${k === DZ ? 'on' : ''}"${!has && k !== 'all' ? ' disabled' : ''}>${l}</button>`).join('');
  const ax = axis(X), down = Array(ax.n).fill(0), up = Array(ax.n).fill(0);
  const add = (t, b, s) => { const i = ax.idx(t); if (i >= 0 && i < ax.n) { up[i] += s; down[i] += Math.max(0, b - s) } };
  if (DZ === 'all') (X.series || []).forEach(b => add(b.t, b.bytes || 0, b.sent || 0));
  else ({ inet: ['internet', 'inbound'], internal: ['internal'], firewall: ['firewall'] }[DZ]).forEach(z => (zs[z] || []).forEach(([t, b, s]) => add(t, b, s)));
  const f = v => bytes(Math.round(v)), sum = a => a.reduce((x, y) => x + y, 0);
  stackChart($('#gdown'), ax, [{ name: 'Download', color: '#0e7490', vals: down }], f, 150);
  stackChart($('#gup'), ax, [{ name: 'Upload', color: '#6d5bd0', vals: up }], f, 150);
  $('#gdowntot').textContent = bytes(sum(down)); $('#guptot').textContent = bytes(sum(up));
  $('#dznote').textContent = (X.zones || []).some(z => z.name === 'pending') ? 'Older data has no direction yet (being recalculated)' : 'Each chart has its own scale';
}
$('#dzseg').addEventListener('click', e => { const b = e.target.closest('[data-dz]'); if (!b || b.disabled) return; DZ = b.dataset.dz; try { localStorage.setItem('fortilog.dz', DZ) } catch { } if (G) renderDataCharts(G) });
// ranked list with download and upload as two thin bars (same scale) instead of one total
function rlistUD(rows, key, order) {
  rows = rows || []; if (!rows.length) return '<span class="muted">No data for this filter</span>';
  const mx = Math.max(1, ...rows.map(x => Math.max((x.bytes || 0) - (x.sent || 0), x.sent || 0)));
  return `<ol class="rl ud">${rows.map((x, i) => { const k = typeof key === 'function' ? key(x.name) : key, d = Math.max(0, (x.bytes || 0) - (x.sent || 0)), u = x.sent || 0;
    return `<li${k ? ` data-k="${k}" data-v="${esc(x.name)}"` : ' class="nok"'} title="${esc(x.name)} · ↓ ${bytes(d)} · ↑ ${bytes(u)}"><span class="ri">${i + 1}</span><span class="rn">${esc(x.name)}</span>
      <span class="rb2"><i class="d" style="width:${Math.max(1, 100 * d / mx)}%"></i><i class="u" style="width:${Math.max(1, 100 * u / mx)}%"></i></span>
      <b class="${order === 'sent' ? 'su' : ''}">↓ ${bytes(d)}<br>↑ ${bytes(u)}</b>${k ? '<button class="x" title="Exclude (or Shift+click)">&minus;</button>' : ''}</li>` }).join('')}</ol>`;
}
const SUBN = { forward: 'Network traffic', local: 'Traffic to the firewall', webfilter: 'Web filter', 'app-ctrl': 'Application control', dns: 'DNS filter', virus: 'Antivirus', ips: 'Intrusion prevention', anomaly: 'DoS / anomaly', ssl: 'SSL inspection', waf: 'Web app firewall', emailfilter: 'Email filter', dlp: 'Data leak prevention', 'file-filter': 'File filter', 'virtual-patch': 'Virtual patching' };

// ------------------------------------------------------------ v5.10: AI bar and more AI widgets
function renderAIBar() {
  const why = D.modeNote ? ` (${esc(D.modeNote)})` : '';
  const mode = D.mode === 'summary' ? `<span class="mode ok" title="Answered from the hourly AI summary">Fast AI summary</span>` : `<span class="mode" title="Read from every stored log line">Raw logs</span><span class="muted">${why}</span>`;
  const empty = !D.total ? `<div class="aiempty"><b>No AI logs for this source and period.</b> ${AISRC === 'ai' ? 'If your policies have no web filter or application control profile, choose <a href="#" data-aisrc="aitraffic">Traffic logs</a> or <a href="#" data-aisrc="aiall">All AI logs</a>. ' : ''}Logs stored before the AI rules were added have no AI tag: run Settings &gt; AI detection &gt; Re-classify.</div>` : '';
  $('#aibar').innerHTML = `<div class="aisrc"><span class="lbl">AI data</span><div class="seg">${AISRCS.map(([k, l, t]) => `<button data-aisrc="${k}" class="${k === AISRC ? 'on' : ''}" title="${esc(t)}">${l}</button>`).join('')}</div><span class="aimode">${mode}</span></div>${empty}`;
}
$('#aibar').addEventListener('click', e => {
  const b = e.target.closest('[data-aisrc]'); if (!b) return; e.preventDefault();
  AISRC = b.dataset.aisrc; try { localStorage.setItem('fortilog.aisrc', AISRC) } catch { } D = null; refresh();
});
function renderAIMore() {
  // tools over time (top 6, from each tool's per-bucket counts)
  const ax = axis(D), top = (D.apps || []).filter(a => a.spark).slice(0, 6);
  if (top.length) stackChart($('#aitrend'), ax, top.map((a, i) => ({ name: a.name, color: PAL[i === 1 ? 7 : i % 8], vals: a.spark })), v => short(Math.round(v)));
  else $('#aitrend').innerHTML = '<span class="muted">No data for this filter</span>';
  $('#aitrendleg').innerHTML = top.map((a, i) => `<span data-k="tool" data-v="${esc(a.name)}"><i style="background:${PAL[i === 1 ? 7 : i % 8]}"></i>${esc(a.name)}</span>`).join('');
  // people x tools
  const ut = D.userTools || [], tools = new Map(), people = new Map();
  ut.forEach(r => { tools.set(r.tool, (tools.get(r.tool) || 0) + r.count); if (!people.has(r.user)) people.set(r.user, {}); people.get(r.user)[r.tool] = r });
  const tl = [...tools.entries()].sort((a, b) => b[1] - a[1]).slice(0, 7).map(x => x[0]);
  const pl = [...people.entries()].map(([u, m]) => [u, m, Object.values(m).reduce((a, r) => a + r.count, 0)]).sort((a, b) => b[2] - a[2]);
  const mx = Math.max(1, ...ut.map(r => r.count));
  $('#aimatrix').innerHTML = pl.length ? `<div class="tablewrap" style="max-height:none;border:0"><table class="matrix"><thead><tr><th>Person</th>${tl.map(t => `<th class="n" data-k="tool" data-v="${esc(t)}" style="cursor:pointer">${esc(t)}</th>`).join('')}<th class="n">Total</th></tr></thead><tbody>${pl.map(([u, m, sum]) =>
    `<tr><td data-k="user" data-v="${esc(u)}" class="f">${esc(u)}</td>${tl.map(t => { const r = m[t]; return `<td class="n" style="background:${r ? `rgba(14,116,144,${(.08 + .55 * r.count / mx).toFixed(2)})` : 'transparent'}" title="${r ? `${esc(u)} · ${esc(t)}: ${num(r.count)} events${r.blocked ? ', ' + num(r.blocked) + ' blocked' : ''}` : ''}">${r ? short(r.count) + (r.blocked ? `<small class="rd2"> ${pc(r.blocked, r.count)}%</small>` : '') : ''}</td>` }).join('')}<td class="n"><b>${short(sum)}</b></td></tr>`).join('')}</tbody></table></div>`
    : '<span class="muted">No AI use with a username in this period.</span>';
  $('#aiblockedusers').innerHTML = bars(D.blockedUsers, { key: 'user', color: () => '#e4572e' });
}

// ------------------------------------------------------------ v5.10: customise the layout (hide / show panels)
const HID = new Set((() => { try { return JSON.parse(localStorage.getItem('fortilog.hidden') || '[]') } catch { return [] } })());
const saveHid = () => { try { localStorage.setItem('fortilog.hidden', JSON.stringify([...HID])) } catch { } };
function applyHidden() {
  $$('#global article.card, #dashboard article.card, #policy article.card').forEach(a => {
    if (!a.dataset.w) { const h = a.querySelector('h3'); if (!h) return; a.dataset.w = a.closest('section').id + ':' + h.textContent.trim() }
    a.classList.toggle('whid', HID.has(a.dataset.w));
    let b = a.querySelector(':scope > .wtog');
    if (document.body.classList.contains('custom')) {
      if (!b) { b = document.createElement('button'); b.className = 'wtog'; b.type = 'button'; a.prepend(b) }
      b.textContent = HID.has(a.dataset.w) ? 'Show' : 'Hide';
    } else if (b) b.remove();
  });
  const n = [...HID].filter(w => w.startsWith(view + ':')).length;
  $('#custbar').innerHTML = `<b>Customise this page</b> Hide the panels you do not need: they stay hidden on this browser (handy for a wall screen). ${n ? `${n} hidden here.` : ''}<span class="sep"></span><button id="custall" type="button">Show all</button><button id="custdone" type="button" class="primary">Done</button>`;
}
document.addEventListener('click', e => {
  const t = e.target.closest('.wtog'); if (t) { const w = t.closest('article').dataset.w; HID.has(w) ? HID.delete(w) : HID.add(w); saveHid(); applyHidden(); return }
  if (e.target.id === 'custall') { [...HID].filter(w => w.startsWith(view + ':')).forEach(w => HID.delete(w)); saveHid(); applyHidden() }
  if (e.target.id === 'custdone' || e.target.id === 'customise') { document.body.classList.toggle('custom', e.target.id === 'customise' && !document.body.classList.contains('custom')); $('#custbar').hidden = !document.body.classList.contains('custom'); applyHidden() }
});

// ------------------------------------------------------------ views and refresh
const TITLES = { sites: ['Sites', 'Your sites and their zones: who is where, how busy each network is, and the subnets not described yet.'], wan: ['WAN links', 'Real usage of each internet circuit, from the firewall interface counters (SNMPv3).'], advanced: ['Advanced', 'Every log, including the network devices\' own traffic and site-to-site duplicates.'], devices: ['Devices & people', 'Who is behind each device: staff, assignments for servers and static PCs, and devices nobody is assigned to.'],
  alerts: ['Alerts', 'Detections from the logs: brute force, out-of-hours changes, silent firewalls, unusual devices.'], global: ['All logs', 'Every log from every FortiGate: traffic, security and system events.'], dashboard: ['AI overview', 'Use of AI tools, from web filter and application control logs.'],
  policy: ['AI policy and risk', 'How the firewall policy handles AI tools.'], investigate: ['AI investigation', 'AI use by one IP address or person.'],
  mapping: ['User mapping', 'Who was behind each IP address: firewall, NPS (wireless) and manual mappings.'], logs: ['Log explorer', 'Every stored log line, filtered.'], reports: ['Reports', 'Build, save and export your own reports from the stored logs.'], settings: ['Settings', 'Collector, firewalls, AI detection and NPS.'] };
function setView(v) {
  view = v; $('#title').textContent = TITLES[v][0]; $('#subtitle').textContent = TITLES[v][1];
  $$('#tabs button').forEach(b => b.classList.toggle('active', b.dataset.view === v));
  const sec = v === 'advanced' ? 'global' : v; // v5.16: Advanced is the All logs page with device traffic
  $$('main>section').forEach(x => x.hidden = x.id !== sec);
  $('#filterbar').hidden = v === 'settings' || v === 'alerts'; $('#period').hidden = v === 'logs';
  $('#f-scope').disabled = AIV.includes(v);
  $('#aibar').hidden = !AIV.includes(v);
  writeHash();
  if (v === 'settings') loadConfig(); else refresh();
}
$$('#tabs button').forEach(b => b.onclick = () => setView(b.dataset.view));

async function refresh() {
  if (view === 'settings') return;
  if (ctl) ctl.abort(); ctl = new AbortController();
  const mine = ctl, main = $('main'); main.classList.add('busy');
  try {
    if (view === 'logs') await loadLogs(mine.signal);
    else if (view === 'reports') await runReport(mine.signal);
    else if (view === 'devices') await loadDevices(mine.signal);
    else if (view === 'alerts') await loadAlerts(mine.signal);
    else if (view === 'wan') await loadWAN(mine.signal);
    else if (view === 'sites') await loadSites(mine.signal);
    else if (view === 'global' || view === 'advanced') {
      const key = qs().toString();
      if (!G || Gkey !== key || Date.now() - G._t > 30000) { const r = await api('/api/global?' + key, { signal: mine.signal }); G = r.data; G.collectors = r.collectors; G.now = r.now; G.summaries = r.summaries; G._t = Date.now(); Gkey = key }
      try { const ak = 'hours=' + (F.range === 'custom' ? '' : F.range) + (F.range === 'custom' ? '&from=' + new Date(F.from).toISOString() + '&to=' + new Date(F.to).toISOString() : '');
        if (ATTRK !== ak) { ATTR = await api('/api/attribution?' + ak, { signal: mine.signal }); ATTRK = ak } } catch (e) { if (e.name === 'AbortError') throw e; ATTR = null }
      renderGlobal(); renderAttr($('#gattr'), view === 'global' ? ATTR : null); renderAdvanced(G); applyHidden();
    } else if (view === 'mapping') { await loadMapping(mine.signal); renderMapping() }
    else {
      const key = qs().toString();
      if (!D || Dkey !== key || Date.now() - D._t > 30000) { const [d, s] = await Promise.all([api('/api/insights?' + key, { signal: mine.signal }), api('/api/status', { signal: mine.signal })]); d._t = Date.now(); D = d; Dkey = key; INV = null; $('#notice').hidden = !s.parse_partial; $('#notice').textContent = `${num(s.parse_partial)} partially parsed messages are kept as raw logs.` }
      if (view === 'investigate' && (F.src || F.user) && !INV) INV = await api('/api/investigate?' + key, { signal: mine.signal });
      renderAIBar();
      aiPeriod(); ({ dashboard: renderOverview, policy: renderPolicy, investigate: renderInvestigate })[view](); applyHidden();
    }
    $('#updated').textContent = 'Updated ' + new Date().toLocaleTimeString();
  } catch (e) {
    if (e.name === 'AbortError') return;
    const m = `<div class="notice err">${esc(e.message || 'error')}</div>`;
    if (view === 'logs') $('#logrows').innerHTML = `<tr><td colspan="${COLS.length}" class="err">${esc(e.message)}</td></tr>`; else $('#' + { global: 'gheadline', dashboard: 'headline', policy: 'ptiles', investigate: 'invbody', mapping: 'mtiles', reports: 'rout', advanced: 'gheadline', wan: 'wanstatus', sites: 'sitesbody', devices: 'dvbody', alerts: 'albody' }[view] || 'notice').innerHTML = m; if (view === 'wan') $('#wanbody').innerHTML = '';
  } finally { if (ctl === mine) main.classList.remove('busy') }
}
// Firewall -> collector -> database, shown on the All logs tab so a break in the chain is obvious.
function renderPipeline(s) {
  const el = $('#pipeline'); if (!el) return;
  const st = (ok, warn) => ok ? 'ok' : warn ? 'warn' : 'bad';
  const steps = [
    ['Received from firewalls', num(s.received), s.last_received ? 'last ' + ago(s.last_received) : 'nothing since the service started', st(s.last_received && Date.now() / 1000 - s.last_received < 300, s.last_received)],
    ['Refused or filtered', num(s.skipped), (s.keep_subtypes || []).length ? 'keeping only: ' + s.keep_subtypes.join(', ') : 'no type filter', st(!s.skipped, true)],
    ['Written to database', num(s.written), s.last_written ? 'last ' + ago(s.last_written) : 'nothing written yet', st(s.last_written && Date.now() / 1000 - s.last_written < 300, s.last_written)],
    ['Waiting', num(s.queue_depth) + ' queued · ' + num(s.spool_files) + ' spool files', s.database_connected ? 'database connected' : s.database_connecting ? 'database upgrading' + (s.database_step ? ': ' + s.database_step : '') : 'database NOT connected', st(s.database_connected && !s.spool_files, s.database_connected)],
    ['In the database', s.db_rows_5min != null ? num(s.db_rows_5min) + ' rows in last 5 min' : '–', s.db_latest_event ? 'newest log time ' + ago(s.db_latest_event) : 'no logs in the last 2 days', st(s.db_rows_5min > 0, s.db_latest_event)],
  ];
  el.innerHTML = `<div class="psteps">${steps.map(([l, v, n, c]) => `<div class="pstep ${c}"><small>${l}</small><b>${v}</b><span>${esc(n)}</span></div>`).join('<i>→</i>')}</div>` +
    (s.last_db_error ? `<p class="err">Last database problem (${ago(s.last_db_error.at)}): ${esc(s.last_db_error.error)}</p>` : '') +
    (s.quarantined ? `<p class="hint">${num(s.quarantined)} malformed log${s.quarantined === 1 ? '' : 's'} set aside in spool/quarantine since the service started${s.last_quarantine ? ` (last ${ago(s.last_quarantine.at)})` : ''}. Everything else is stored normally.</p>` : '');
}
async function health() {
  try {
    const s = await api('/api/status'), ref = Object.entries(s.refused || {});
    renderPipeline(s);
    $('#health').textContent = s.database_connected ? 'Database connected' : s.database_connecting ? 'Upgrading database… logs are queued' : 'Database unavailable · spooling';
    $('#health').className = 'badge ' + (s.database_connected ? 'ok' : 'warn');
    $('#health').title = `Received ${num(s.received)} · stored ${num(s.written)} · refused ${num(s.skipped)} · queue ${num(s.queue_depth)} · spool files ${num(s.spool_files)}`;
    if (ref.length) { $('#notice').hidden = false; $('#notice').textContent = 'Logs refused from senders not in "Other allowed sources": ' + ref.map(([ip, n]) => `${ip} (${num(n)})`).join(', ') + '. Add them in Settings, or clear that box.' }
  }
  catch { $('#health').textContent = 'API unavailable'; $('#health').className = 'badge warn' }
}
setInterval(health, 10000);
setInterval(() => { if ($('#auto').checked && !document.hidden && !['settings', 'reports', 'devices'].includes(view) && F.range !== 'custom' && $('#drawer').hidden) refresh() }, 60000);

// start once every script (settings.js too) has loaded
window.addEventListener('DOMContentLoaded', () => { readHash(); toInputs(); renderChips(); renderViews(); health(); setView(view) });
