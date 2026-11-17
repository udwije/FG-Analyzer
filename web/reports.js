// Reports tab: custom report builder, ready-made templates, saved (and shared) reports, CSV and print.
// The period and the filter bar above apply to every report.
let RF = null;            // available fields {dims, metrics}
let RS = null;            // current spec
let RID = 0;              // id of the saved report being edited (0 = new)
let RRES = null, RPIVOT = false;

const RTEMPLATES = [
  { name: 'Top users by data', group: ['user'], metrics: ['bytes', 'sent', 'received', 'events'], sort: 'bytes' },
  { name: 'Busiest source IPs', group: ['src_ip'], metrics: ['events', 'blocked', 'bytes', 'sent'], sort: 'events' },
  { name: 'Source IPs: users and destinations', group: ['src_ip'], metrics: ['events', 'users', 'destinations', 'apps', 'first_seen', 'last_seen'], sort: 'events' },
  { name: 'Events per firewall per day', group: ['fw'], bucket: 'day', metrics: ['events', 'blocked', 'blocked_pct', 'bytes'], sort: 'bucket', asc: true },
  { name: 'Traffic over time (hourly)', group: [], bucket: 'hour', metrics: ['events', 'blocked', 'bytes'], sort: 'bucket', asc: true },
  { name: 'Blocked traffic by policy', group: ['policy', 'action'], metrics: ['events', 'sources', 'users'], sort: 'events', filter: { outcome: 'blocked' } },
  { name: 'Sources with the most blocks', group: ['src_ip', 'user'], metrics: ['blocked', 'events', 'blocked_pct', 'destinations'], sort: 'blocked' },
  { name: 'Web categories by user', group: ['category', 'user'], metrics: ['events', 'blocked'], sort: 'events', filter: { subtype: 'webfilter' } },
  { name: 'Top destinations', group: ['dest'], metrics: ['events', 'blocked', 'bytes'], sort: 'events' },
  { name: 'Traffic by direction per day', group: ['zone'], bucket: 'day', metrics: ['received', 'sent', 'bytes', 'events'], sort: 'bucket', asc: true, filter: { type: 'traffic' } },
  { name: 'Data by country', group: ['country'], metrics: ['bytes', 'sent', 'received', 'events'], sort: 'bytes' },
  { name: 'Applications by risk', group: ['risk', 'application'], metrics: ['events', 'blocked', 'users', 'bytes'], sort: 'events' },
  { name: 'AI tool usage by user', group: ['tool', 'user'], metrics: ['events', 'blocked', 'sent', 'first_seen', 'last_seen'], sort: 'events', filter: { scope: 'aiall' } },
  { name: 'AI tools per day', group: ['tool'], bucket: 'day', metrics: ['events', 'users', 'sent'], sort: 'bucket', asc: true, filter: { scope: 'aiall' } },
  { name: 'Admin, VPN and system events', group: ['fw', 'msg'], metrics: ['events', 'first_seen', 'last_seen'], sort: 'events', filter: { type: 'event' } },
  { name: 'Where usernames come from', group: ['user_source'], metrics: ['events', 'users', 'sources'], sort: 'events' },
  { name: 'Severity per firewall', group: ['fw', 'level'], metrics: ['events'], sort: 'events' },
];

// report field -> dashboard filter key (for click-to-filter)
const RDRILL = { fw: 'fw', type: 'type', subtype: 'subtype', level: 'level', action: 'action', user: 'user', src_ip: 'src', dst_ip: 'dst', hostname: 'host',
  category: 'category', application: 'app', risk: 'risk', tool: 'tool', service: 'service', policy: 'policy', msg: 'msg', dest: v => destKey(v) };

const rstore = { get() { try { return JSON.parse(localStorage.getItem('fortilog.report') || 'null') } catch { return null } }, set(v) { try { localStorage.setItem('fortilog.report', JSON.stringify(v)) } catch { } } };
const defSpec = () => ({ name: 'Top users by data', group: ['user'], bucket: '', metrics: ['bytes', 'sent', 'received', 'events'], sort: 'bytes', asc: false, limit: 100, exact: false });

async function reportInit() {
  if (RF) return;
  RF = await api('/api/report/fields');
  const dopt = first => `<option value="">${first}</option>` + RF.dims.map(d => `<option value="${d.key}">${esc(d.label)}</option>`).join('');
  $('#r-g0').innerHTML = dopt('Nothing (one total)'); $('#r-g1').innerHTML = dopt('—'); $('#r-g2').innerHTML = dopt('—');
  $('#r-metrics').innerHTML = RF.metrics.map(m => `<label class="mchip" title="${m.fast ? 'Available from the fast summaries' : 'Needs a scan of the raw logs'}"><input type="checkbox" value="${m.key}">${esc(m.label)}${m.fast ? '' : ' <i>raw</i>'}</label>`).join('');
  $('#rtemplates').innerHTML = RTEMPLATES.map((t, i) => `<button class="rli" data-t="${i}">${esc(t.name)}</button>`).join('');
  RS = rstore.get() || defSpec();
  toForm();
  ['#r-g0', '#r-g1', '#r-g2', '#r-bucket'].forEach(s => $(s).onchange = () => { fromForm(); sortOptions() });
  $('#r-metrics').onchange = () => { fromForm(); sortOptions() };
  loadSaved();
}

function toForm() {
  $('#r-name').value = RS.name || '';
  ['#r-g0', '#r-g1', '#r-g2'].forEach((s, i) => $(s).value = (RS.group || [])[i] || '');
  $('#r-bucket').value = RS.bucket || '';
  $$('#r-metrics input').forEach(c => c.checked = (RS.metrics || []).includes(c.value));
  $('#r-asc').value = RS.asc ? '1' : '';
  $('#r-limit').value = String(RS.limit || 100);
  $('#r-exact').checked = !!RS.exact;
  $('#r-shared').checked = !!RS._shared;
  sortOptions();
  $('#r-sort').value = RS.sort;
  $('#r-save').textContent = RID ? 'Save changes' : 'Save';
}
function fromForm() {
  const group = ['#r-g0', '#r-g1', '#r-g2'].map(s => $(s).value).filter(Boolean).filter((v, i, a) => a.indexOf(v) === i);
  const metrics = $$('#r-metrics input').filter(c => c.checked).map(c => c.value);
  RS = { name: $('#r-name').value.trim(), group, bucket: $('#r-bucket').value, metrics: metrics.length ? metrics : ['events'], sort: $('#r-sort').value,
    asc: $('#r-asc').value === '1', limit: +$('#r-limit').value, exact: $('#r-exact').checked, _shared: $('#r-shared').checked };
  const ok = [...RS.metrics, ...RS.group, ...(RS.bucket ? ['bucket'] : [])];
  if (!ok.includes(RS.sort)) RS.sort = RS.bucket && !RS.group.length ? 'bucket' : RS.metrics[0];
  rstore.set(RS);
}
function sortOptions() {
  const cur = $('#r-sort').value || (RS && RS.sort);
  const lab = k => (RF.metrics.find(m => m.key === k) || RF.dims.find(d => d.key === k) || {}).label || k;
  const metrics = $$('#r-metrics input').filter(c => c.checked).map(c => c.value);
  const group = ['#r-g0', '#r-g1', '#r-g2'].map(s => $(s).value).filter(Boolean);
  const keys = [...metrics, ...($('#r-bucket').value ? ['bucket'] : []), ...group];
  $('#r-sort').innerHTML = keys.map(k => `<option value="${k}">${esc(k === 'bucket' ? 'Time' : lab(k))}</option>`).join('');
  if (keys.includes(cur)) $('#r-sort').value = cur;
}
const specParam = () => { const { _shared, ...s } = RS; return JSON.stringify(s) };
const reportQS = () => { const p = qs(); p.set('spec', specParam()); return p };

async function runReport(signal) {
  await reportInit();
  fromForm();
  $('#rout').innerHTML = '<p class="muted">Running the report…</p>';
  RRES = await api('/api/report?' + reportQS(), { signal });
  renderReport();
}

// ------------------------------------------------------------ rendering
const DUR = s => { s = +s || 0; const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m` };
function bucketLabel(v, b) {
  const d = new Date(v);
  if (b === 'hour') return d.toLocaleString([], { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
  if (b === 'day') return d.toLocaleDateString([], { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' });
  if (b === 'week') return 'Week of ' + d.toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' });
  if (b === 'month') return d.toLocaleDateString([], { month: 'long', year: 'numeric' });
  return ldt(v);
}
function fmtCell(c, v, b) {
  if (v === null || v === undefined) return '<span class="muted">–</span>';
  switch (c.kind) {
    case 'count': return num(v);
    case 'bytes': return bytes(+v);
    case 'pct': return (+v).toFixed(1) + '%';
    case 'seconds': return DUR(v);
    case 'time': return c.key === 'bucket' ? esc(bucketLabel(v, b)) : esc(ldt(v));
    default: return esc(v);
  }
}
function filterSummary() {
  const label = { type: 'Log type', scope: 'Scope', outcome: 'Outcome', q: 'Search', ...Object.fromEntries(FIELDS.map(f => [f.k, f.l.replace(' (exact)', '')])) };
  const parts = Object.keys(label).filter(k => F[k]).map(k => `${label[k]}: ${F[k].replace(/^=/, '').replace(/, =/g, ', ')}`);
  return parts.length ? parts.join(' · ') : 'No filters';
}
const isDim = k => RF.dims.some(d => d.key === k);

function renderReport() {
  const R = RRES, S = R.spec, cols = R.columns, si = cols.findIndex(c => c.key === S.sort);
  const isM = i => !isDim(cols[i].key) && cols[i].key !== 'bucket';
  const max = {}; cols.forEach((c, i) => { if (isM(i) && ['count', 'bytes', 'seconds'].includes(c.kind)) max[i] = Math.max(1, ...R.rows.map(r => +r[i] || 0)) });
  const a = new Date(R.from), b = new Date(R.to);
  const src = { raw: ['Raw logs', 'Exact, scanned from every stored log line'], summary: ['Summary', 'Exact, from the 5-minute summaries'], 'summary-approx': ['Summary', 'From the hourly summaries (very small rows may be missing)'] }[R.source] || [R.source, ''];
  const canPivot = S.bucket && S.group.length === 1;
  let html = `<div class="rhead"><div><h2>${esc(S.name || 'Untitled report')}</h2>
    <p class="muted">${a.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })} – ${b.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })} · ${esc(filterSummary())}</p></div>
    <div class="rmeta"><span class="mode${R.source === 'raw' ? '' : ' ok'}" title="${esc(src[1])}">${src[0]}</span> ${num(R.groups)} row${R.groups === 1 ? '' : 's'}${R.groups > R.rows.length ? `, showing ${num(R.rows.length)}` : ''} · ${(R.took_ms / 1000).toFixed(1)} s
    ${canPivot ? `<button id="r-pivot">${RPIVOT ? 'Show as list' : 'Show as table by time'}</button>` : ''}</div></div>`;
  if (R.note) html += `<p class="hint">${esc(R.note)}</p>`;
  if (S.bucket && (S.group.length === 0 || (canPivot && !RPIVOT))) html += rchart(R, S, si);
  if (canPivot && RPIVOT) html += rpivot(R, S, si);
  else {
    const head = cols.map((c, i) => `<th class="${isM(i) ? 'n ' : ''}rs${i === si ? ' on' : ''}" data-sort="${c.key}">${esc(c.label)}${i === si ? (S.asc ? ' ▲' : ' ▼') : ''}</th>`).join('');
    const body = R.rows.map(r => '<tr>' + r.map((v, i) => {
      const c = cols[i], dk = RDRILL[c.key], fk = typeof dk === 'function' ? dk(String(v)) : dk;
      if (isM(i)) {
        const bar = max[i] && i === si ? `<i class="rbar" style="width:${Math.max(1, 100 * (+v || 0) / max[i])}%"></i>` : '';
        return `<td class="n rcell">${bar}<span>${fmtCell(c, v, S.bucket)}</span></td>`;
      }
      return fk && v !== '(none)' ? `<td class="f" data-k="${fk}" data-v="${esc(v)}">${fmtCell(c, v, S.bucket)}</td>` : `<td>${fmtCell(c, v, S.bucket)}</td>`;
    }).join('') + '</tr>').join('');
    const hasKeys = cols.some((c, i) => !isM(i));
    const tot = R.totals && hasKeys ? `<tr class="rtot">${cols.map((c, i) => i === 0 ? '<td><b>Total</b></td>' : isM(i) ? `<td class="n"><b>${fmtCell(c, R.totals[c.key], S.bucket)}</b></td>` : '<td></td>').join('')}</tr>` : '';
    html += R.rows.length ? `<div class="tablewrap rtable"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody><tfoot>${tot}</tfoot></table></div>` : '<p class="muted">No logs match this period and filters.</p>';
  }
  $('#rout').innerHTML = html;
  $$('#rout th[data-sort]').forEach(th => th.onclick = () => { const k = th.dataset.sort; RS.asc = RS.sort === k ? !RS.asc : false; RS.sort = k; rstore.set(RS); toForm(); refresh() });
  if ($('#r-pivot')) $('#r-pivot').onclick = () => { RPIVOT = !RPIVOT; renderReport() };
}

// stacked bars of the sort measure (or the first count measure) over time; one series per value when grouped (top 6)
function rchart(R, S, si) {
  const cols = R.columns, bi = cols.findIndex(c => c.key === 'bucket');
  let mi = si; if (mi < 0 || ['text', 'time', 'pct'].includes(cols[mi].kind)) mi = cols.findIndex(c => ['count', 'bytes'].includes(c.kind));
  if (bi < 0 || mi < 0) return '';
  const gi = cols.findIndex(c => isDim(c.key));
  const series = new Map(), times = [...new Set(R.rows.map(r => r[bi]))].sort();
  if (times.length < 2) return '';
  R.rows.forEach(r => { const k = gi >= 0 ? r[gi] : cols[mi].label; if (!series.has(k)) series.set(k, {}); series.get(k)[r[bi]] = +r[mi] || 0 });
  const tops = [...series.entries()].map(([k, v]) => [k, v, Object.values(v).reduce((a, b) => a + b, 0)]).sort((a, b) => b[2] - a[2]).slice(0, 6);
  const W = 1000, H = 240, L = 60, B = 28, T = 10, pw = W - L - 10, ph = H - T - B, n = times.length, bw = pw / n;
  const stack = times.map(t => tops.reduce((a, [, v]) => a + (v[t] || 0), 0)), mx = Math.max(1, ...stack);
  const fmt = cols[mi].kind === 'bytes' ? bytes : short;
  let g = ''; [0, .5, 1].forEach(f => { const y = T + ph - f * ph; g += `<line x1="${L}" x2="${W - 10}" y1="${y}" y2="${y}" class="grid"/><text x="${L - 6}" y="${y + 4}" text-anchor="end">${fmt(Math.round(mx * f))}</text>` });
  const step = Math.max(1, Math.ceil(n / 8));
  times.forEach((t, i) => { if (i % step === 0) g += `<text x="${L + i * bw + bw / 2}" y="${H - 8}" text-anchor="middle">${esc(bucketLabel(t, S.bucket).replace(/^Week of /, ''))}</text>` });
  let bars = '';
  times.forEach((t, i) => { let y = T + ph; tops.forEach(([k, v], j) => { const h = (v[t] || 0) / mx * ph; if (h > 0) { y -= h; bars += `<rect x="${L + i * bw + 1}" y="${y}" width="${Math.max(1, bw - 2)}" height="${h}" fill="${PAL[j % 8]}"><title>${esc(String(k))} · ${esc(bucketLabel(t, S.bucket))}: ${fmt(v[t])}</title></rect>` } }) });
  const legend = gi >= 0 ? `<div class="clegend">${tops.map(([k], j) => `<span><i style="background:${PAL[j % 8]}"></i>${esc(String(k))}</span>`).join('')}${series.size > 6 ? `<span class="muted">+${series.size - 6} more in the table</span>` : ''}</div>` : '';
  return `<div class="chartwrap rchart"><svg viewBox="0 0 ${W} ${H}" style="cursor:default">${g}${bars}</svg></div><p class="hint" style="margin:2px 0 8px">${esc(cols[mi].label)} per ${S.bucket}${gi >= 0 ? ' (top 6 stacked)' : ''}</p>${legend}`;
}

// one row per value, one column per time bucket, cell = the sort measure
function rpivot(R, S, si) {
  const cols = R.columns, bi = cols.findIndex(c => c.key === 'bucket'), gi = cols.findIndex(c => isDim(c.key));
  let mi = si; if (mi < 0 || ['text', 'time'].includes(cols[mi].kind)) mi = cols.findIndex(c => ['count', 'bytes', 'pct', 'seconds'].includes(c.kind));
  const times = [...new Set(R.rows.map(r => r[bi]))].sort(), rows = new Map();
  R.rows.forEach(r => { if (!rows.has(r[gi])) rows.set(r[gi], {}); rows.get(r[gi])[r[bi]] = r[mi] });
  const sum = o => Object.values(o).reduce((a, b) => a + (+b || 0), 0);
  const list = [...rows.entries()].sort((a, b) => sum(b[1]) - sum(a[1]));
  const mx = Math.max(1, ...R.rows.map(r => +r[mi] || 0)), add = cols[mi].kind !== 'pct';
  const dk = RDRILL[cols[gi].key];
  return `<p class="hint">${esc(cols[mi].label)} by ${esc(cols[gi].label)} and ${S.bucket}. Darker cells are larger.</p><div class="tablewrap rtable"><table class="pivot"><thead><tr><th>${esc(cols[gi].label)}</th>${times.map(t => `<th class="n">${esc(bucketLabel(t, S.bucket).replace(/^Week of /, ''))}</th>`).join('')}${add ? '<th class="n">Total</th>' : ''}</tr></thead><tbody>${list.map(([k, v]) => {
    const fk = typeof dk === 'function' ? dk(String(k)) : dk;
    return `<tr><td${fk && k !== '(none)' ? ` class="f" data-k="${fk}" data-v="${esc(k)}"` : ''}>${esc(k)}</td>${times.map(t => { const x = v[t]; return `<td class="n" style="background:rgba(14,116,144,${x ? (0.06 + 0.5 * (+x) / mx).toFixed(2) : 0})">${x == null ? '' : fmtCell(cols[mi], x, S.bucket)}</td>` }).join('')}${add ? `<td class="n"><b>${fmtCell(cols[mi], sum(v), S.bucket)}</b></td>` : ''}</tr>`;
  }).join('')}</tbody></table></div>`;
}

// ------------------------------------------------------------ templates, saved reports, buttons
function setFilters(extra) { // a template's filters (outcome, scope, subtype...) replace those four, the rest stays
  ['type', 'scope', 'outcome', 'subtype'].forEach(k => F[k] = '');
  Object.entries(extra || {}).forEach(([k, v]) => F[k] = v);
  toInputs(); writeHash(); renderChips();
}
$('#rtemplates').onclick = e => {
  const b = e.target.closest('[data-t]'); if (!b) return;
  const t = RTEMPLATES[+b.dataset.t];
  RID = 0; RPIVOT = false;
  RS = { name: t.name, group: t.group, bucket: t.bucket || '', metrics: t.metrics, sort: t.sort, asc: !!t.asc, limit: 100, exact: false };
  rstore.set(RS); toForm(); setFilters(t.filter); refresh();
};
async function loadSaved() {
  let l = [];
  try { l = await api('/api/reports') } catch (x) { $('#rsaved').innerHTML = `<span class="err">${esc(x.message)}</span>`; return }
  const me = (ME || {}).username, admin = (ME || {}).role === 'admin';
  $('#rsaved').innerHTML = l.length ? l.map(r => `<div class="rsv"><button class="rli" data-id="${r.id}" title="Saved ${esc(ldt(r.updated))}">${esc(r.name)}</button>
    <small>${r.shared ? 'shared · ' : ''}${esc(r.owner === me ? 'yours' : r.owner)}</small>${r.owner === me || admin ? `<button class="x2" data-del="${r.id}" title="Delete">×</button>` : ''}</div>`).join('')
    : '<span class="muted">None yet. Build a report and press Save.</span>';
  $('#rsaved').onclick = async e => {
    const d = e.target.closest('[data-del]');
    if (d) { if (!confirm('Delete this saved report?')) return; try { await jsend('/api/reports?id=' + d.dataset.del, 'DELETE'); if (RID === +d.dataset.del) RID = 0; loadSaved() } catch (x) { alert(x.message) } return }
    const b = e.target.closest('[data-id]'); if (!b) return;
    const r = l.find(x => x.id === +b.dataset.id); if (!r) return;
    RID = r.owner === me || admin ? r.id : 0; RPIVOT = false;
    RS = { ...r.spec, name: r.name, _shared: r.shared }; rstore.set(RS); toForm();
    applySavedFilters(r.filters); refresh();
  };
}
// saved filters: the dashboard query string (hours or from/to, plus filter fields)
function applySavedFilters(s) {
  const p = new URLSearchParams(s || ''), keep = { ...DEF };
  if (p.get('from') && p.get('to')) { keep.range = 'custom'; keep.from = localInput(new Date(p.get('from'))); keep.to = localInput(new Date(p.get('to'))) }
  else if (p.get('hours')) keep.range = RANGES.some(r => r[0] === p.get('hours')) ? p.get('hours') : '24';
  KEYS.forEach(k => { if (!['range', 'from', 'to'].includes(k) && p.has(k)) keep[k] = p.get(k) });
  F = keep; toInputs(); writeHash(); renderChips();
}
async function saveReport(asNew) {
  fromForm();
  if (!RS.name) { const n = prompt('Name this report'); if (!n) return; RS.name = n.trim(); $('#r-name').value = RS.name }
  try {
    const { _shared, ...spec } = RS;
    const r = await jsend('/api/reports', 'POST', { id: asNew ? 0 : RID, name: RS.name, spec, filters: qs().toString(), shared: $('#r-shared').checked });
    RID = r.id; toForm(); loadSaved();
  } catch (x) { alert(x.message) }
}
$('#r-run').onclick = () => { fromForm(); refresh() };
$('#r-name').onkeydown = e => { if (e.key === 'Enter') { fromForm(); refresh() } };
$('#r-save').onclick = () => saveReport(false);
$('#r-saveas').onclick = () => { RID = 0; saveReport(true) };
$('#r-csv').onclick = () => { fromForm(); location.href = '/api/report.csv?' + reportQS() };
$('#r-print').onclick = () => { document.body.classList.add('printing-report'); window.print(); setTimeout(() => document.body.classList.remove('printing-report'), 500) };
