// Executive summary: management report laid out as A4 pages (prints / saves to PDF from the browser).
// v5.10: cover page, section choice, logo / prepared for / classification, sparklines, exclusions.
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const num = n => Number(n || 0).toLocaleString();
const big = n => { n = +n || 0; return n >= 1e9 ? (n / 1e9).toFixed(1) + ' bn' : n >= 1e6 ? (n / 1e6).toFixed(1) + ' M' : n >= 1e4 ? (n / 1e3).toFixed(0) + ' k' : num(Math.round(n)) };
const bytes = n => { n = +n || 0; if (!n) return '0 B'; const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']; let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++ } return `${n.toFixed(i ? 1 : 0)} ${u[i]}` };
const pc = (a, b) => b ? Math.round(100 * a / b) : 0;
const rate = n => { n = +n || 0; return n >= 1e9 ? (n / 1e9).toFixed(2) + ' Gbps' : n >= 1e6 ? (n / 1e6).toFixed(1) + ' Mbps' : (n / 1e3).toFixed(0) + ' kbps' };
const dt = (s, o) => new Date(s).toLocaleDateString([], o || { day: 'numeric', month: 'short', year: 'numeric' });
const dtt = s => new Date(s).toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
const dur = s => s >= 86400 ? (s / 86400).toFixed(1) + ' days' : s >= 3600 ? (s / 3600).toFixed(1) + ' h' : Math.round(s / 60) + ' min';
const PAL = ['#0e7490', '#6d5bd0', '#c2417a', '#0f9d8a', '#e08a00', '#2f9e6e', '#9aa5b1', '#d9452b', '#3b82c4', '#8a6d3b'];
const SUB = { forward: 'Network traffic', local: 'Traffic to the firewalls', webfilter: 'Web filtering', 'app-ctrl': 'Application control', dns: 'DNS filtering',
  virus: 'Antivirus', ips: 'Intrusion prevention', anomaly: 'DoS / anomaly protection', system: 'Firewall system', vpn: 'VPN', user: 'User authentication',
  sniffer: 'Monitoring', 'ssl': 'Encrypted traffic inspection', waf: 'Web application firewall', emailfilter: 'Email filtering', dlp: 'Data loss prevention', router: 'Routing', ha: 'High availability' };
const subName = s => SUB[s] || s;
const STATUS = { ok: ['Healthy', 'All checks are within their limits'], amber: ['Needs attention', 'Some items should be reviewed'], red: ['Action needed', 'Issues require action'] };
let E = null;

// ------------------------------------------------------------ options (kept in this browser)
const OPT = (() => { try { return JSON.parse(localStorage.getItem('fortilog.exec') || '{}') } catch { return {} } })();
const saveOpt = () => { try { localStorage.setItem('fortilog.exec', JSON.stringify(OPT)) } catch { alert('The logo is too large to keep in this browser; use a smaller image.') } };
OPT.sections = OPT.sections || { cover: true, summary: true, trends: true, internet: true, security: true, appendix: true };
if (OPT.sections.wan === undefined) OPT.sections.wan = true; // v5.21: Internet circuits page
if (OPT.cls === undefined) OPT.cls = 'Confidential';
$$('[data-sec]').forEach(c => { c.checked = OPT.sections[c.dataset.sec] !== false; c.onchange = () => { OPT.sections[c.dataset.sec] = c.checked; saveOpt(); if (E) render() } });
[['#o-title', 'title'], ['#o-for', 'prepFor'], ['#o-by', 'prepBy'], ['#o-cls', 'cls']].forEach(([id, k]) => { $(id).value = OPT[k] || ''; $(id).oninput = () => { OPT[k] = $(id).value; saveOpt(); if (E) render() } });
$('#o-logo').onchange = () => {
  const f = $('#o-logo').files[0]; if (!f) return;
  if (f.size > 400 * 1024) { alert('Choose a logo under 400 KB.'); return }
  const r = new FileReader(); r.onload = () => { OPT.logo = r.result; saveOpt(); if (E) render() }; r.readAsDataURL(f);
};
$('#o-nologo').onclick = () => { delete OPT.logo; saveOpt(); $('#o-logo').value = ''; if (E) render() };
$('#custbtn').onclick = e => { e.stopPropagation(); $('#custpop').hidden = !$('#custpop').hidden };
// v5.15: two tabs in Customise: this report (this browser) and the report settings (saved for everyone, admins edit)
let ES = null;
const lines = v => (v || '').split(/[\r\n,]+/).map(x => x.trim()).filter(Boolean);
const ESF = [['es-bua', 'blocked_up_amber'], ['es-bur', 'blocked_up_red'], ['es-afa', 'admin_fail_amber'], ['es-afr', 'admin_fail_red'], ['es-raa', 'risk_apps_amber'],
  ['es-rar', 'risk_apps_red'], ['es-aiu', 'ai_upload_up_amber'], ['es-dbd', 'device_blocks_day'], ['es-qam', 'quiet_amber_min'], ['es-qrh', 'quiet_red_hours']];
const ESL = [['es-src', 'exclude_sources'], ['es-dst', 'exclude_destinations'], ['es-usr', 'exclude_users'], ['es-sub', 'exclude_subtypes'], ['es-ignfw', 'ignore_firewalls'], ['es-dom', 'internal_domains']];
async function loadES() {
  $('#es-msg').textContent = 'Loading…'; $('#es-msg').className = '';
  const r = await fetch('/api/exec/settings');
  if (!r.ok) { $('#es-msg').textContent = 'Could not load the settings.'; $('#es-msg').className = 'err'; return }
  ES = await r.json(); const e = ES.exec || {};
  $('#es-org').value = e.org_name || '';
  ESF.forEach(([id, k]) => $('#' + id).value = e[k] ?? '');
  ESL.forEach(([id, k]) => $('#' + id).value = (e[k] || []).join('\n'));
  $('#es-showint').checked = !!e.show_internal_dests;
  $$('#cp-settings input, #cp-settings textarea').forEach(x => x.disabled = !ES.can_edit);
  $('#es-save').hidden = !ES.can_edit;
  $('#es-who').textContent = ES.can_edit ? 'Saved for everyone (the same values as Settings > Executive summary).' : 'Only an admin can change these. They apply to everyone.';
  $('#es-msg').textContent = '';
}
$$('[data-ct]').forEach(b => b.onclick = () => {
  $$('[data-ct]').forEach(x => x.classList.toggle('on', x === b));
  $('#cp-layout').hidden = b.dataset.ct !== 'layout'; $('#cp-settings').hidden = b.dataset.ct !== 'settings';
  if (b.dataset.ct === 'settings') loadES();
});
$('#es-save').onclick = async () => {
  const e = { ...(ES && ES.exec || {}), org_name: $('#es-org').value.trim(), show_internal_dests: $('#es-showint').checked };
  ESF.forEach(([id, k]) => e[k] = +$('#' + id).value || 0);
  ESL.forEach(([id, k]) => e[k] = lines($('#' + id).value));
  $('#es-msg').textContent = 'Saving…'; $('#es-msg').className = '';
  const r = await fetch('/api/exec/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(e) });
  const t = await r.text();
  if (!r.ok) { let m = t; try { m = JSON.parse(t).error || t } catch { } $('#es-msg').textContent = m; $('#es-msg').className = 'err'; return }
  ES = JSON.parse(t); $('#es-msg').textContent = 'Saved. Rebuilding the report…';
  fetch('/api/status').then(r => r.ok ? r.json() : null).then(s => { $('#exwrap').hidden = !(s && s.exclusions && s.exclusions.active) }).catch(() => { });
  await load(); $('#es-msg').textContent = 'Saved.';
};
document.addEventListener('click', e => { if (!e.target.closest('.pop')) $('#custpop').hidden = true });

async function load() {
  const per = $('#per').value, p = new URLSearchParams({ period: per });
  if (per === 'custom') {
    if (!$('#cf').value || !$('#ct').value) { msg('Choose From and To dates.'); return }
    p.set('from', new Date($('#cf').value + 'T00:00').toISOString()); p.set('to', new Date(new Date($('#ct').value + 'T00:00').getTime() + 864e5).toISOString());
  }
  if (!$('#exon').checked) p.set('excl', '0');
  history.replaceState(null, '', '?' + p);
  msg('Building the summary…');
  const r = await fetch('/api/exec?' + p);
  if (r.status === 401) { location.href = '/login.html?next=' + encodeURIComponent(location.pathname + location.search); return }
  const t = await r.text();
  if (!r.ok) { let m = t; try { m = JSON.parse(t).error || t } catch { } msg(m); return }
  E = JSON.parse(t); render();
}
function msg(t) { $('#msg').hidden = false; $('#msg').textContent = t; $('#doc').hidden = true }

// ------------------------------------------------------------ small chart helpers (SVG)
function trend(cur, prev, goodWhenUp) {
  if (prev == null) return '';
  if (!prev) return '<span class="tr">new this period</span>';
  const x = (cur - prev) / prev * 100;
  if (Math.abs(x) < 3) return '<span class="tr">≈ same as before</span>';
  const cls = goodWhenUp == null ? '' : (x > 0) === goodWhenUp ? (x > 0 ? 'upg' : 'down') : (x > 0 ? 'up' : 'downb');
  return `<span class="tr ${cls}">${x > 0 ? '▲' : '▼'} ${Math.abs(x) > 999 ? '>999' : Math.abs(x).toFixed(0)}% vs previous</span>`;
}
function spark(vals, color) {
  if (!vals || vals.length < 2) return '';
  const w = 260, h = 34, mx = Math.max(1, ...vals), pts = vals.map((v, i) => [i * w / (vals.length - 1), h - 3 - (v / mx) * (h - 6)]);
  const line = pts.map(p => p.map(x => x.toFixed(1)).join(',')).join(' ');
  return `<svg viewBox="0 0 ${w} ${h}" width="100%" height="${h}" preserveAspectRatio="none"><polygon points="0,${h} ${line} ${w},${h}" fill="${color}" opacity=".12"/><polyline points="${line}" fill="none" stroke="${color}" stroke-width="1.8"/></svg>`;
}
function scoreRing(ok, total, status) {
  const p = total ? ok / total : 1, c = { ok: '#1f9d63', amber: '#d98200', red: '#d9452b' }[status] || '#1f9d63';
  return `<svg class="score" viewBox="0 0 64 64" width="74" height="74"><circle cx="32" cy="32" r="27" fill="#fff" stroke="#e6ebf0" stroke-width="7"/><circle cx="32" cy="32" r="27" fill="none" stroke="${c}" stroke-width="7" stroke-linecap="round" pathLength="100" stroke-dasharray="${(p * 100).toFixed(1)} 100" transform="rotate(-90 32 32)"/><text x="32" y="31" text-anchor="middle" style="font:700 15px var(--sans);fill:#14263a">${ok}/${total}</text><text x="32" y="44" text-anchor="middle" style="font-size:8px;fill:#5d7083">checks OK</text></svg>`;
}
// grouped bars: one bar per key, side by side, for each time unit (download and upload are compared, not added up)
function grouped(series, keys, colors, labels, fmt, unit, H = 220) {
  if (!series.length) return '<p class="muted">No data in this period.</p>';
  const W = 940, L = 64, B = 30, T = 10, pw = W - L - 6, ph = H - T - B, n = series.length, bw = pw / n, k = keys.length;
  const mx = Math.max(1, ...series.flatMap(s => keys.map(x => +s[x] || 0)));
  let g = ''; [0, .25, .5, .75, 1].forEach(f => { const y = T + ph - f * ph; g += `<line x1="${L}" x2="${W - 6}" y1="${y}" y2="${y}" class="grid"/><text x="${L - 6}" y="${y + 4}" text-anchor="end">${fmt(mx * f)}</text>` });
  const step = Math.max(1, Math.ceil(n / 10));
  series.forEach((s, i) => { if (i % step === 0) g += `<text x="${L + i * bw + bw / 2}" y="${H - 9}" text-anchor="middle">${esc(unit === 'hour' ? new Date(s.t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : dt(s.t, { day: 'numeric', month: 'short' }))}</text>` });
  const gw = bw * .78, w = gw / k;
  let b = '';
  series.forEach((s, i) => keys.forEach((key, j) => { const v = +s[key] || 0, h = v / mx * ph; if (h > 0) b += `<rect x="${L + i * bw + (bw - gw) / 2 + j * w + .5}" y="${T + ph - h}" width="${Math.max(1, w - 1)}" height="${h}" fill="${colors[j]}" rx="2"><title>${esc(labels[j])}: ${fmt(v)}</title></rect>` }));
  const tot = keys.map(key => series.reduce((a, s) => a + (+s[key] || 0), 0));
  return `<svg viewBox="0 0 ${W} ${H}" style="width:100%">${g}${b}</svg><div class="legend">${labels.map((l, j) => `<span><i style="background:${colors[j]}"></i>${esc(l)} <b>${fmt(tot[j])}</b></span>`).join('')}</div>`;
}
function stacked(series, keys, colors, labels, fmt, unit, H = 230) {
  if (!series.length) return '<p class="muted">No data in this period.</p>';
  const W = 940, L = 64, B = 30, T = 10, pw = W - L - 6, ph = H - T - B, n = series.length, bw = pw / n;
  const tot = series.map(s => keys.reduce((a, k) => a + (+s[k] || 0), 0)), mx = Math.max(1, ...tot);
  let g = ''; [0, .25, .5, .75, 1].forEach(f => { const y = T + ph - f * ph; g += `<line x1="${L}" x2="${W - 6}" y1="${y}" y2="${y}" class="grid"/><text x="${L - 6}" y="${y + 4}" text-anchor="end">${fmt(mx * f)}</text>` });
  const step = Math.max(1, Math.ceil(n / 10));
  series.forEach((s, i) => { if (i % step === 0) g += `<text x="${L + i * bw + bw / 2}" y="${H - 9}" text-anchor="middle">${esc(unit === 'hour' ? new Date(s.t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : dt(s.t, { day: 'numeric', month: 'short' }))}</text>` });
  let b = '';
  series.forEach((s, i) => { let y = T + ph; keys.forEach((k, j) => { const h = (+s[k] || 0) / mx * ph; if (h > 0) { y -= h; b += `<rect x="${L + i * bw + bw * .14}" y="${y}" width="${bw * .72}" height="${h}" fill="${colors[j]}" rx="2"><title>${esc(labels[j])}: ${fmt(s[k])}</title></rect>` } }) });
  return `<svg viewBox="0 0 ${W} ${H}" style="width:100%">${g}${b}</svg><div class="legend">${labels.map((l, j) => `<span><i style="background:${colors[j]}"></i>${esc(l)}</span>`).join('')}</div>`;
}
function hbars(rows, val, fmt, color, label) {
  rows = (rows || []).filter(r => +r[val] > 0); if (!rows.length) return '<p class="muted">Nothing in this period.</p>';
  const mx = Math.max(...rows.map(r => +r[val]));
  return `<div class="hb">${rows.map((r, i) => `<div><span title="${esc(label ? label(r) : r.name)}">${esc(label ? label(r) : r.name)}</span><em style="width:${Math.max(1.5, 100 * r[val] / mx)}%;background:${typeof color === 'function' ? color(r, i) : color}"></em><b>${fmt(r[val])}</b></div>`).join('')}</div>`;
}
function donut(parts, centre, sub) {
  parts = parts.filter(p => p.v > 0); const tot = parts.reduce((a, p) => a + p.v, 0) || 1; let a = -Math.PI / 2, paths = '';
  const R = 80, r = 52, c = 85, P = (rad, ang) => `${(c + rad * Math.cos(ang)).toFixed(2)} ${(c + rad * Math.sin(ang)).toFixed(2)}`;
  parts.forEach((p, i) => { const f = p.v / tot, b = a + f * 2 * Math.PI, lg = f > .5 ? 1 : 0;
    paths += f > .9999 ? `<circle cx="${c}" cy="${c}" r="${(R + r) / 2}" fill="none" stroke="${PAL[i % 10]}" stroke-width="${R - r}"/>` : `<path d="M${P(R, a)} A${R} ${R} 0 ${lg} 1 ${P(R, b)} L${P(r, b)} A${r} ${r} 0 ${lg} 0 ${P(r, a)}Z" fill="${PAL[i % 10]}" stroke="#fff" stroke-width="1.5"><title>${esc(p.n)}: ${pc(p.v, tot)}%</title></path>`; a = b });
  return `<div class="donut"><svg viewBox="0 0 170 170">${paths}<text x="${c}" y="${c + 2}" text-anchor="middle" style="font:600 20px var(--serif);fill:#14263a">${esc(centre)}</text><text x="${c}" y="${c + 18}" text-anchor="middle">${esc(sub)}</text></svg>
    <ul>${parts.map((p, i) => `<li><i style="background:${PAL[i % 10]}"></i>${esc(p.n)} <b>${pc(p.v, tot)}%</b></li>`).join('')}</ul></div>`;
}
// download and upload as two separate bars per row (same scale), not one bar
function updown(rows) {
  rows = (rows || []).slice(0, 8); if (!rows.length) return '<p class="muted">Nothing in this period.</p>';
  const mx = Math.max(1, ...rows.map(r => Math.max(+r.bytes - +r.sent, +r.sent)));
  return `<div class="ud">${rows.map(r => { const d = +r.bytes - +r.sent, u = +r.sent; return `<div><span title="${esc(r.name)}">${esc(r.name)}</span><span class="b"><em class="d" style="width:${Math.max(.5, 100 * d / mx)}%"></em><em class="u" style="width:${Math.max(.5, 100 * u / mx)}%"></em></span><span class="n">↓ ${bytes(d)}<br>↑ ${bytes(u)}</span></div>` }).join('')}</div>
    <div class="legend"><span><i style="background:#0e7490"></i>Download</span><span><i style="background:#6d5bd0"></i>Upload</span></div>`;
}
const table = (head, rows, empty = 'Nothing in this period.') => rows.length ? `<table><thead><tr>${head.map(h => `<th${h[1] ? ' class="n"' : ''}>${h[0]}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>` : `<p class="muted">${empty}</p>`;

// ------------------------------------------------------------ pages
const initials = s => (s || 'N').split(/\s+/).filter(Boolean).slice(0, 2).map(w => w[0].toUpperCase()).join('');
const mark = () => `<div class="mark">${OPT.logo ? `<img src="${esc(OPT.logo)}" alt="">` : esc(initials(E.org))}</div>`;
function header(no, title, sub) {
  const P = E.period;
  return `<div class="ph"><div><div class="sec">${String(no).padStart(2, '0')} · ${esc(E.org)}</div><h1>${esc(title)}</h1>${sub ? `<div class="sub">${esc(sub)}</div>` : ''}</div>
    <div class="per"><div><b>${esc(P.label)}</b>${dt(P.from)} – ${dt(new Date(new Date(P.to) - 1))}</div>${mark()}</div></div>`;
}
let PG = 0, NPG = 0;
const footer = () => `<div class="pf"><span>${OPT.cls ? `<span class="cls">${esc(OPT.cls)}</span> · ` : ''}${esc(E.org)} · ${esc(OPT.title || 'Network and Security Report')}</span><span>Generated ${dtt(E.generated)} · Page ${++PG} of ${NPG}</span></div>`;
const page = (no, title, sub, body) => `<section class="page">${header(no, title, sub)}<div class="pb">${body}</div>${footer()}</section>`;
// v5.11: every page is a fixed A4 sheet (1060 x 1499 px, printed at 74.85%). Content that does not fit is scaled down
// (never below 62%) instead of spilling onto an extra, almost empty page.
function fitPages() {
  $$('#doc .page').forEach(pg => {
    const pb = pg.querySelector('.pb'); if (!pb) return;
    pb.style.transform = ''; pb.style.width = '';
    const foot = pg.querySelector('.pf'), notes = pg.querySelector('.dnotes');
    const limit = (notes || foot).getBoundingClientRect().top - 14, top = pb.getBoundingClientRect().top;
    if (top + pb.scrollHeight <= limit) return;
    let z = 1;
    for (let i = 0; i < 4; i++) {
      z = Math.max(.62, Math.min(z, (limit - top) / pb.scrollHeight * z));
      pb.style.width = (100 / z).toFixed(2) + '%';
      if (top + pb.scrollHeight * z <= limit || z === .62) break;
    }
    pb.style.transform = `scale(${z.toFixed(4)})`;
  });
}

function exclLine() {
  const X = E.exclusions || {};
  if (!X.active) return '';
  if (!X.applied) return `<div class="exn">ℹ️<div><b>All traffic is included.</b> Exclusions are configured but switched off for this report.</div></div>`;
  const rm = X.removed || {};
  return `<div class="exn">⊘<div><b>Excluded from this report:</b> ${esc((X.rules || []).join(' · '))}. That removed ${big(rm.events)} events and ${bytes(rm.bytes)} of data${X.coverage < 99.5 ? ` (applied to ${Math.round(X.coverage)}% of the period so far)` : ''}.</div></div>`;
}

function render() {
  PG = 0;
  const S = OPT.sections, C = E.cur, P = E.prev, fws = E.firewalls || [], st = E.status || 'ok';
  const mon = fws.filter(f => f.monitored !== false), col = E.collector || {};
  const avg = mon.length ? mon.reduce((a, f) => a + (+f.availability || 0), 0) / mon.length : 0;
  const zok = C.inet_bytes > 0 && C.pending_bytes * 100 <= C.bytes; // v5.12: traffic directions known for this period
  const live = mon.filter(f => (f.quiet || 0) < 3600).length, okChecks = E.checks.filter(c => c.status === 'ok' || c.status === 'na').length;
  const ser = E.series || [], u = E.series_unit;
  const kpi = (l, v, sub, tr, sp) => `<div class="kpi"><small>${l}</small><b>${v}</b><div class="s">${sub}</div>${tr || ''}${sp || ''}</div>`;
  const pages = [];

  // cover
  if (S.cover) pages.push(() => `<section class="page cover"><div class="cv-top"><div class="cv-brand">${mark()}<div class="org">${esc(E.org)}</div></div>
    <div class="cv-title"><div class="kick">Executive report</div><h1>${esc(OPT.title || 'Network and Security Report')}</h1><div class="per">${esc(E.period.label)} · ${dt(E.period.from)} – ${dt(new Date(new Date(E.period.to) - 1))}</div>
    <div class="cv-status ${st}"><i></i>${esc(E.headline)}</div></div></div>
    <div class="cv-body"><div class="cv-nums"><div><small>Network activity</small><b>${big(C.events)}</b><span>events logged · ${trend(C.events, P && P.events, null)}</span></div>
      <div><small>Blocked by policy</small><b>${pc(C.blocked, C.events)}%</b><span>${big(C.blocked)} events · ${trend(C.blocked, P && P.blocked, false)}</span></div>
      ${zok ? `<div><small>Internet traffic</small><b>${bytes(C.inet_bytes)}</b><span>↓ ${bytes(C.inet_bytes - C.inet_sent)} · ↑ ${bytes(C.inet_sent)}${C.int_bytes ? ` · ${bytes(C.int_bytes)} internal only` : ''}</span></div>`
          : `<div><small>Data transferred</small><b>${bytes(C.bytes)}</b><span>${num(C.devices)} internal devices · ${num(C.users)} people</span></div>`}</div>
      <div class="cv-head">${esc((E.story || [])[0] || '')}</div>
      <div class="cv-toc">${[['summary', 'Summary', 'status, headline figures, what needs attention'], ['trends', 'Trends', 'activity, data and firewall availability'], ['internet', 'Internet and AI use', 'websites, destinations, AI tools'], ['security', 'Security posture', 'what was stopped and what to look at'], ['wan', 'Internet circuits', 'usage, link quality, tunnels and incidents'], ['appendix', 'Appendix', 'details for the IT team']].filter(x => S[x[0]]).map((x, i) => `<div><b>${String(i + 1).padStart(2, '0')}</b><span>${x[1]}</span><em>${x[2]}</em></div>`).join('')}</div>
      <div class="cv-meta"><div><small>Prepared for</small><b>${esc(OPT.prepFor || 'Management')}</b></div><div><small>Prepared by</small><b>${esc(OPT.prepBy || 'IT Security')}</b></div><div><small>Generated</small><b>${dtt(E.generated)}</b></div></div></div>
    ${footer()}</section>`);
  let no = 0;
  if (S.summary) pages.push(() => page(++no, 'Executive summary', '', `
    <div class="status st-${st}">${scoreRing(okChecks, E.checks.length, st)}<div><h2>${esc(E.headline)}</h2><p>${STATUS[st][1]}. ${P ? `Compared with ${dt(E.period.prev_from)} – ${dt(new Date(new Date(E.period.prev_to) - 1))}.` : 'No comparison yet: the stored logs do not reach back to the period before.'}</p></div></div>
    <div class="kpis">${kpi('Network activity', big(C.events), 'events logged', trend(C.events, P && P.events, null), spark(ser.map(s => s.events), '#0e7490'))}
      ${kpi('Blocked by security policy', big(C.blocked), `${pc(C.blocked, C.events)}% of all activity`, trend(C.blocked, P && P.blocked, false), spark(ser.map(s => s.blocked), '#d9452b'))}
      ${zok ? kpi('Internet traffic', bytes(C.inet_bytes), `↓ ${bytes(C.inet_bytes - C.inet_sent)} download · ↑ ${bytes(C.inet_sent)} upload`, trend(C.inet_bytes, P && P.inet_bytes, null), spark(ser.map(s => (+s.inet_down || 0) + (+s.inet_up || 0)), '#6d5bd0'))
        : kpi('Data transferred', bytes(C.bytes), `${bytes(C.bytes - C.sent)} down · ${bytes(C.sent)} up`, trend(C.bytes, P && P.bytes, null), spark(ser.map(s => (+s.down || 0) + (+s.up || 0)), '#6d5bd0'))}
      ${kpi('People and devices', `${num(C.users)} · ${num(C.devices)}`, 'named users · internal devices', trend(C.devices, P && P.devices, null))}
      ${kpi('Firewall availability', avg.toFixed(1) + '%', `${live} of ${mon.length} reporting now${col.longest_gap >= 600 ? ' · collection stopped ' + dur(col.longest_gap) : ''}`, '')}
      ${kpi('AI tools in use', num(C.ai_tools), `${bytes(C.ai_sent)} uploaded to them`, trend(C.ai_sent, P && P.ai_sent, false))}</div>
    ${exclLine()}
    <div class="cols"><div><h2 class="s">What happened</h2><ol class="story">${E.story.map(s => `<li><span>${esc(s)}</span></li>`).join('')}</ol></div>
      <div><h2 class="s">Needs attention</h2><div class="att">${E.findings.length ? E.findings.slice(0, 4).map(f => `<div class="it ${f.status}"><b><span class="tag ${f.status}">${f.status === 'red' ? 'Act' : 'Review'}</span>${esc(f.title)}</b><p>${esc(f.detail)}</p><p class="act"><b style="display:inline">Recommended:</b> ${esc(f.action)}</p></div>`).join('')
        : '<div class="it none"><b>Nothing needs attention</b><p>All checks are within their limits for this period.</p></div>'}${E.findings.length > 4 ? `<p class="notes">${E.findings.length - 4} more in the health checks below.</p>` : ''}</div></div></div>
    <h2 class="s" style="margin-top:26px">Health checks</h2>
    <div class="hc">${E.checks.map(c => `<div><i class="light l-${c.status}"></i><b>${esc(c.label)}</b><span class="pill ${c.status}">${{ ok: 'OK', amber: 'Review', red: 'Act', na: 'n/a' }[c.status] || c.status}</span><span class="v">${esc(c.value)}</span><span class="d">${esc(c.detail)}</span></div>`).join('')}</div>`));

  const Zs = C.zones || {}, zv = k => Zs[k] || [0, 0];
  const zrow = (k, l, c, desc) => { const [b, up] = zv(k); return b > 0 ? `<div><i style="background:${c}"></i><span>${l}<small>${desc}</small></span><span class="n">${bytes(b - up)}</span><span class="n">${bytes(up)}</span><b>${bytes(b)}</b></div>` : '' };
  const zones = () => {
          const Z = [['#0e7490', zv('internet')[0]], ['#3b82c4', zv('inbound')[0]], ['#8a6d3b', zv('internal')[0]], ['#9aa5b1', zv('firewall')[0]], ['#c3a4d8', zv('infra')[0]]], tot = Z.reduce((a, z) => a + (z[1] || 0), 0) || 1;
    return `<div class="zbar">${Z.map(([c, v]) => v > 0 ? `<i style="width:${100 * v / tot}%;background:${c}" title="${bytes(v)}"></i>` : '').join('')}</div>
      <div class="zl"><div class="h"><span></span><span>Direction</span><span class="n">Download</span><span class="n">Upload</span><span class="n">Total</span></div>
      ${zrow('internet', 'To the internet', '#0e7490', 'your users and devices: browsing, cloud, updates')}
      ${zrow('inbound', 'From the internet', '#3b82c4', 'published services, VPN, scans')}
      ${zrow('internal', 'Internal only', '#8a6d3b', 'LAN to LAN, between sites, servers and backups')}
              ${zrow('firewall', 'Firewalls themselves', '#9aa5b1', 'management, VPN termination, scans of the firewall')}
        ${zrow('infra', 'Network devices', '#c3a4d8', 'routing, multicast, switches, APs and controllers')}</div>
        <p class="hint" style="margin-top:6px">Download and upload are from your devices' point of view. Network-device traffic is not counted in the figures above it.</p>`;
  };
  if (S.trends) pages.push(() => page(++no, 'Trends', 'How activity and data volume changed over the period.', `<div class="g2"><div class="box full"><h3>Network activity per ${u}</h3><p class="hint">Allowed and blocked activity across all firewalls.</p>
      ${stacked(ser.map(s => ({ ...s, allowed: s.events - s.blocked })), ['allowed', 'blocked'], ['#0e7490', '#d9452b'], ['Allowed', 'Blocked by policy'], big, u, 200)}</div>
    ${zok ? `<div class="box full"><h3>Internet data per ${u}</h3><p class="hint">Download and upload side by side. Internet traffic only (to and from public addresses).</p>
      ${grouped(ser, ['inet_down', 'inet_up'], ['#0e7490', '#6d5bd0'], ['Downloaded', 'Uploaded'], bytes, u, 200)}</div>
    <div class="box full"><h3>Internal only, per ${u}</h3><p class="hint">Traffic that never left your network (LAN to LAN, between sites, servers and backups).</p>${grouped(ser, ['int_down', 'int_up'], ['#8a6d3b', '#c9a26b'], ['Download', 'Upload'], bytes, u, 160)}</div>
    <div class="box"><h3>Where the traffic goes</h3><p class="hint">All data through the firewalls, by direction.</p>${zones()}</div>`
      : `<div class="box full"><h3>Data volume per ${u}</h3><p class="hint">Download and upload side by side.</p>${grouped(ser, ['down', 'up'], ['#0e7490', '#6d5bd0'], ['Downloaded', 'Uploaded'], bytes, u, 200)}</div>`}
    <div class="box"><h3>Firewalls</h3><p class="hint">Share of the activity, and of the period each firewall was sending logs.</p>
      ${table([['Firewall'], ['Share', 1], ['Available', 1], ['Longest silence', 1]], fws.map(f => `<tr${f.monitored === false ? ' class="fwoff"' : ''}><td><i class="light l-${f.monitored === false ? 'na' : f.missing || f.longest_gap >= 86400 ? 'red' : f.longest_gap >= 3600 ? 'amber' : 'ok'}"></i>${esc(f.name)}${f.monitored === false ? ' <small>(not monitored)</small>' : ''}</td><td class="n">${pc(+f.events, mon.reduce((a, x) => a + +x.events, 0))}%</td><td class="n">${f.missing ? 'no logs' : (+f.availability).toFixed(1) + '%'}</td><td class="n">${f.longest_gap > 600 ? dur(f.longest_gap) : 'none'}</td></tr>`))}
              ${(E.wan || []).length ? '' : ''}<p class="coll">${col.slots ? `LogSikka was collecting <b>${(+col.coverage || 0).toFixed(1)}%</b> of the time${col.longest_gap >= 600 ? `; longest stop <b>${dur(col.longest_gap)}</b> (not counted against the firewalls)` : ''}.` : ''}</p></div>${(E.wan || []).length && !(S.wan && wanPageOK()) ? `<div class="box full"><h3>Internet circuits (measured on the firewall interfaces)</h3><p class="hint">From the interface counters over SNMPv3. 95th percentile = what the circuit carried 95% of the time; busy = share of the time above 80% of the contracted capacity.</p>
        ${table([['Circuit'], ['Capacity', 1], ['Average ↓ / ↑', 1], ['95th pct ↓ / ↑', 1], ['Peak ↓ / ↑', 1], ['Busy ↓', 1]], E.wan.filter(l => l.samples).map(l => `<tr><td><b>${esc(l.label)}</b> <small>${esc(l.dev)}</small></td><td class="n">${l.down_mbps ? l.down_mbps + ' Mbps' : '–'}</td><td class="n">${rate(l.avg_down)} / ${rate(l.avg_up)}</td><td class="n">${rate(l.p95_down)} / ${rate(l.p95_up)}${l.down_mbps ? ` <small>(${pc(l.p95_down, l.down_mbps * 1e6)}%)</small>` : ''}</td><td class="n">${rate(l.peak_down)} / ${rate(l.peak_up)}</td><td class="n">${pc(l.busy_down, l.samples)}%</td></tr>`), 'No WAN samples in this period.')}</div>` : ''}</div>`));

  const cats = E.categories || [], ai = E.ai || [], T = E.top || {};
  if (S.internet) pages.push(() => page(++no, 'Internet and AI use', 'Websites, services and AI tools.', `<div class="g2"><div class="box"><h3>What websites are used for</h3><p class="hint">Web filter categories, by visits.</p>${cats.length ? donut(cats.slice(0, 8).map(c => ({ n: c.name, v: +c.count })), big(cats.reduce((a, c) => a + +c.count, 0)), 'web visits') : '<p class="muted">No web filter data in this period.</p>'}</div>
    <div class="box"><h3>Most used destinations</h3><p class="hint">Internet sites and services by activity.</p>${hbars((T.dests || []).slice(0, 8), 'count', big, '#0e7490')}</div>
    <div class="box full"><h3>AI tools</h3><p class="hint">Generative AI services seen on the network.</p>
      ${table([['Tool'], ['People', 1], ['Devices', 1], ['Activity', 1], ['Uploaded', 1], ['Blocked', 1]], ai.slice(0, 10).map(t => `<tr><td>${esc(t.name)}${t.new ? ' <span class="pill new">New</span>' : ''}</td><td class="n">${t.users != null ? num(t.users) : '–'}</td><td class="n">${t.devices != null ? num(t.devices) : '–'}</td><td class="n">${big(t.events)}</td><td class="n">${bytes(t.sent)}</td><td class="n">${pc(t.blocked, t.events)}%</td></tr>`), 'No AI tools seen in this period.')}</div>
    <div class="box"><h3>Data by destination country</h3><p class="hint">Internet traffic, download and upload combined.</p>${hbars((T.countries || []).slice(0, 8), 'bytes', bytes, '#0f9d8a')}</div>
    <div class="box"><h3>Top users by ${T.inetLists ? 'internet ' : ''}data</h3><p class="hint">Download and upload of each person${T.inetLists ? ', internet traffic only' : ''}.</p>${updown(T.usersData)}</div>
    <div class="box"><h3>Top destinations by ${T.inetLists ? 'internet ' : ''}data</h3><p class="hint">Where the data went.</p>${updown(T.whereData)}</div>
    <div class="box"><h3>Most used applications</h3><p class="hint">By activity.</p>${hbars((T.apps || []).slice(0, 8), 'count', big, '#6d5bd0')}</div></div>`));

  const subs = (E.subtypes || []).filter(s => +s.blocked > 0), si = E.signins || {};
  if (S.security) pages.push(() => page(++no, 'Security posture', 'What the firewalls stopped, and what to look at.', `<div class="g2"><div class="box"><h3>What was blocked</h3><p class="hint">Blocked activity by type of protection.</p>${hbars(subs.sort((a, b) => b.blocked - a.blocked).slice(0, 8), 'blocked', big, '#d9452b', r => subName(r.name))}</div>
    <div class="box"><h3>Sign-ins and changes</h3><p class="hint">Firewall administration and VPN.</p>
      ${table([['Event'], ['Count', 1]], [['Failed admin sign-ins', si.failed_admin], ['Failed VPN sign-ins', si.failed_vpn], ['…of which from the internet', si.from_internet], ['Successful sign-ins', si.success], ['Configuration changes', si.config_changes]].map(([l, v]) => `<tr><td>${l}</td><td class="n">${v == null ? '–' : num(v)}</td></tr>`))}</div>
    <div class="box full"><h3>Devices with unusual blocked activity</h3><p class="hint">Devices that keep trying connections the policy blocks — often unwanted software, malware or a misconfiguration.</p>
      ${table([['Device'], ['User'], ['Mostly trying to reach'], ['Blocked', 1], ['Per day', 1]], (E.devices || []).map(d => `<tr><td>${esc(d.ip)}</td><td>${esc(d.user || '–')}</td><td>${esc(d.top || '–')}</td><td class="n">${big(d.blocked)}</td><td class="n">${big(d.per_day)}</td></tr>`), 'No device exceeded the limit.')}</div>
    <div class="box"><h3>Failed sign-ins: top sources</h3>${table([['Source'], ['Account'], ['Type'], ['Count', 1]], (si.top || []).slice(0, 8).map(t => `<tr><td>${esc(t.source)}${t.internet ? ' <span class="pill web">internet</span>' : ''}</td><td>${esc(t.user)}</td><td>${esc(t.kind)}</td><td class="n">${num(t.count)}</td></tr>`), 'No failed sign-ins.')}</div>
    <div class="box"><h3>High-risk applications allowed</h3>${table([['Application'], ['Allowed', 1], ['Blocked', 1]], (E.risk_apps || []).slice(0, 8).map(r => `<tr><td>${esc(r.name)}</td><td class="n">${big(r.count - r.blocked)}</td><td class="n">${big(r.blocked)}</td></tr>`), 'None allowed.')}</div></div>`));

  const tt = (rows, head, f) => table(head, (rows || []).slice(0, 10).map(f));
  const X = E.exclusions || {};
  // v5.21: Internet circuits (WAN links over SNMPv3: usage, data used, link quality, IPsec tunnels, incidents)
  const W = E.wan_page;
  if (S.wan && wanPageOK()) pages.push(() => {
    const L = (W.links || []).filter(l => l.samples), Q = W.quality || [], T = W.tunnels || [], I = W.incidents || [];
    const sum = k => L.reduce((a, l) => a + (+l[k] || 0), 0);
    const qAvg = Q.length ? Q.reduce((a, q) => a + q.quality_pct, 0) / Q.length : null;
    const tAvg = T.length ? T.reduce((a, t) => a + t.uptime_pct, 0) / T.length : null;
    const qCls = v => v == null ? '' : v >= 99 ? 'qok' : v >= 95 ? 'qam' : 'qred';
    const qualOf = l => { const m = Q.filter(q => q.dev === l.dev && q.iface === l.iface); return m.length ? Math.min(...m.map(q => q.quality_pct)) : null };
    const capPct = (v, mb) => mb ? ` <small>(${pc(v, mb * 1e6)}%)</small>` : '';
    const KIND = { wan_busy: 'Near capacity', wan_sla: 'SD-WAN member', wan_tunnel: 'Tunnel down', fw_load: 'Firewall load', wan_poll: 'Not answering' };
    return page(++no, 'Internet circuits', 'What each circuit carried, how good the links were, and what went wrong.', `
      <div class="kpis">${kpi('Circuits', num(L.length), 'measured on the firewall interfaces', '')}
        ${kpi('Data downloaded', bytes(sum('data_down')), 'all circuits, from the interface counters', '')}
        ${kpi('Data uploaded', bytes(sum('data_up')), 'all circuits', '')}
        ${kpi('Link quality', qAvg == null ? '–' : qAvg.toFixed(1) + '%', 'time alive, under 2% loss and 150 ms', '')}
        ${kpi('Tunnel uptime', tAvg == null ? '–' : tAvg.toFixed(2) + '%', `${T.reduce((a, t) => a + t.tunnels, 0)} IPsec tunnels`, '')}
        ${kpi('Incidents', num(I.length), 'WAN alerts in the period', '')}</div>
      <div class="g2"><div class="box full"><h3>Usage against capacity</h3><p class="hint">95th percentile = what the circuit carried 95% of the time (what you size and pay for). Busy = share of the time above 80% of capacity.</p>
        ${table([['Circuit'], ['Capacity', 1], ['Data used ↓ / ↑', 1], ['Average ↓ / ↑', 1], ['95th pct ↓', 1], ['Peak ↓', 1], ['Busy ↓', 1], ['Link quality', 1]], L.map(l => { const q = qualOf(l); return `<tr>
          <td><b>${esc(l.label)}</b> <small>${esc(l.dev)} · ${esc(l.iface)}</small></td><td class="n">${l.down_mbps ? l.down_mbps + ' Mbps' : '–'}</td>
          <td class="n">${bytes(l.data_down)} / ${bytes(l.data_up)}</td><td class="n">${rate(l.avg_down)} / ${rate(l.avg_up)}</td>
          <td class="n">${rate(l.p95_down)}${capPct(l.p95_down, l.down_mbps)}</td><td class="n">${rate(l.peak_down)}</td><td class="n">${pc(l.busy_down, l.samples)}%</td>
          <td class="n"><span class="q ${qCls(q)}">${q == null ? '–' : q.toFixed(1) + '%'}</span></td></tr>` }), 'No WAN samples in this period.')}</div>
      <div class="box"><h3>Link quality by SD-WAN member</h3><p class="hint">Share of the time the member was alive with under 2% packet loss and under 150 ms (worst health check).</p>
        ${table([['Member'], ['Quality', 1], ['Latency', 1], ['Loss', 1], ['Down', 1]], Q.map(q => `<tr><td>${esc(q.iface)} <small>${esc(q.dev)}</small></td>
          <td class="n"><span class="q ${qCls(q.quality_pct)}">${q.quality_pct.toFixed(1)}%</span></td><td class="n">${q.latency_ms.toFixed(0)} ms</td><td class="n">${q.loss_pct.toFixed(1)}%</td>
          <td class="n">${q.dead_samples ? pc(q.dead_samples, q.samples) + '%' : 'never'}</td></tr>`), 'No SD-WAN health data in this period (stored from v5.21 on).')}</div>
      <div class="box"><h3>IPsec tunnels</h3><p class="hint">Average uptime of the tunnels that were up at least once; drops = times a tunnel went down.</p>
        ${table([['Firewall'], ['Tunnels', 1], ['Uptime', 1], ['Drops', 1], ['Least available']], T.map(t => `<tr><td>${esc(t.dev)}</td><td class="n">${t.tunnels}</td>
          <td class="n"><span class="q ${qCls(t.uptime_pct)}">${t.uptime_pct.toFixed(2)}%</span></td><td class="n">${num(t.drops)}</td><td>${esc(t.worst)} <small>${t.worst_pct.toFixed(1)}%</small></td></tr>`), 'No tunnel data in this period.')}</div>
      <div class="box full"><h3>Incidents</h3><p class="hint">WAN alerts raised in the period.</p>
        ${table([['When'], ['Firewall'], ['What'], ['Type']], I.slice(0, 15).map(i => `<tr><td>${dtt(i.first)}</td><td>${esc(i.fw)}</td><td>${esc(i.title)}</td><td><span class="pill ${i.severity === 'red' ? 'red' : 'amber'}">${esc(KIND[i.kind] || i.kind)}</span></td></tr>`), 'No WAN incidents in this period.')}</div></div>`);
  });
  if (S.appendix) pages.push(() => page(++no, 'Appendix: details for the IT team', 'Top items behind the charts.', `<div class="g2"><div class="box"><h3>Busiest devices</h3>${tt(T.sources, [['Source IP'], ['Activity', 1], ['Blocked', 1], ['Data', 1]], r => `<tr><td>${esc(r.name)}</td><td class="n">${big(r.count)}</td><td class="n">${big(r.blocked)}</td><td class="n">${bytes(r.bytes)}</td></tr>`)}</div>
    <div class="box"><h3>Most active users</h3>${tt(T.users, [['User'], ['Activity', 1], ['Blocked', 1], ['Data', 1]], r => `<tr><td>${esc(r.name)}</td><td class="n">${big(r.count)}</td><td class="n">${big(r.blocked)}</td><td class="n">${bytes(r.bytes)}</td></tr>`)}</div>
    <div class="box"><h3>Biggest uploaders${T.inetLists ? ' to the internet' : ''}</h3>${tt(T.uploaders, [['Source IP'], ['Uploaded', 1], ['Downloaded', 1]], r => `<tr><td>${esc(r.name)}</td><td class="n">${bytes(r.sent)}</td><td class="n">${bytes(r.bytes - r.sent)}</td></tr>`)}</div>
    <div class="box"><h3>Most blocked destinations</h3>${tt(T.mostBlocked, [['Destination'], ['Blocked', 1]], r => `<tr><td>${esc(r.name)}</td><td class="n">${big(r.count)}</td></tr>`)}</div>
    <div class="box"><h3>Firewall policies used</h3>${tt(T.policies, [['Policy'], ['Activity', 1], ['Blocked', 1]], r => `<tr><td>${esc(r.name)}</td><td class="n">${big(r.count)}</td><td class="n">${big(r.blocked)}</td></tr>`)}</div>
    <div class="box"><h3>Configuration changes by administrator</h3>${tt(si.changes, [['Administrator'], ['Firewall'], ['Changes', 1], ['Last', 1]], r => `<tr><td>${esc(r.user)}</td><td>${esc(r.fw)}</td><td class="n">${num(r.count)}</td><td class="n">${dtt(r.last)}</td></tr>`)}</div>
    <div class="box full notes"><h3 style="color:var(--ink)">About this report</h3><p>Built from the FortiGate logs collected by LogSikka. Most figures come from the 5-minute and hourly summaries; per-hour top lists keep the busiest few thousand values, so the smallest items may be missing from long lists. Counts are log events (connections and security events), not page views or people.
      Usernames come from the firewall, the NPS (wireless) server or manual mappings; activity without a username can only be traced to a device. Status thresholds and exclusions are set in Settings &gt; Executive summary. Built in ${(E.took_ms / 1000).toFixed(1)} s.</p>
      ${X.active ? `<p><b>Exclusions${X.applied ? '' : ' (switched off for this report)'}:</b></p><ul>${(X.rules || []).map(r => `<li>${esc(r)}</li>`).join('')}</ul>${X.applied ? `<p>They removed ${num((X.removed || {}).events)} events and ${bytes((X.removed || {}).bytes)} from the totals, trends, firewall share and the lists of sources, destinations and users${X.coverage < 99.5 ? `, for ${Math.round(X.coverage)}% of the period (the rest is still being calculated)` : ''}. ${esc(X.not_adjusted || '')}</p>` : ''}` : ''}
      ${E.notes.length ? `<p><b>Notes:</b> ${E.notes.map(esc).join(' ')}</p>` : ''}</div></div>`));

  NPG = pages.length;
  if (!NPG) { msg('Choose at least one section under Customise.'); return }
  $('#doc').innerHTML = pages.map(f => f()).join(''); $('#doc').hidden = false; $('#msg').hidden = true;
  if (!S.appendix && E.notes.length) { const last = [...$$('#doc .page')].pop(); last.insertAdjacentHTML('beforeend', `<div class="dnotes"><b>Notes:</b> ${E.notes.map(esc).join(' ')}</div>`) }
  fitPages();
  document.title = `${E.org} · ${OPT.title || 'Network and Security Report'} · ${E.period.label}`;
}

// ------------------------------------------------------------ controls
const q = new URLSearchParams(location.search);
if (q.get('period')) $('#per').value = q.get('period');
if (q.get('from')) $('#cf').value = q.get('from').slice(0, 10);
if (q.get('to')) $('#ct').value = new Date(new Date(q.get('to')) - 864e5).toISOString().slice(0, 10);
if (q.get('excl') === '0') $('#exon').checked = false;
$('#cust').hidden = $('#per').value !== 'custom';
$('#per').onchange = () => { $('#cust').hidden = $('#per').value !== 'custom'; if ($('#per').value !== 'custom') load() };
$('#go').onclick = load;
$('#exon').onchange = load;
$('#pdf').onclick = () => window.print();
fetch('/api/status').then(r => r.ok ? r.json() : null).then(s => { if (s && s.exclusions && s.exclusions.active) $('#exwrap').hidden = false }).catch(() => { });
load();

// v5.21: the Internet circuits page needs WAN links with samples in the period
function wanPageOK() { return !!(E && E.wan_page && (E.wan_page.links || []).some(l => l.samples)) }
