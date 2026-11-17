// Executive summary: management report laid out as A4 pages (prints / saves to PDF from the browser).
// v5.10: cover page, section choice, logo / prepared for / classification, sparklines, exclusions.
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const num = n => Number(n || 0).toLocaleString();
const big = n => { n = +n || 0; return n >= 1e9 ? (n / 1e9).toFixed(1) + ' bn' : n >= 1e6 ? (n / 1e6).toFixed(1) + ' M' : n >= 1e4 ? (n / 1e3).toFixed(0) + ' k' : num(Math.round(n)) };
const bytes = n => { n = +n || 0; if (!n) return '0 B'; const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']; let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++ } return `${n.toFixed(i ? 1 : 0)} ${u[i]}` };
const pc = (a, b) => b ? Math.round(100 * a / b) : 0;
const dt = (s, o) => new Date(s).toLocaleDateString([], o || { day: 'numeric', month: 'short', year: 'numeric' });
const dtt = s => new Date(s).toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
const dur = s => s >= 86400 ? (s / 86400).toFixed(1) + ' days' : s >= 3600 ? (s / 3600).toFixed(1) + ' h' : Math.round(s / 60) + ' min';
const PAL = ['#0e7490', '#6d5bd0', '#c2417a', '#0f9d8a', '#e08a00', '#2f9e6e', '#9aa5b1', '#d9452b', '#3b82c4', '#8a6d3b'];
const SUB = { forward: 'Network traffic', local: 'Traffic to the firewalls', webfilter: 'Web filtering', 'app-ctrl': 'Application control', dns: 'DNS filtering',
  virus: 'Antivirus', ips: 'Intrusion prevention', anomaly: 'DoS / anomaly protection', system: 'Firewall system', vpn: 'VPN', user: 'User authentication',
  sniffer: 'Monitoring', 'ssl': 'Encrypted traffic inspection', waf: 'Web application firewall', emailfilter: 'Email filtering', dlp: 'Data loss prevention', router: 'Routing', ha: 'High availability' };
const subName = s => SUB[s] || s;
const STATUS = { ok: ['Healthy', 'All checks are within their limits'], amber: ['Needs attention', 'Some items should be reviewed'], red: ['Action needed', 'Issues require action'] };

const table = (head, rows, empty = 'Nothing in this period.') => rows.length ? `<table><thead><tr>${head.map(h => `<th${h[1] ? ' class="n"' : ''}>${h[0]}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>` : `<p class="muted">${empty}</p>`;

function trend(cur, prev, goodWhenUp) {
  if (prev == null) return '';
  if (!prev) return '<span class="tr">new this period</span>';
  const x = (cur - prev) / prev * 100;
  if (Math.abs(x) < 3) return '<span class="tr">≈ same as before</span>';
  const cls = goodWhenUp == null ? '' : (x > 0) === goodWhenUp ? (x > 0 ? 'upg' : 'down') : (x > 0 ? 'up' : 'downb');
  return `<span class="tr ${cls}">${x > 0 ? '▲' : '▼'} ${Math.abs(x) > 999 ? '>999' : Math.abs(x).toFixed(0)}% vs previous</span>`;
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

// ------------------------------------------------------------ v5.16: AI usage report
const OPT = (() => { try { return JSON.parse(localStorage.getItem('fortilog.exec') || '{}') } catch { return {} } })();
const RISKL = { 5: 'Critical', 4: 'High', 3: 'Elevated', 2: 'Medium', 1: 'Low' };
let R = null, PG = 0, NPG = 0;
const initials = s => (s || 'N').split(/\s+/).filter(Boolean).slice(0, 2).map(w => w[0].toUpperCase()).join('');
const mark = () => `<div class="mark">${OPT.logo ? `<img src="${esc(OPT.logo)}" alt="">` : esc(initials(R.org))}</div>`;
function header(no, title, sub) {
  const P = R.period;
  return `<div class="ph"><div><div class="sec">${String(no).padStart(2, '0')} · ${esc(R.org)}</div><h1>${esc(title)}</h1>${sub ? `<div class="sub">${esc(sub)}</div>` : ''}</div>
    <div class="per"><div><b>${esc(P.label)}</b>${dt(P.from)} – ${dt(new Date(new Date(P.to) - 1))}</div>${mark()}</div></div>`;
}
const footer = () => `<div class="pf"><span>${OPT.cls ? `<span class="cls">${esc(OPT.cls)}</span> · ` : ''}${esc(R.org)} · AI usage report</span><span>Generated ${dtt(R.generated)} · Page <i class="pn"></i> of <i class="pt"></i></span></div>`;
const page = (no, title, sub, body) => `<section class="page">${header(no, title, sub)}<div class="pb">${body}</div>${footer()}</section>`;
const who = u => esc(u.display || u.user) + (u.display ? ` <small class="muted">${esc(u.user)}</small>` : '');

async function load() {
  const per = $('#per').value, p = new URLSearchParams({ period: per });
  if (per === 'custom') {
    if (!$('#cf').value || !$('#ct').value) { msg('Choose From and To dates.'); return }
    p.set('from', new Date($('#cf').value + 'T00:00').toISOString()); p.set('to', new Date(new Date($('#ct').value + 'T00:00').getTime() + 864e5).toISOString());
  }
  if (!$('#exon').checked) p.set('excl', '0');
  history.replaceState(null, '', '?' + p);
  msg('Building the report…');
  const r = await fetch('/api/aireport?' + p);
  if (r.status === 401) { location.href = '/login.html?next=' + encodeURIComponent(location.pathname + location.search); return }
  const t = await r.text();
  if (!r.ok) { let m = t; try { m = JSON.parse(t).error || t } catch { } msg(m); return }
  R = JSON.parse(t); render();
  $('#exwrap').hidden = !(R.exclusions && R.exclusions.active);
}
function msg(t) { $('#msg').hidden = false; $('#msg').textContent = t; $('#doc').hidden = true }

function render() {
  PG = 0;
  const C = R.cur || {}, P = R.prev, T = R.tools || [], nw = T.filter(t => t.new);
  const kpi = (l, v, sub, tr) => `<div class="kpi"><small>${l}</small><b>${v}</b><div class="s">${sub}</div>${tr || ''}</div>`;
  // activity per day: top 6 tools stacked
  const top = T.slice(0, 6).map(t => t.name), keys = top.map((_, i) => 'k' + i), byT = new Map();
  (R.series || []).forEach(s => { const k = new Date(s.t).getTime(); if (!byT.has(k)) byT.set(k, { t: s.t, other: 0 }); const i = top.indexOf(s.tool), row = byT.get(k); if (i >= 0) row['k' + i] = (row['k' + i] || 0) + s.events; else row.other += s.events });
  const ser = [...byT.values()].sort((a, b) => new Date(a.t) - new Date(b.t));
  const rk = r => r ? `<span class="rk rk${r}">${RISKL[r]}</span>` : '';
  const pages = [];
  let no = 0;
  pages.push(() => page(++no, 'AI usage report', 'Who uses which generative AI tools, how much data goes to them, and what the policy stops.', `
    <div class="kpis">${kpi('AI activity', big(C.events), 'web filter, application control and traffic events', trend(C.events, P && P.events, null))}
      ${kpi('People', num(C.users), `${num(R.people_total)} with a username${R.staff_list ? ' (staff list loaded)' : ''}`, trend(C.users, P && P.users, null))}
      ${kpi('Devices', num(C.devices), 'internal addresses using AI', trend(C.devices, P && P.devices, null))}
      ${kpi('AI tools', num(C.tools), nw.length ? `${nw.length} new this period` : 'none new this period', '')}
      ${kpi('Uploaded to AI tools', bytes(C.sent), 'from traffic logs: text, files, images', trend(C.sent, P && P.sent, false))}
      ${kpi('Blocked by policy', pc(C.blocked, C.events) + '%', big(C.blocked) + ' attempts', trend(C.blocked, P && P.blocked, null))}</div>
    <div class="cols"><div><h2 class="s">AI activity per ${R.series_unit || 'day'}</h2>${stacked(ser, [...keys, 'other'], [...PAL.slice(0, 6), '#cbd5df'], [...top, 'Other tools'], big, R.series_unit, 210)}</div>
      <div><h2 class="s">Share by tool</h2>${T.length ? donut(T.slice(0, 8).map(t => ({ n: t.name, v: t.events })), big(C.events), 'events') : '<p class="muted">No AI use in this period.</p>'}</div></div>
    ${R.exclusions && R.exclusions.applied ? `<div class="exn2"><b>Left out of this report:</b> ${esc((R.exclusions.rules || []).join(' · '))}</div>` : ''}
    <h2 class="s" style="margin-top:22px">Recommendations</h2><div class="att">${(R.recommendations || []).length ? R.recommendations.map(f => `<div class="it ${f.status}"><b><span class="tag ${f.status}">${f.status === 'red' ? 'Act' : 'Review'}</span>${esc(f.title)}</b><p>${esc(f.detail)}</p><p class="act"><b style="display:inline">Recommended:</b> ${esc(f.action)}</p></div>`).join('')
      : '<div class="it none"><b>Nothing needs attention</b><p>No new, high-risk or heavily blocked AI tools, and no large uploads.</p></div>'}</div>`));
  // v5.17: the picture before the detail
  const tl = T.slice(0, 12), riskEv = {};
  T.forEach(t => { const k = RISKL[t.risk] || 'Not rated'; riskEv[k] = (riskEv[k] || 0) + t.events });
  const RC = { Critical: '#b42318', High: '#e4572e', Elevated: '#f08a3c', Medium: '#e0b400', Low: '#2f9e6e', 'Not rated': '#9aa5b1' };
  const stackRows = (rows, parts, fmt) => { const mx = Math.max(1, ...rows.map(r => parts.reduce((a, p) => a + (+r[p[0]] || 0), 0)));
    return rows.length ? `<div class="hbx">${rows.map(r => { const tot = parts.reduce((a, p) => a + (+r[p[0]] || 0), 0); return `<div><span title="${esc(r.name)}">${esc(r.name)}</span><span class="st" style="width:${Math.max(2, 100 * tot / mx)}%">${parts.map(p => `<i style="width:${pc(+r[p[0]] || 0, tot || 1)}%;background:${p[1]}" title="${esc(p[2])}: ${fmt(+r[p[0]] || 0)}"></i>`).join('')}</span><b>${fmt(tot)}</b></div>` }).join('')}</div>
      <div class="legend">${parts.map(p => `<span><i style="background:${p[1]}"></i>${esc(p[2])}</span>`).join('')}</div>` : '<p class="muted">Nothing in this period.</p>' };
  pages.push(() => page(++no, 'At a glance', 'The main patterns before the detail.', `<div class="g2">
    <div class="box"><h3>Allowed and blocked, by tool</h3><p class="hint">Activity per tool; the red part was stopped by policy.</p>${stackRows(tl.map(t => ({ name: t.name, a: t.events - t.blocked, b: t.blocked })), [['a', '#0e7490', 'Allowed'], ['b', '#d9452b', 'Blocked']], big)}</div>
    <div class="box"><h3>Data uploaded, by tool</h3><p class="hint">What was sent to each tool (text, files, images).</p>${hbars(tl.filter(t => t.sent > 0).sort((a, b) => b.sent - a.sent), 'sent', bytes, '#6d5bd0')}</div>
    <div class="box"><h3>People using each tool</h3><p class="hint">Distinct people with a username.</p>${hbars(tl.filter(t => t.users > 0).sort((a, b) => b.users - a.users), 'users', num, '#0f9d8a')}</div>
    <div class="box"><h3>Activity by risk rating</h3><p class="hint">FortiGuard risk of the tools in use.</p>${donut(Object.entries(riskEv).map(([n, v]) => ({ n, v })), big(C.events), 'events')}</div>
    <div class="box"><h3>Departments</h3><p class="hint">${R.staff_list ? 'AI activity per department.' : 'Load the staff list (Settings > Staff directory) to see departments.'}</p>${hbars((R.departments || []).slice(0, 10).map(d => ({ ...d, name: d.name })), 'events', big, '#3b82c4')}</div>
    <div class="box"><h3>Tools seen for the first time</h3><p class="hint">Not seen before this period.</p>${nw.length ? `<div class="newl">${nw.map(t => `<span>${esc(t.name)}</span>`).join('')}</div>` : '<p class="muted">No new tools.</p>'}
      <h3 style="margin-top:18px">Biggest uploaders</h3>${hbars((R.uploaders || []).slice(0, 6).map(u => ({ ...u, name: u.display || u.user })), 'sent', bytes, '#c2417a')}</div></div>`));
  pages.push(() => page(++no, 'Every AI tool', `All ${T.length} tools seen in the period, busiest first.`, `<div class="box full">${table([['Tool'], ['Risk'], ['People', 1], ['Devices', 1], ['Depts', 1], ['Activity', 1], ['Uploaded', 1], ['Blocked', 1], ['Busiest users']],
    T.map(t => `<tr class="tt"><td><b>${esc(t.name)}</b>${t.new ? ' <span class="pill new">New</span>' : ''}${t.first_ever ? `<br><small>since ${dt(t.first_ever, { day: 'numeric', month: 'short' })}</small>` : ''}</td><td>${rk(t.risk)}</td><td class="n">${num(t.users)}</td><td class="n">${num(t.devices)}</td><td class="n">${t.depts || '–'}</td>
      <td class="n">${big(t.events)}<br>${trend(t.events, t.prev_events, null)}</td><td class="n">${bytes(t.sent)}</td><td class="n">${pc(t.blocked, t.events)}%</td>
      <td><div class="chips3">${(t.top_users || []).slice(0, 3).map(u => `<span>${esc(u.display || u.user)} · ${big(u.events)}</span>`).join('') || '<small>no usernames</small>'}</div></td></tr>`), 'No AI tools seen in this period.')}</div>`));
  const D = R.departments || [];
  pages.push(() => page(++no, 'People and departments', 'Who uses AI, where the data goes and who keeps trying blocked tools.', `<div class="g2">
    <div class="box full"><h3>Departments</h3><p class="hint">${R.staff_list ? 'From the staff list.' : 'Load the staff list (Settings > Staff directory) to see departments.'}</p>${table([['Department'], ['People', 1], ['Activity', 1], ['Uploaded', 1], ['Blocked', 1], ['Tools']],
      D.map(d => `<tr class="tt"><td><b>${esc(d.name)}</b></td><td class="n">${num(d.users)}</td><td class="n">${big(d.events)}</td><td class="n">${bytes(d.sent)}</td><td class="n">${pc(d.blocked, d.events)}%</td><td><div class="chips3">${d.tools.map(x => `<span>${esc(x)}</span>`).join('')}</div></td></tr>`), 'No AI use with a username.')}</div>
    <div class="box"><h3>Biggest uploaders to AI</h3><p class="hint">Data sent to AI tools, from traffic logs.</p>${hbars((R.uploaders || []).map(u => ({ ...u, name: (u.display || u.user) + (u.dept ? ' · ' + u.dept : '') })), 'sent', bytes, '#6d5bd0')}</div>
    <div class="box"><h3>Blocked attempts by person</h3><p class="hint">People who most often tried an AI tool the policy blocks.</p>${hbars((R.blocked_people || []).map(u => ({ ...u, name: (u.display || u.user) + (u.dept ? ' · ' + u.dept : '') })), 'blocked', big, '#d9452b')}</div>
    <div class="box full"><h3>Most active people</h3>${table([['Person'], ['Department'], ['Activity', 1], ['Uploaded', 1], ['Blocked', 1], ['Tools']],
      (R.people || []).slice(0, 40).map(u => `<tr class="tt"><td>${who(u)}</td><td>${esc(u.dept || '')}</td><td class="n">${big(u.events)}</td><td class="n">${bytes(u.sent)}</td><td class="n">${big(u.blocked)}</td><td><div class="chips3">${(u.tools || []).map(x => `<span>${esc(x)}</span>`).join('')}</div></td></tr>`), 'No AI use with a username.')}</div></div>`));
  NPG = pages.length;
  $('#doc').innerHTML = pages.map(f => f()).join(''); $('#doc').hidden = false; $('#msg').hidden = true;
  paginate();
  document.title = `${R.org} · AI usage report · ${R.period.label}`;
}
const q = new URLSearchParams(location.search);
if (q.get('period')) $('#per').value = q.get('period');
if (q.get('from')) $('#cf').value = q.get('from').slice(0, 10);
if (q.get('to')) $('#ct').value = new Date(new Date(q.get('to')) - 864e5).toISOString().slice(0, 10);
$('#cust').hidden = $('#per').value !== 'custom';
$('#per').onchange = () => { $('#cust').hidden = $('#per').value !== 'custom'; if ($('#per').value !== 'custom') load() };
$('#go').onclick = load;
$('#exon').onchange = load;
if (q.get('excl') === '0') $('#exon').checked = false;
fetch('/api/status').then(r => r.ok ? r.json() : null).then(s => { if (s && s.exclusions && s.exclusions.active) $('#exwrap').hidden = false }).catch(() => { });
$('#pdf').onclick = () => window.print();
load();

// v5.17: every page ends above its footer. A table that does not fit continues on a new page (same title, header row
// repeated); anything else that still overflows is scaled down a little. Page numbers are filled in afterwards.
function paginate() {
  const limitOf = pg => pg.querySelector('.pf').getBoundingClientRect().top - 16;
  const over = pg => { const pb = pg.querySelector('.pb'); return pb.getBoundingClientRect().top + pb.scrollHeight > limitOf(pg) };
  for (let guard = 0; guard < 60; guard++) {
    const pg = $$('#doc .page').find(over); if (!pg) break;
    const tables = [...pg.querySelectorAll('.pb table')].filter(t => t.tBodies[0] && t.tBodies[0].rows.length > 1);
    const tb = tables[tables.length - 1];
    if (!tb) { break }
    const box = tb.closest('.box') || tb.parentElement, title = (box.querySelector('h3') || {}).textContent || '';
    const np = pg.cloneNode(true), pb = np.querySelector('.pb');
    pb.innerHTML = `<div class="g2"><div class="box full">${title ? `<h3>${esc(title)}</h3>` : ''}<p class="cont">continued</p><table>${tb.tHead ? tb.tHead.outerHTML : ''}<tbody></tbody></table></div></div>`;
    pg.after(np);
    const dst = pb.querySelector('tbody'), src = tb.tBodies[0];
    while (over(pg) && src.rows.length > 1) dst.prepend(src.rows[src.rows.length - 1]);
  }
  fitPages(); // whatever is left (charts) is scaled slightly
  const all = $$('#doc .page');
  all.forEach((p, i) => { p.querySelectorAll('.pn').forEach(x => x.textContent = i + 1); p.querySelectorAll('.pt').forEach(x => x.textContent = all.length) });
}
