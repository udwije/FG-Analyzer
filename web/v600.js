// v6.0 (LogSikka, phase A): sites and tags, settings saved one section at a time with their change history,
// server health over 24 hours, loading feedback, breadcrumb and the LogSikka header.

// ------------------------------------------------------------ loading feedback: a thin bar while anything loads
(() => {
  const bar = document.createElement('div'); bar.id = 'topbar'; bar.innerHTML = '<i></i>'; document.body.prepend(bar);
  let busy = 0, timer = null;
  const set = () => { clearTimeout(timer); if (busy > 0) timer = setTimeout(() => bar.classList.add('on'), 150); else { bar.classList.remove('on') } };
  const f0 = window.fetch;
  window.fetch = async (...a) => { busy++; set(); try { return await f0(...a) } finally { busy--; set() } };
})();

// ------------------------------------------------------------ header: version, breadcrumb
(async () => { try { const me = await (await fetch('/api/me')).json(); const v = $('#bver'); if (v && me.version) v.textContent = me.version } catch { } })();
{
  const _sv = setView;
  setView = function (v) {
    _sv(v);
    const b = $(`#tabs button[data-view="${v}"]`);
    let g = b && b.previousElementSibling;
    while (g && !g.classList.contains('tabgrp')) g = g.previousElementSibling;
    const grp = v === 'settings' ? 'System' : g ? g.textContent.trim() : '';
    let c = $('#crumb'); if (!c) { c = document.createElement('span'); c.id = 'crumb'; c.className = 'crumb'; $('#title').before(c) }
    c.textContent = grp ? grp + ' ›' : '';
  };
}

// ------------------------------------------------------------ settings: save one section, and its change history
const CARDKEYS = {
  'set-syslog-listener': ['listen_address', 'web_listen_address', 'tcp_enabled', 'udp_enabled', 'allowed_sources', 'keep_subtypes'],
  'set-firewalls': ['firewalls'],
  'set-internal-networks': ['internal_networks', 'infra_networks', 'tunnel_interfaces'],
  'set-ai-detection': ['ai_categories', 'ai_rules'],
  'set-nps-user-mapping-wireless': ['nps'],
  'set-postgresql': ['database'],
  'set-storage': ['retention_days', 'batch_size', 'spool_directory', 'spool_max_mb', 'compress_after_days', 'query_concurrency'],
  'set-staff-directory': ['directory'],
  'set-alerts': ['alerts'],
  'set-executive-summary': ['exec'],
  'set-wan-links-snmpv3': ['wan'],
  'set-dashboard-access': ['web_tls', 'session_hours', 'tls_cert_file', 'tls_key_file'],
};
const activeCard = () => [...document.querySelectorAll('#config .scard')].find(c => !c.hidden);
$('#config').onsubmit = async e => {
  e.preventDefault();
  const card = activeCard(), keys = card && CARDKEYS[card.id], title = card ? card.querySelector('h2').textContent.trim() : '';
  try {
    const all = formConfig();
    let r;
    if (keys) {
      const values = {}; keys.forEach(k => { if (all[k] !== undefined) values[k] = all[k] });
      r = await fetch('/api/config/section', { method: 'PUT', headers: cfgHeaders(), body: JSON.stringify({ section: title, values }) });
    } else r = await fetch('/api/config', { method: 'PUT', headers: cfgHeaders(), body: JSON.stringify(all) });
    if (!r.ok) throw new Error(cfgSaveError(r, await errText(r)));
    const j = await r.json(); D = G = null;
    const ch = j.changes ? (j.changes.length ? ` Changed: ${j.changes.slice(0, 4).join('; ')}${j.changes.length > 4 ? ` and ${j.changes.length - 4} more` : ''}.` : ' Nothing changed.') : '';
    $('#message').textContent = (j.restart_required ? 'Saved. Restart the service to apply the listener, HTTPS, firewall list or database changes.' : 'Saved. The changes are already in use.') + ch;
    loadConfig();
  } catch (x) { $('#message').textContent = x.message }
};
// "Changes" button on every section: who changed what, and when
function historyButtons() {
  document.querySelectorAll('#config .scard').forEach(c => {
    const row = c.querySelector('.cardsave'); if (!row || row.querySelector('.hist')) return;
    const b = document.createElement('button'); b.type = 'button'; b.className = 'hist'; b.textContent = 'Changes';
    b.title = 'Who changed this section, and what'; row.insertBefore(b, row.querySelector('.sep'));
    b.onclick = () => showHistory(c.querySelector('h2').textContent.trim());
  });
}
async function showHistory(section) {
  const d = document.createElement('div'); d.className = 'modal';
  d.innerHTML = `<div class="card mbox wide2"><h2>Changes: ${esc(section)}</h2><div id="histbody"><p class="muted">Loading…</p></div><div class="actions"><button type="button" id="histclose">Close</button></div></div>`;
  document.body.append(d); d.querySelector('#histclose').onclick = () => d.remove(); d.addEventListener('keydown', e => { if (e.key === 'Escape') d.remove() });
  d.onclick = e => { if (e.target === d) d.remove() };
  try {
    const l = await api('/api/config/history?section=' + encodeURIComponent(section));
    d.querySelector('#histbody').innerHTML = l.length ? `<div class="histl">${l.map(h => {
      const det = h.detail.replace(/^[^:]*: /, '');
      return `<div><b>${ldt(h.at)}</b> <span class="muted">${esc(h.user || '?')}</span><ul>${det.split('; ').map(x => `<li>${esc(x)}</li>`).join('')}</ul></div>`;
    }).join('')}</div>` : '<p class="muted">No changes recorded for this section yet (recorded from v6.0 on).</p>';
  } catch (x) { d.querySelector('#histbody').innerHTML = `<p class="err">${esc(x.message)}</p>` }
}
{ const _lc = loadConfig; loadConfig = async function () { await _lc(); historyButtons() } }

// ------------------------------------------------------------ tags
const KINDS = { staff: ['Staff LAN', '#0e7490'], servers: ['Servers', '#6d5bd0'], wifi: ['Staff Wi-Fi', '#3b82c4'], guest: ['Guest', '#e08a00'],
  voice: ['Voice', '#0f9d8a'], cctv: ['CCTV', '#c2417a'], iot: ['IoT', '#b45309'], printers: ['Printers', '#8a6d3b'],
  management: ['Management', '#475569'], dmz: ['DMZ', '#d9452b'], other: ['Other', '#9aa5b1'] };
const kindPill = k => k ? `<span class="tpill" style="--c:${(KINDS[k] || KINDS.other)[1]}">${esc((KINDS[k] || [k])[0])}</span>` : '';
function tagChip(t) {
  const [k, ...rest] = t.split(':'), v = rest.join(':'), link = k === 'site' || k === 'zone';
  const lab = { site: 'Site', zone: 'Zone', kind: 'Type', dept: 'Dept', role: 'Role', staff: 'Staff' }[k] || k;
  const val = k === 'kind' ? (KINDS[v] || [v])[0] : v === 'former' ? 'left' : v;
  return `<span class="tagc t-${esc(k)}${link ? ' link' : ''}" ${link ? `data-tag="${esc(t)}" title="Show the dashboards for this ${lab.toLowerCase()}"` : ''}><small>${esc(lab)}</small>${esc(val)}</span>`;
}
// a site or zone tag filters the dashboards by its subnets
async function filterByTag(tag) {
  try {
    const r = await api('/api/tags?tag=' + encodeURIComponent(tag));
    F.src = r.subnets.join(', '); toInputs(); renderChips(); $('#drawer').hidden = true;
    if (['settings', 'sites', 'alerts', 'wan', 'devices', 'mapping'].includes(view)) setView('global'); else apply();
  } catch (x) { toast(x.message) }
}
document.addEventListener('click', e => { const t = e.target.closest('[data-tag]'); if (t) { e.preventDefault(); e.stopPropagation(); filterByTag(t.dataset.tag) } }, true);
{
  const _od = openDrawer;
  openDrawer = function (row) {
    _od(row);
    if (row.tags && row.tags.length) { const h = $('#dbody .dhead'); if (h) h.insertAdjacentHTML('beforeend', `<div class="tagrow">${row.tags.map(tagChip).join('')}</div>`) }
  };
}

// ------------------------------------------------------------ Sites
let ST = null, STEDIT = null;
async function loadSites(signal) { ST = await api('/api/sites?' + qs(), { signal }); renderSites() }
function siteZoneSubnets(site, zone) {
  const s = (ST.sites || []).find(x => x.name === site); if (!s) return [];
  return zone ? ((s.zones || []).find(z => z.name === zone) || {}).subnets || [] : (s.zones || []).flatMap(z => z.subnets || []);
}
function renderSites() {
  const Z = ST.zones || [], sites = [...new Set(Z.map(z => z.site))], conf = ST.sites || [];
  const sum = k => Z.reduce((a, z) => a + (+z[k] || 0), 0);
  renderPeriod({ from: ST.from, to: ST.to }, [[num(conf.length), 'Sites'], [num(conf.reduce((a, s) => a + (s.zones || []).length, 0)), 'Zones'],
    [num(sum('devices')), 'Internal devices'], [bytes(sum('inet_down')), 'Internet ↓']]);
  const el = $('#sitesbody');
  if (STEDIT) { el.innerHTML = siteEditor(); bindEditor(); return }
  const covered = sum('devices') - Z.filter(z => !z.zone).reduce((a, z) => a + z.devices, 0);
  let h = '';
  if (!conf.length) h += `<div class="card intro"><h3>Describe your network once</h3><p>Add your sites (head office, branches), the firewall at each site, and the zones of each site with their subnets: staff LAN, servers, guest Wi-Fi, CCTV… Every address then carries a <b>site</b> and <b>zone</b> tag: the dashboards can be filtered by a click instead of typing subnets, and the log detail shows where a device is.</p>
    ${ST.can_edit ? '<button class="primary" id="siteedit">Add your sites</button> <span class="muted">The busiest internal networks seen in the logs are listed below to start from.</span>' : '<p class="muted">An admin can add the sites.</p>'}</div>`;
  else h += `<div class="card sitebar"><span><b>${pc(covered, sum('devices'))}%</b> of the internal devices seen in this period are in a zone.</span><span class="sep"></span>${ST.complete ? '' : '<span class="muted">Summaries for the start of this period are still being built.</span>'}${ST.can_edit ? '<button id="siteedit">Edit sites and zones</button>' : ''}</div>`;
  sites.forEach(sn => {
    const zs = Z.filter(z => z.site === sn), s = conf.find(x => x.name === sn) || { firewalls: [] }, ev = zs.reduce((a, z) => a + z.events, 0) || 1;
    h += `<div class="card site"><div class="siteh"><h3>${sn === '(no site)' ? 'Not in a site' : esc(sn)}</h3>${(s.firewalls || []).map(f => `<span class="fwtag">${esc(f)}</span>`).join('')}
      ${sn !== '(no site)' && siteZoneSubnets(sn).length ? `<a href="#" data-tag="site:${esc(sn)}" class="siteall">Show this site on the dashboards →</a>` : ''}</div>
      ${table([['Zone'], ['Devices', 1], ['Activity', 1], ['Share', 1], ['Blocked', 1], ['Internet ↓ / ↑', 1], ['All data', 1], ['Busiest devices']], zs.map(z => `<tr${z.zone ? ` data-tag="zone:${esc(z.zone)}" class="zrow" title="Show this zone on the dashboards"` : ''}>
        <td>${z.zone ? `<b>${esc(z.zone)}</b> ${kindPill(z.kind)}${z.vlan ? ` <small class="muted">VLAN ${z.vlan}</small>` : ''}<br><small class="muted mono">${esc((z.subnets || []).join(', '))}</small>`
          : `<i class="muted">Not in a zone</i><br><small class="muted">internal addresses logged by this site's firewall</small>`}</td>
        <td class="r">${num(z.devices)}</td><td class="r">${short(z.events)}</td><td class="r"><span class="share" style="width:${Math.max(2, pc(z.events, ev) * .6)}px"></span>${pc(z.events, ev)}%</td>
        <td class="r">${pc(z.blocked, z.events)}%</td><td class="r">${bytes(z.inet_down)} / ${bytes(z.inet_up)}</td><td class="r">${bytes(z.bytes)}</td>
        <td>${(z.top || []).slice(0, 3).map(t => `<span class="mono">${esc(t.ip)}</span> <small class="muted">${short(t.events)}</small>`).join('<br>')}</td></tr>`), 'Nothing in this period.')}</div>`;
  });
  const sg = ST.suggestions || [];
  if (sg.length) h += `<div class="card"><h3>Networks not in a zone yet</h3><p class="hint">Internal /24 networks seen in this period that no zone covers, busiest first.${ST.can_edit ? ' Add them to a zone so their traffic gets a site and zone.' : ''}</p>
    ${table([['Network'], ['Devices', 1], ['Activity', 1], ['Data', 1], ['Logged by'], ['']], sg.map(s => `<tr><td class="mono"><b>${esc(s.subnet)}</b></td><td class="r">${num(s.devices)}</td><td class="r">${short(s.events)}</td>
      <td class="r">${bytes(s.bytes)}</td><td>${(s.firewalls || []).map(f => `<span class="fwtag">${esc(f)}</span>`).join(' ')}</td>
      <td>${ST.can_edit ? `<button data-addnet="${esc(s.subnet)}" data-fw="${esc((s.firewalls || [])[0] || '')}">Add to a zone…</button>` : ''}</td></tr>`))}</div>`;
  el.innerHTML = h;
  if ($('#siteedit')) $('#siteedit').onclick = () => { STEDIT = JSON.parse(JSON.stringify(conf)); renderSites() };
  el.querySelectorAll('[data-addnet]').forEach(b => b.onclick = () => {
    STEDIT = JSON.parse(JSON.stringify(conf));
    const fw = b.dataset.fw, site = STEDIT.find(s => (s.firewalls || []).includes(fw));
    const target = site || (STEDIT.push({ name: fw ? fw.replace(/[-_ ]?FW$/i, '') || fw : 'New site', firewalls: fw ? [fw] : [], zones: [] }), STEDIT[STEDIT.length - 1]);
    target.zones = target.zones || [];
    target.zones.push({ name: 'Network ' + b.dataset.addnet.replace(/\.0\/24$/, '.x'), kind: 'staff', subnets: [b.dataset.addnet], _new: true });
    renderSites();
  });
}
function siteEditor() {
  const fwl = ST.known_firewalls || [], kinds = ST.kinds || Object.keys(KINDS);
  return `<div class="card siteed"><div class="siteh"><h3>Sites and zones</h3><span class="sep"></span><button id="se-addsite">+ Site</button></div>
    <p class="hint">A zone holds one or more subnets (one per line or comma separated). When zones overlap, the most specific subnet wins. Addresses outside every zone get the site of the firewall that logged them.</p>
    ${STEDIT.map((s, i) => `<fieldset class="sitefs" data-si="${i}"><legend><input data-f="name" value="${esc(s.name)}" placeholder="Site name (e.g. Head office)" class="sname"></legend>
      <div class="fwpick"><small class="muted">Firewalls at this site</small>${[...new Set([...fwl, ...(s.firewalls || [])])].map(f => `<label class="chk"><input type="checkbox" data-fw="${esc(f)}"${(s.firewalls || []).includes(f) ? ' checked' : ''}>${esc(f)}</label>`).join('') || '<span class="muted">List your firewalls in Settings &gt; Firewalls first.</span>'}</div>
      <table class="zed"><thead><tr><th>Zone</th><th>Type</th><th>VLAN</th><th>Subnets</th><th></th></tr></thead><tbody>${(s.zones || []).map((z, j) => `<tr data-zi="${j}"${z._new ? ' class="znew"' : ''}>
        <td><input data-z="name" value="${esc(z.name)}" placeholder="e.g. HO staff"></td>
        <td><select data-z="kind">${kinds.map(k => `<option value="${k}"${(z.kind || 'other') === k ? ' selected' : ''}>${esc((KINDS[k] || [k])[0])}</option>`).join('')}</select></td>
        <td><input data-z="vlan" type="number" min="0" max="4094" value="${z.vlan || ''}" class="vlan"></td>
        <td><textarea data-z="subnets" rows="${Math.max(1, (z.subnets || []).length)}" placeholder="10.10.0.0/16">${esc((z.subnets || []).join('\n'))}</textarea></td>
        <td><button type="button" data-rmzone="${j}">Remove</button></td></tr>`).join('')}</tbody></table>
      <div class="actions left"><button type="button" data-addzone="${i}">+ Zone</button><span class="sep"></span><button type="button" data-rmsite="${i}">Remove this site</button></div></fieldset>`).join('') || '<p class="muted">No sites yet: press + Site.</p>'}
    <div class="cardsave"><span class="cmsg" id="se-msg"></span><span class="sep"></span><button type="button" id="se-cancel">Cancel</button><button type="button" class="primary" id="se-save">Save sites</button></div></div>`;
}
function readEditor() {
  return [...document.querySelectorAll('.sitefs')].map(fs => ({
    name: fs.querySelector('[data-f=name]').value.trim(),
    firewalls: [...fs.querySelectorAll('[data-fw]')].filter(c => c.checked).map(c => c.dataset.fw),
    zones: [...fs.querySelectorAll('tbody tr')].map(tr => ({ name: tr.querySelector('[data-z=name]').value.trim(), kind: tr.querySelector('[data-z=kind]').value,
      vlan: +tr.querySelector('[data-z=vlan]').value || 0, subnets: tr.querySelector('[data-z=subnets]').value.split(/[\s,;]+/).map(x => x.trim()).filter(Boolean) })),
  }));
}
function bindEditor() {
  $('#se-addsite').onclick = () => { STEDIT = readEditor(); STEDIT.push({ name: '', firewalls: [], zones: [{ name: '', kind: 'staff', subnets: [] }] }); renderSites() };
  document.querySelectorAll('[data-addzone]').forEach(b => b.onclick = () => { STEDIT = readEditor(); STEDIT[+b.dataset.addzone].zones.push({ name: '', kind: 'staff', subnets: [] }); renderSites() });
  document.querySelectorAll('[data-rmzone]').forEach(b => b.onclick = () => { STEDIT = readEditor(); STEDIT[+b.closest('.sitefs').dataset.si].zones.splice(+b.dataset.rmzone, 1); renderSites() });
  document.querySelectorAll('[data-rmsite]').forEach(b => b.onclick = () => { STEDIT = readEditor(); const s = STEDIT[+b.dataset.rmsite]; if (!s.name || confirm(`Remove the site ${s.name} and its zones?`)) { STEDIT.splice(+b.dataset.rmsite, 1); renderSites() } });
  $('#se-cancel').onclick = () => { STEDIT = null; renderSites() };
  $('#se-save').onclick = async () => {
    const sites = readEditor();
    try {
      const r = await jsend('/api/config/section', 'PUT', { section: 'Sites', values: { sites } });
      STEDIT = null; toast('Sites saved.' + (r.changes && r.changes.length ? ' ' + r.changes.length + ' change(s).' : '')); D = G = null; refresh();
    } catch (x) { $('#se-msg').textContent = x.message; $('#se-msg').className = 'cmsg err' }
  };
  const first = document.querySelector('.znew [data-z=name]'); if (first) { first.focus(); first.select() }
}

// ------------------------------------------------------------ System health: server performance over 24 hours
{
  const _lh = loadHealth;
  loadHealth = async function () {
    await _lh();
    const el = $('#syshealth'); if (!el) return;
    let S; try { S = await api('/api/health/series') } catch { return }
    const P = S.points || [], last = P[P.length - 1];
    const box = document.createElement('div'); box.className = 'perf';
    if (!last) { box.innerHTML = `<h3>Server performance</h3><p class="muted">Collecting: the first point appears two minutes after the service starts (one per minute, last 24 hours, kept in memory).</p>`; el.prepend(box); return }
    const tile = (l, v, s, cls) => `<div class="${cls || ''}"><small>${l}</small><b>${v}</b><span>${s}</span></div>`;
    const st = (v, a, r) => v >= r ? 'r' : v >= a ? 'a' : '';
    box.innerHTML = `<h3>Server performance <small class="muted">${esc(S.host)} · ${S.cores} cores · LogSikka ${esc(S.version)} · running since ${ldt(S.started)}</small></h3>
      <div class="hkpis">${tile('CPU', last.cpu.toFixed(0) + '%', `I/O wait ${last.iowait.toFixed(1)}% · load ${last.load1 >= 0 ? last.load1.toFixed(2) : '–'}`, st(last.cpu, 70, 90))}
      ${tile('Memory', last.mem_pct.toFixed(0) + '%', `swap ${last.swap_pct.toFixed(0)}% · LogSikka ${last.go_mem_mb.toFixed(0)} MB`, st(last.mem_pct, 85, 95))}
      ${tile('Logs in', num(Math.round(last.in_rate)) + '/s', `written ${num(Math.round(last.out_rate))}/s · queue ${num(last.queue)}`, last.queue > 50000 ? 'r' : '')}
      ${tile('Write time', last.write_ms.toFixed(0) + ' ms', 'per batch (average)', st(last.write_ms, 500, 2000))}
      ${tile('Newest log', last.lag_s >= 0 ? (last.lag_s < 120 ? Math.round(last.lag_s) + ' s ago' : Math.round(last.lag_s / 60) + ' min ago') : '–', `spool ${num(last.spool)} files`, last.lag_s > 600 ? 'r' : last.lag_s > 120 ? 'a' : '')}
      ${tile('Database', last.cache_hit >= 0 ? last.cache_hit.toFixed(1) + '%' : '–', `cache hits · ${num(last.db_conns)} connections`, last.cache_hit >= 0 && last.cache_hit < 95 ? 'a' : '')}</div>
      <div class="perfg"><div><h5>CPU and I/O wait</h5><div id="pf1"></div></div><div><h5>Memory and swap</h5><div id="pf2"></div></div>
      <div><h5>Logs per second</h5><div id="pf3"></div></div><div><h5>Write time per batch (ms)</h5><div id="pf4"></div></div></div>
      <p class="hint">One point per minute, last 24 hours, kept in memory (a restart starts again). High I/O wait with a slow write time usually means the disk is the limit.</p>
      <p class="hint">${S.bg_paused && Date.now() / 1000 - S.bg_paused < 120 ? 'History work (summaries of older hours, exclusions) is <b>waiting while the dashboards are in use</b>; it continues when they are idle.' : 'History work runs when no dashboard is loading.'}${S.exclusions && (S.exclusions.skipped_hours || []).length ? ` <span class="err">Exclusions skipped for ${S.exclusions.skipped_hours.map(esc).join(', ')} after repeated time-outs.</span>` : ''}</p>`;
    el.prepend(box);
    const pt = k => P.map(p => [p.t, p[k]]), pctf = v => Math.round(v) + '%';
    hLine($('#pf1'), [{ name: 'CPU', color: '#e4572e', pts: pt('cpu') }, { name: 'I/O wait', color: '#6d5bd0', pts: pt('iowait') }], pctf, { max: 100, limit: 90 });
    hLine($('#pf2'), [{ name: 'Memory', color: '#0e7490', pts: pt('mem_pct') }, { name: 'Swap', color: '#e08a00', pts: pt('swap_pct') }], pctf, { max: 100, limit: 90 });
    const sm = v => v < 10 ? v.toFixed(1) : short(Math.round(v));
    hLine($('#pf3'), [{ name: 'Received', color: '#0e7490', pts: pt('in_rate') }, { name: 'Written', color: '#2f9e6e', pts: pt('out_rate') }], sm, { max: Math.max(5, ...P.map(p => Math.max(p.in_rate, p.out_rate))) * 1.1 });
    hLine($('#pf4'), [{ name: 'Write time', color: '#c2417a', pts: pt('write_ms') }], v => sm(v) + ' ms', { max: Math.max(50, ...P.map(p => p.write_ms)) * 1.1 });
  };
}
