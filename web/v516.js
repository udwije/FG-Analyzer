// v5.16: Advanced view, WAN links (SNMPv3), system health and certificate requests, settings for network devices.
const bps = n => { n = +n || 0; return n >= 1e9 ? (n / 1e9).toFixed(2) + ' Gbps' : n >= 1e6 ? (n / 1e6).toFixed(1) + ' Mbps' : n >= 1e3 ? (n / 1e3).toFixed(0) + ' kbps' : Math.round(n) + ' bps' };
const mbps = n => n ? (n >= 1000 ? (n / 1000) + ' Gbps' : n + ' Mbps') : '';

// ------------------------------------------------------------ All logs / Advanced
function renderAdvanced(X) {
  const adv = view === 'advanced';
  $('#gadvrow').hidden = !adv;
  $('#gviewnote').innerHTML = adv
    ? '<b>Advanced:</b> every log, including the firewalls\' own traffic, routing, multicast, the infrastructure addresses and site-to-site duplicates. <a href="#" data-goview="global">Back to endpoint traffic</a>'
    : 'Endpoint traffic: what your users, devices and servers do. Download and upload are from the endpoint\'s point of view. Device traffic is in <a href="#" data-goview="advanced">Advanced</a>.';
  $$('#gviewnote [data-goview]').forEach(a => a.onclick = e => { e.preventDefault(); setView(a.dataset.goview) });
  if (!adv || !X) return;
  $('#gadvsrc').innerHTML = rlist(X.advSources, { key: 'src' });
  $('#gadvdst').innerHTML = rlist(X.advDests, { key: destKey });
  $('#gadvsvc').innerHTML = rlist(X.advServices, { key: 'service' });
  const z = Object.fromEntries((X.zones || []).map(x => [x.name, x])), g = k => z[k] || { count: 0, bytes: 0 };
  const dev = ['firewall', 'infra', 'transit'], all = (X.zones || []).reduce((a, x) => a + x.count, 0) || 1, allB = (X.zones || []).reduce((a, x) => a + x.bytes, 0) || 1;
  $('#gadvshare').innerHTML = `<div class="zt">${dev.map(k => { const n = ZN[k]; return `<div style="grid-template-columns:12px minmax(0,1.6fr) auto auto"><i style="background:${n[1]}"></i><span><b>${n[0]}</b><small>${n[2]}</small></span><span class="v">${short(g(k).count)} logs<br>${bytes(g(k).bytes)}</span><b class="p">${pc(g(k).count, all)}%</b></div>` }).join('')}</div>
    <p class="hint" style="margin-top:10px">Of all traffic logs in this period: ${pc(dev.reduce((a, k) => a + g(k).count, 0), all)}% of the logs and ${pc(dev.reduce((a, k) => a + g(k).bytes, 0), allB)}% of the data.</p>`;
}

// ------------------------------------------------------------ WAN links
let WAN = null;
async function loadWAN(signal) {
  const liveReq = api('/api/wan?live=1', { signal });
  const histReq = api('/api/wan?' + qs(), { signal });
  let live = null;
  try { live = await liveReq; WAN = { ...(WAN || {}), ...live, links: (WAN && WAN.links) || live.links || [], usage: (WAN && WAN.usage) || {} }; renderWAN(); }
  catch (x) { if (!signal.aborted) { WAN = WAN || { enabled: true, links: [], status: [], usage: {} }; renderWAN(); } }
  try { const history = await histReq; WAN = { ...(live || {}), ...history }; renderWAN(); }
  catch (x) { if (!signal.aborted) { const el=document.querySelector('#wanstatus'); if(el) el.insertAdjacentHTML('beforeend', `<div class="card notice">Live WAN status is shown. Historical data for the selected filters could not be loaded: ${esc(x.message)}</div>`); } }
}

function renderWAN() {
  const W = WAN, links = W.links || [];
  renderPeriod({ from: W.from, to: W.to }, [[num(links.length), 'Links'], [W.enabled ? (W.poll_seconds + ' s') : 'off', 'Polling'],
    [links.length ? bps(links.reduce((a, l) => a + (+l.p95_down || 0), 0)) : '–', '95th pct. down (sum)']]);
  const st = W.status || [];
  $('#wanstatus').innerHTML = !W.enabled ? `<div class="card notice">WAN polling is off. Add the firewalls and their WAN interfaces in <a href="#" data-goview="settings">Settings &gt; WAN links</a>.</div>`
    : `<div class="card wanst">${st.map(d => `<span class="${d.error ? 'bad' : 'ok'}"><i class="sd ${d.error ? 'bad' : d.last_ok ? 'ok' : ''}"></i><b>${esc(d.name)}</b> ${d.error ? `<span class="err">${esc(d.error)}</span>` : d.last_ok ? 'polled ' + ago(new Date(d.last_ok) / 1000) : 'waiting for the first poll'}</span>`).join('')}</div>`;
  $$('#wanstatus [data-goview]').forEach(a => a.onclick = e => { e.preventDefault(); setView(a.dataset.goview) });
  if (!links.length) { $('#wanbody').innerHTML = W.enabled ? '<div class="card"><p class="muted">No WAN interfaces chosen yet.</p></div>' : ''; return }
  const live = {}; st.forEach(d => Object.entries(d.live || {}).forEach(([k, v]) => live[d.name + '|' + k] = v));
  const util = (v, cap) => cap ? Math.round(100 * v / (cap * 1e6)) : null;
  const pill = p => p == null ? '' : `<span class="upill ${p >= 80 ? 'r' : p >= 60 ? 'a' : ''}">${p}%</span>`;
  $('#wanbody').innerHTML = `<div class="card"><h3>Summary</h3><p class="hint">Average, 95th percentile (what the link carried 95% of the time) and peak for the selected period. Busy = share of the time above 80% of the contracted capacity.</p>
    ${table([['Link'], ['Capacity'], ['Now ↓ / ↑', 1], ['Average ↓ / ↑', 1], ['95th pct ↓ / ↑', 1], ['Peak ↓ / ↑', 1], ['Busy ↓ / ↑', 1], ['Down', 1]], links.map(l => {
      const lv = live[l.dev + '|' + l.iface] || {}, n = +l.samples || 0;
      return `<tr><td><b>${esc(l.label)}</b> <small class="muted">${esc(l.dev)} · ${esc(l.iface)}${lv.alias ? ' · ' + esc(lv.alias) : ''}</small></td><td>${mbps(l.down_mbps)}${l.up_mbps && l.up_mbps !== l.down_mbps ? ' / ' + mbps(l.up_mbps) : ''}</td>
        <td class="n">${lv.found === false ? '<span class="err">not found</span>' : lv.at ? `${bps(lv.rx)} / ${bps(lv.tx)}` : '–'}</td>
        ${!n ? '<td class="n" colspan="3"><span class="muted">no samples in this period</span></td>' : `<td class="n">${bps(l.avg_down)} / ${bps(l.avg_up)}</td><td class="n">${bps(l.p95_down)} ${pill(util(l.p95_down, l.down_mbps))} / ${bps(l.p95_up)} ${pill(util(l.p95_up, l.up_mbps))}</td>
        <td class="n">${bps(l.peak_down)} / ${bps(l.peak_up)}</td>`}<td class="n">${n ? pc(l.busy_down, n) + '% / ' + pc(l.busy_up, n) + '%' : '–'}</td><td class="n">${n && l.down_samples ? pc(l.down_samples, n) + '%' : n ? 'never' : '–'}</td></tr>`;
    }))}</div><div class="grid">${links.map((l, i) => !(l.series || []).length ? `<article class="card"><div class="ch"><h3>${esc(l.label)}</h3><span class="hint">${esc(l.dev)} · ${esc(l.iface)}</span></div><p class="muted">No samples in this period${(live[l.dev + '|' + l.iface] || {}).found === false ? ': the firewall has no interface with this name' : ''}.</p></article>` : `<article class="card"><div class="ch"><h3>${esc(l.label)}</h3><span class="hint">${esc(l.dev)} · ${esc(l.iface)}${l.down_mbps ? ' · capacity ' + mbps(l.down_mbps) : ''}</span></div>
      <div class="dchart"><div class="dlab">Download<span>${bps(l.avg_down)}</span><small class="muted">average</small></div><div class="chartwrap mini2" id="wd${i}"></div></div>
      <div class="dchart"><div class="dlab">Upload<span>${bps(l.avg_up)}</span><small class="muted">average</small></div><div class="chartwrap mini2" id="wu${i}"></div></div>
      ${l.by_hour_down ? `<p class="hint" style="margin:10px 0 4px">Busiest hours (average download${l.down_mbps ? ', share of capacity' : ''})</p><div class="hrow">${l.by_hour_down.map((v, h) => { const p = l.down_mbps ? v / (l.down_mbps * 1e6) : v / Math.max(1, ...l.by_hour_down); return `<i title="${String(h).padStart(2, '0')}:00 ${bps(v)}" style="background:rgba(14,116,144,${(0.06 + 0.9 * Math.min(1, p)).toFixed(2)})">${h % 3 ? '' : h}</i>` }).join('')}</div>` : ''}</article>`).join('')}</div>`;
  links.forEach((l, i) => {
    if (!(l.series || []).length) return;
    const s = l.series || [], step = W.step || 60, t0 = s.length ? s[0][0] : Math.floor(new Date(W.from) / 1000 / step) * step;
    const ax = { step, t0, n: Math.max(1, Math.min(700, Math.ceil((new Date(W.to) / 1000 - t0) / step))), idx: t => Math.floor((t - t0) / step) };
    const dn = Array(ax.n).fill(0), up = Array(ax.n).fill(0);
    s.forEach(r => { const k = ax.idx(r[0]); if (k >= 0 && k < ax.n) { dn[k] = r[1]; up[k] = r[2] } });
    stackChart($('#wd' + i), ax, [{ name: 'Download', color: '#0e7490', vals: dn }], bps, 150);
    stackChart($('#wu' + i), ax, [{ name: 'Upload', color: '#6d5bd0', vals: up }], bps, 150);
  });
}

// ------------------------------------------------------------ Settings: network devices, tunnels, WAN devices
let WANDEVS = [];
function wanDevHTML(d, i) {
  const sel = (n, list, v) => `<select data-f="${n}">${list.map(x => `<option${x === v ? ' selected' : ''}>${x}</option>`).join('')}</select>`;
  return `<fieldset class="wandev" data-i="${i}"><legend>Firewall ${i + 1}</legend><div class="formgrid three">
    <label>Name<input data-f="name" value="${esc(d.name || '')}" placeholder="HO-FW"></label><label>Address<input data-f="host" value="${esc(d.host || '')}" placeholder="10.0.0.1"></label>
    <label>SNMP port<input data-f="port" type="number" value="${d.port || 161}"></label><label>SNMPv3 username<input data-f="username" value="${esc(d.username || '')}" placeholder="fgt-monitor"></label>
    <label>Security level${sel('security_level', ['authPriv', 'authNoPriv'], d.security_level || 'authPriv')}</label><label>Authentication${sel('auth_protocol', ['SHA256', 'SHA512', 'SHA1', 'MD5'], d.auth_protocol || 'SHA256')}</label>
    <label>Privacy${sel('priv_protocol', ['AES128', 'AES256'], d.priv_protocol || 'AES128')}</label><label>Auth passphrase<input data-f="auth_pass" type="password" autocomplete="new-password" placeholder="${d.host ? 'stored: leave empty to keep' : ''}"></label>
    <label>Priv passphrase<input data-f="priv_pass" type="password" autocomplete="new-password" placeholder="${d.host ? 'stored: leave empty to keep' : ''}"></label></div>
    <table class="wanif"><thead><tr><th>Interface</th><th>Label on the dashboard</th><th>Download Mbps</th><th>Upload Mbps</th><th></th></tr></thead><tbody>${(d.interfaces || []).map((f, j) => `<tr data-j="${j}">
      <td><input data-g="name" value="${esc(f.name)}"></td><td><input data-g="label" value="${esc(f.label || '')}" placeholder="e.g. SLT 100M ILL"></td><td><input data-g="down_mbps" type="number" value="${f.down_mbps || ''}"></td><td><input data-g="up_mbps" type="number" value="${f.up_mbps || ''}"></td>
      <td><button type="button" data-rmif="${j}">Remove</button></td></tr>`).join('')}</tbody></table>
    <div class="actions left"><button type="button" data-find="${i}">Find interfaces</button><button type="button" data-addif="${i}">+ Interface by name</button><span class="sep"></span><button type="button" data-rmdev="${i}">Remove this firewall</button></div>
    <div class="wanfound" id="wanfound${i}"></div></fieldset>`;
}
function readWANDevs() {
  return $$('#wandevs .wandev').map(fs => {
    const d = {}; fs.querySelectorAll('[data-f]').forEach(x => d[x.dataset.f] = x.type === 'number' ? +x.value || 0 : x.value.trim());
    d.interfaces = [...fs.querySelectorAll('tbody tr')].map(tr => { const f = {}; tr.querySelectorAll('[data-g]').forEach(x => f[x.dataset.g] = x.type === 'number' ? +x.value || 0 : x.value.trim()); return f }).filter(f => f.name);
    return d;
  });
}
function renderWANDevs() { $('#wandevs').innerHTML = WANDEVS.map(wanDevHTML).join('') || '<p class="muted">No firewall added.</p>' }
$('#wanadd').onclick = () => { WANDEVS = readWANDevs(); WANDEVS.push({ port: 161, interfaces: [] }); renderWANDevs() };
$('#wandevs').addEventListener('click', async e => {
  const b = e.target.closest('button'); if (!b) return;
  if (b.dataset.rmdev != null) { WANDEVS = readWANDevs(); WANDEVS.splice(+b.dataset.rmdev, 1); renderWANDevs(); return }
  if (b.dataset.rmif != null) { const i = +b.closest('.wandev').dataset.i; WANDEVS = readWANDevs(); WANDEVS[i].interfaces.splice(+b.dataset.rmif, 1); renderWANDevs(); return }
  if (b.dataset.addif != null) { const i = +b.dataset.addif, n = prompt('Interface name on the FortiGate (ifName, e.g. wan1, port5)'); if (!n) return; WANDEVS = readWANDevs(); WANDEVS[i].interfaces.push({ name: n.trim() }); renderWANDevs(); return }
  if (b.dataset.pick != null) {
    const i = +b.dataset.dev, x = JSON.parse(b.dataset.pick); WANDEVS = readWANDevs();
    if (!WANDEVS[i].interfaces.some(f => f.name === x.name)) WANDEVS[i].interfaces.push({ name: x.name, label: x.alias || x.name, down_mbps: Math.round((x.est_down_kbps || 0) / 1000) || x.speed_mbps || 0, up_mbps: Math.round((x.est_up_kbps || 0) / 1000) || x.speed_mbps || 0 });
    renderWANDevs(); return;
  }
  if (b.dataset.find != null) {
    const i = +b.dataset.find, d = readWANDevs()[i], el = $('#wanfound' + i); el.innerHTML = '<p class="muted">Asking the firewall…</p>';
    try {
      const r = await jsend('/api/wan/discover', 'POST', d);
      el.innerHTML = `<p class="hint">${esc(r.sys_name)}: ${r.interfaces.length} interfaces. Pick the internet circuits (the speed shown is the port speed; enter the contracted capacity).</p>
        <div class="scrollbox">${table([['Interface'], ['Alias'], ['Port speed'], ['Estimated bandwidth ↓ / ↑'], ['State'], ['']], r.interfaces.filter(x => x.type !== 24).map(x => `<tr><td><b>${esc(x.name)}</b></td><td>${esc(x.alias)}</td><td>${mbps(x.speed_mbps)}</td><td>${x.est_down_kbps || x.est_up_kbps ? mbps(Math.round(x.est_down_kbps / 1000)) + ' / ' + mbps(Math.round(x.est_up_kbps / 1000)) : '<span class="muted">not set</span>'}</td><td>${x.up ? 'up' : '<span class="muted">down</span>'}</td>
          <td><button type="button" data-dev="${i}" data-pick='${esc(JSON.stringify({ name: x.name, alias: x.alias, speed_mbps: x.speed_mbps, est_down_kbps: x.est_down_kbps, est_up_kbps: x.est_up_kbps }))}'>Add</button></td></tr>`))}</div>`;
    } catch (x) { el.innerHTML = `<p class="err">${esc(x.message)}</p>` }
  }
});
{
  const _fc = formConfig;
  formConfig = function () {
    const c = _fc(), f = $('#config').elements;
    c.infra_networks = lines(f.infra_networks.value); c.tunnel_interfaces = lines(f.tunnel_interfaces.value);
    c.wan = { enabled: f.wan_enabled.checked, poll_seconds: +f.wan_poll.value || 30, keep_days: +f.wan_keep.value || 180, devices: readWANDevs() };
    return c;
  };
  const _lc = loadConfig;
  loadConfig = async function () {
    await _lc();
    const f = $('#config').elements, c = CFG || {}, w = c.wan || {};
    f.infra_networks.value = (c.infra_networks || []).join('\n'); f.tunnel_interfaces.value = (c.tunnel_interfaces || []).join('\n');
    f.wan_enabled.checked = !!w.enabled; f.wan_poll.value = w.poll_seconds || 30; f.wan_keep.value = w.keep_days || 180;
    WANDEVS = JSON.parse(JSON.stringify(w.devices || [])); renderWANDevs();
    loadHealth();
  };
}

// ------------------------------------------------------------ Settings: system health and the certificate
async function loadHealth() {
  const el = $('#syshealth');
  let H;
  try { H = await api('/api/health') } catch (x) { el.innerHTML = `<p class="err">${esc(x.message)}</p>`; return }
  const db = H.database || {}, jobs = (H.jobs || {}).list || [], t = H.tls || {}, dir = H.directory || {}, sp = H.spool || {};
  const disks = (H.disk || []).map(dk => {
    const days = db.bytes_per_day ? Math.floor(dk.free / db.bytes_per_day) : null;
    return `<div><small>${esc(dk.label)} disk</small><b>${bytes(dk.free)} free</b><span>of ${bytes(dk.total)}${days != null && dk.label.startsWith('PostgreSQL') ? ` · about ${num(days)} days at today's growth` : ''}</span></div>`;
  }).join('');
  const exp = t.not_after ? Math.floor((new Date(t.not_after) - Date.now()) / 864e5) : null;
  el.innerHTML = `<div class="ch"><h2 style="margin:0">System health</h2><span class="hint">Refreshed when you open Settings</span></div>
    <div class="hkpis"><div><small>Database</small><b>${db.size ? bytes(db.size) : '–'}</b><span>${db.timescale ? 'TimescaleDB' : 'PostgreSQL'}${db.connected === false ? ' · not connected' : ''}</span></div>
      <div><small>Logs per day</small><b>${db.logs_per_day ? short(db.logs_per_day) : '–'}</b><span>${db.bytes_per_day ? 'about ' + bytes(db.bytes_per_day) + ' a day' : ''}</span></div>
      <div><small>Size at ${db.retention_days || '–'} days kept</small><b>${db.steady_size ? bytes(db.steady_size) : '–'}</b><span>upper bound (compression shrinks older days)</span></div>
      ${disks}
      <div><small>Spool</small><b>${num(sp.files)} files</b><span>${bytes(sp.bytes)} of ${num(sp.max_mb)} MB</span></div>
      <div><small>Staff list</small><b>${dir.loaded ? num(dir.active) + ' active' : dir.enabled ? 'waiting' : 'off'}</b><span>${dir.error ? `<span class="err">${esc(dir.error)}</span>` : dir.imported ? 'read ' + ldt(dir.imported) : ''}${(dir.files || []).map(f => ' · ' + esc(f.path.split('/').pop()) + ' ' + ldt(f.modified)).join('')}</span></div></div>
    <h3 class="formsub">Background work</h3><div class="jobs">${jobs.map(j => `<div><span>${esc(j.label)}</span><span class="jbar"><i style="width:${j.percent}%"></i></span><b>${j.done ? 'done' : j.percent + '%'}</b><small class="muted">${!j.done && j.upto ? 'at ' + ldt(j.upto) : ''}</small></div>`).join('')}
      <div><span>Hours waiting to be re-summarised</span><span></span><b>${num((H.jobs || {}).dirty_hours || 0)}</b><small></small></div>
      <div><span>Finished days summarised</span><span></span><b>${num((H.jobs || {}).days_built || 0)}</b><small></small></div></div>
    ${(db.tables || []).length ? `<details><summary>Largest tables</summary>${table([['Table'], ['Size', 1]], db.tables.map(x => `<tr><td>${esc(x.name)}</td><td class="n">${bytes(x.size)}</td></tr>`))}</details>` : ''}
    <h3 class="formsub">Dashboard certificate</h3>
    <p>${t.subject ? `<b>${esc(t.subject)}</b> issued by ${esc(t.issuer)}${t.self_signed ? ' <span class="pill bad">self-signed</span>' : ''} · expires ${ldt(t.not_after)}${exp != null && exp < 30 ? ` <span class="pill bad">in ${exp} days</span>` : ''}` : 'No certificate found.'}</p>
    <details${t.pending_request ? ' open' : ''}><summary>Use a certificate from your own CA (removes the browser warning)</summary>
      <p class="hint">1. Create a request here. 2. Have your CA (e.g. Active Directory Certificate Services, Web Server template) sign it. 3. Paste the signed certificate (with the chain) and install it. The private key never leaves this server. Restart the service afterwards.</p>
      <div class="formgrid three"><label>Name people use<input id="tls-cn" placeholder="logsikka.corp.lk"></label><label>Other names or IPs (one per line)<textarea id="tls-names" rows="2" placeholder="logsikka&#10;192.168.2.20"></textarea></label><label>Organisation<input id="tls-org"></label></div>
      <div class="actions left"><button type="button" id="tls-csr">Create request</button></div>
      <textarea id="tls-csrout" rows="6" readonly ${t.csr ? '' : 'hidden'}>${esc(t.csr || '')}</textarea>
      <label>Signed certificate (PEM, with the chain)<textarea id="tls-cert" rows="5" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label>
      <div class="actions left"><button type="button" id="tls-install">Install certificate</button><span id="tls-msg" class="muted"></span></div></details>`;
  $('#tls-csr').onclick = async () => {
    try { const r = await jsend('/api/tls', 'POST', { action: 'csr', cn: $('#tls-cn').value, org: $('#tls-org').value, names: lines($('#tls-names').value) }); $('#tls-csrout').hidden = false; $('#tls-csrout').value = r.csr; $('#tls-csrout').select(); $('#tls-msg').textContent = 'Request created: copy it to your CA.' }
    catch (x) { $('#tls-msg').textContent = x.message }
  };
  $('#tls-install').onclick = async () => {
    try { await jsend('/api/tls', 'POST', { action: 'install', cert: $('#tls-cert').value }); $('#tls-msg').textContent = 'Installed. Restart the service (sudo systemctl restart logsikka) to use it.'; loadHealth() }
    catch (x) { $('#tls-msg').textContent = x.message }
  };
}
