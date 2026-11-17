// v5.13: Devices & people (assignments, staff, suggestions, warnings) and Alerts.
const DTYPES = { person: ['Person', '#0e7490'], server: ['Server', '#6d5bd0'], printer: ['Printer / scanner', '#8a6d3b'], shared: ['Shared device', '#0f9d8a'],
  network: ['Network device', '#3b82c4'], camera: ['Camera / IoT', '#c2417a'], ignore: ['Ignore', '#9aa5b1'], unknown: ['Unknown device', '#e4572e'] };
const tpill = t => `<span class="tpill" style="--c:${(DTYPES[t] || DTYPES.unknown)[1]}">${esc((DTYPES[t] || [t])[0])}</span>`;
let DV = null, DVTAB = (() => { try { return localStorage.getItem('fortilog.dvtab') || 'unassigned' } catch { return 'unassigned' } })();
let ASG = null, STAFF = null, HIST = null, DVSEL = new Set(), ASQ = '', ASTYPE = '', STQ = '', STSHOW = 'active';
const DISMISS = new Set((() => { try { return JSON.parse(localStorage.getItem('fortilog.dismissed') || '[]') } catch { return [] } })());

// attribution bar: shared by All logs and Devices & people
function renderAttr(el, A) {
  if (!el) return;
  if (!A || !A.total) { el.hidden = true; return }
  el.hidden = false;
  const tot = A.total || 1;
  el.innerHTML = `<div class="ch"><h3>Who is behind the traffic</h3><span class="hint">Internal devices, by activity. ${A.staff_list ? '' : 'Load the staff list (Settings) to count verified staff only.'}</span>
    <span class="cov"><b>${A.coverage}%</b> traced to a person or a known device</span></div>
    <div class="zbar">${A.parts.map(p => `<i style="width:${100 * p.count / tot}%;background:${(DTYPES[p.name] || DTYPES.unknown)[1]}" title="${esc(p.label)}: ${pc(p.count, tot)}%"></i>`).join('')}</div>
    <div class="clegend">${A.parts.map(p => `<span class="nolink"><i style="background:${(DTYPES[p.name] || DTYPES.unknown)[1]}"></i>${esc(p.label)} <b>${pc(p.count, tot)}%</b></span>`).join('')}
    ${A.people != null ? `<span class="nolink"><b>${num(A.people)}</b> ${A.staff_list ? 'staff' : 'people'} seen</span>` : ''}</div>`;
}

const DVTABS = [['unassigned', 'Devices without a user'], ['suggestions', 'Suggestions'], ['assignments', 'Assignments'], ['staff', 'Staff'], ['warnings', 'Warnings'], ['history', 'History']];
async function loadDevices(signal) {
  const [dv, as] = await Promise.all([api('/api/devices?' + qs(), { signal }), api('/api/assignments', { signal })]);
  DV = dv; ASG = as;
  if (DVTAB === 'staff' && !STAFF) STAFF = await api('/api/staff', { signal });
  if (DVTAB === 'history') HIST = await api('/api/assignments/history', { signal });
  renderDevices();
}
function renderDevices() {
  const pf = F.range === 'custom' && F.from && F.to ? { from: new Date(F.from), to: new Date(F.to) } : { from: new Date(Date.now() - (+F.range || 24) * 36e5), to: new Date() };
  renderPeriod(pf, [[num((ASG.assignments || []).length), 'Assignments'], [num((DV.unassigned || []).length), 'Without a user'], [DV.attribution ? DV.attribution.coverage + '%' : '–', 'Traced']]);
  renderAttr($('#dvattr'), DV.attribution);
  const sug = (DV.suggestions || []).filter(s => !DISMISS.has(s.value)), w = DV.warnings || [];
  const cnt = { unassigned: (DV.unassigned || []).length, suggestions: sug.length, assignments: (ASG.assignments || []).length, warnings: w.length };
  $('#dvseg').innerHTML = DVTABS.map(([k, l]) => `<button type="button" data-dv="${k}" class="${k === DVTAB ? 'on' : ''}">${l}${cnt[k] ? ` <small class="cnt${k === 'warnings' ? ' w' : ''}">${cnt[k]}</small>` : ''}</button>`).join('');
  const people = (ASG.assignments || []).filter(a => a.type === 'person').length;
  $('#dvtiles').innerHTML = kpi('Traced', DV.attribution ? DV.attribution.coverage + '%' : '–', 'of internal activity has a person or a known device') +
    kpi('Devices without a user', num(cnt.unassigned), 'in this period, busiest first') + kpi('Suggestions', num(sug.length), 'ready to accept') +
    kpi('Assignments', num(cnt.assignments), `${num(people)} to people, ${num(cnt.assignments - people)} other devices`) + kpi('Warnings', num(w.length), 'to review');
  const B = $('#dvbody');
  ({ unassigned: renderUnassigned, suggestions: () => renderSuggestions(sug), assignments: renderAssignments, staff: renderStaff, warnings: () => renderWarnings(w), history: renderHistory })[DVTAB](B);
}
$('#dvseg').addEventListener('click', async e => {
  const b = e.target.closest('[data-dv]'); if (!b) return;
  DVTAB = b.dataset.dv; try { localStorage.setItem('fortilog.dvtab', DVTAB) } catch { }
  if (DVTAB === 'staff') STAFF = null;
  if (DVTAB === 'staff' || DVTAB === 'history') await refresh(); else renderDevices();
});

function renderUnassigned(B) {
  const rows = DV.unassigned || [];
  B.innerHTML = `<div class="card"><div class="ch"><h3>Devices without a user</h3><span class="hint">Internal addresses whose traffic has no username in this period, busiest first. Host name, MAC, device type and OS come from the FortiGate's newest log for the address.</span></div>
    <div class="bulk" id="bulk" hidden><b id="bulkn"></b><select id="bulktype">${Object.entries(DTYPES).filter(([k]) => k !== 'unknown').map(([k, v]) => `<option value="${k}">${v[0]}</option>`).join('')}</select>
      <input id="bulkowner" list="dl-staff" placeholder="person or label"><button type="button" id="bulkgo" class="primary">Assign selected</button><button type="button" id="bulkclear">Clear</button></div>
    ${rows.length ? `<div class="tablewrap" style="max-height:none"><table class="dvt"><thead><tr><th><input type="checkbox" id="selall"></th><th>Address</th><th>Host name</th><th>MAC</th><th>Device</th><th>Last user seen</th><th class="n">Events without user</th><th class="n">Data</th><th></th></tr></thead><tbody>
    ${rows.map(r => `<tr><td><input type="checkbox" data-sel="${esc(r.ip)}"${DVSEL.has(r.ip) ? ' checked' : ''}></td><td><b>${esc(r.ip)}</b></td>
      <td>${esc(r.host || '–')}${r.domain ? ' <span class="pill ok" title="In computers.csv">domain PC</span>' : ''}</td><td class="mono">${esc(r.mac || '–')}</td>
      <td>${esc([r.devtype, r.os].filter(Boolean).join(' · ') || '–')}</td><td>${r.last_user ? esc(r.last_user) + staffBadge(r.last_user) : '<span class="muted">nobody</span>'}</td>
      <td class="n">${num(r.unknown)}</td><td class="n">${bytes(r.bytes)}</td>
      <td class="acts"><button type="button" data-assign="${esc(r.ip)}" data-mac="${esc(r.mac || '')}" data-host="${esc(r.host || '')}" data-user="${esc(r.last_user || '')}">Assign</button></td></tr>`).join('')}</tbody></table></div>`
    : `<p class="muted">${DV.mapping_ready ? 'Every internal device in this period has a username or an assignment.' : 'The summaries for this period are still being built; try a shorter period or check back in a few minutes.'}</p>`}</div>`;
  staffList();
  const upd = () => { $('#bulk').hidden = !DVSEL.size; $('#bulkn').textContent = `${DVSEL.size} selected`; };
  B.querySelectorAll('[data-sel]').forEach(c => c.onchange = () => { c.checked ? DVSEL.add(c.dataset.sel) : DVSEL.delete(c.dataset.sel); upd() });
  if ($('#selall')) $('#selall').onchange = e => { B.querySelectorAll('[data-sel]').forEach(c => { c.checked = e.target.checked; c.checked ? DVSEL.add(c.dataset.sel) : DVSEL.delete(c.dataset.sel) }); upd() };
  upd();
  $('#bulkclear').onclick = () => { DVSEL.clear(); renderDevices() };
  $('#bulkgo').onclick = async () => {
    const type = $('#bulktype').value, owner = $('#bulkowner').value.trim(); if (!owner) { alert('Enter the person or a label.'); return }
    let ok = 0, errs = [];
    for (const ip of DVSEL) { try { await jsend('/api/assignments', 'POST', { value: ip, type, owner }); ok++ } catch (x) { errs.push(ip + ': ' + x.message) } }
    DVSEL.clear(); toast(`${ok} device${ok === 1 ? '' : 's'} assigned.` + (errs.length ? ' ' + errs.join('; ') : '')); D = G = null; refresh();
  };
  B.querySelectorAll('[data-assign]').forEach(b => b.onclick = () => assignDialog({ value: b.dataset.assign, mac: b.dataset.mac, host: b.dataset.host, owner: b.dataset.user, type: b.dataset.user ? 'person' : '' }));
}
const staffBadge = u => { if (!STAFFIDX) return ''; const s = STAFFIDX.get(u); return !s ? '' : s.active ? '' : ' <span class="pill bad">left</span>' };
let STAFFIDX = null;
async function staffList() {
  if (!STAFF) { try { STAFF = await api('/api/staff') } catch { return } }
  STAFFIDX = new Map((STAFF.staff || []).map(s => [s.user, s]));
  let dl = $('#dl-staff'); if (!dl) { dl = document.createElement('datalist'); dl.id = 'dl-staff'; document.body.appendChild(dl) }
  dl.innerHTML = (STAFF.staff || []).filter(s => s.active).map(s => `<option value="${esc(s.user)}">${esc([s.display, s.dept].filter(Boolean).join(' · '))}</option>`).join('');
}

function renderSuggestions(sug) {
  const B = $('#dvbody');
  B.innerHTML = `<div class="card"><div class="ch"><h3>Suggestions</h3><span class="hint">Addresses or devices where NPS or the firewall saw the same person on most of the last 7 days. Accepting makes the assignment permanent.</span>
    ${sug.length ? '<button type="button" id="sugall" class="primary" style="margin-left:auto">Accept all</button>' : ''}</div>
    ${sug.length ? `<table><thead><tr><th>Device</th><th>Person</th><th>Why</th><th></th></tr></thead><tbody>${sug.map((s, i) => `<tr><td><b>${esc(s.value)}</b>${s.value !== s.ip ? ` <span class="muted">(${esc(s.ip)})</span>` : ''}</td>
      <td>${esc(s.owner)}${staffBadge(s.owner)}</td><td class="muted">${esc(s.why)}</td><td class="acts"><button type="button" data-acc="${i}" class="primary">Accept</button><button type="button" data-edit="${i}">Edit…</button><button type="button" data-dis="${i}">Dismiss</button></td></tr>`).join('')}</tbody></table>`
      : '<p class="muted">No suggestions right now. They appear when the same person uses a device on most days.</p>'}</div>`;
  staffList();
  const acc = async s => jsend('/api/assignments', 'POST', { value: s.value, type: 'person', owner: s.owner, note: 'accepted suggestion: ' + s.why });
  B.querySelectorAll('[data-acc]').forEach(b => b.onclick = async () => { try { await acc(sug[+b.dataset.acc]); toast('Assigned.'); refresh() } catch (x) { toast(x.message) } });
  B.querySelectorAll('[data-edit]').forEach(b => b.onclick = () => { const s = sug[+b.dataset.edit]; assignDialog({ value: s.value, type: 'person', owner: s.owner, note: s.why }) });
  B.querySelectorAll('[data-dis]').forEach(b => b.onclick = () => { DISMISS.add(sug[+b.dataset.dis].value); try { localStorage.setItem('fortilog.dismissed', JSON.stringify([...DISMISS])) } catch { } renderDevices() });
  if ($('#sugall')) $('#sugall').onclick = async () => { if (!confirm(`Accept all ${sug.length} suggestions?`)) return; let n = 0; for (const s of sug) { try { await acc(s); n++ } catch { } } toast(`${n} assigned.`); refresh() };
}

function renderAssignments(B) {
  const q = ASQ.toLowerCase(), all = ASG.assignments || [];
  const rows = all.filter(a => (!ASTYPE || a.type === ASTYPE) && (!q || [a.value, a.owner, a.display, a.dept, a.note].join(' ').toLowerCase().includes(q)));
  B.innerHTML = `<div class="card"><div class="ch"><h3>Assignments</h3><span class="hint">Permanent: one entry per IP address, subnet, MAC address or host name. The most specific wins (MAC, then IP, then the smallest subnet, then the host name).</span></div>
    <div class="dvfilter"><input id="asq" placeholder="Search address, person, label, department…" value="${esc(ASQ)}"><select id="astype"><option value="">All types</option>${Object.entries(DTYPES).filter(([k]) => k !== 'unknown').map(([k, v]) => `<option value="${k}"${k === ASTYPE ? ' selected' : ''}>${v[0]}</option>`).join('')}</select>
      <span class="muted">${rows.length} of ${all.length}</span><span class="sep"></span><a class="btnlink" href="/api/assignments.csv">Export CSV</a></div>
    ${rows.length ? `<div class="tablewrap" style="max-height:none"><table class="dvt"><thead><tr><th>Device</th><th>Type</th><th>Person or label</th><th>Department</th><th>Note</th><th>Until</th><th>Changed</th><th></th></tr></thead><tbody>
    ${rows.map(a => `<tr><td><b>${esc(a.value)}</b> <small class="muted">${esc(a.kind)}</small>${a.mac ? `<br><small class="mono muted">${esc(a.mac)}</small>` : ''}</td><td>${tpill(a.type)}</td>
      <td>${esc(a.owner)}${a.display ? ` <small class="muted">${esc(a.display)}</small>` : ''}${a.former ? ' <span class="pill bad">left</span>' : ''}</td><td>${esc(a.dept || '')}</td><td class="muted">${esc(a.note || '')}</td>
      <td>${a.until ? ldt(a.until).split(',')[0] : ''}</td><td class="muted">${ldt(a.updated)}${a.by ? ' · ' + esc(a.by) : ''}</td>
      <td class="acts"><button type="button" data-ed="${a.id}">Edit</button><button type="button" data-del="${a.id}">Delete</button></td></tr>`).join('')}</tbody></table></div>` : '<p class="muted">Nothing matches.</p>'}
    <details class="imp"><summary>Import from CSV</summary><p class="hint">One per line: <code>value,type,owner,dept,note,mac,until</code>. Value is an IP, subnet, MAC or host name; type is person, server, printer, shared, network, camera or ignore. An existing entry for the same value is updated.</p>
      <textarea id="ascsv" rows="6" placeholder="10.10.5.20,server,File server,IT&#10;10.10.5.0/28,server,Domain controllers,IT&#10;00:1a:2b:3c:4d:5e,person,kamal.silva,HR,HR desk PC"></textarea><button type="button" id="asimp" class="primary">Import</button> <span id="asmsg" class="hint"></span></details></div>`;
  $('#asq').oninput = e => { ASQ = e.target.value; const p = e.target.selectionStart; renderAssignments(B); $('#asq').focus(); $('#asq').setSelectionRange(p, p) };
  $('#astype').onchange = e => { ASTYPE = e.target.value; renderAssignments(B) };
  B.querySelectorAll('[data-ed]').forEach(b => b.onclick = () => assignDialog(all.find(a => a.id === +b.dataset.ed)));
  B.querySelectorAll('[data-del]').forEach(b => b.onclick = async () => {
    const a = all.find(x => x.id === +b.dataset.del); if (!confirm(`Delete the assignment of ${a.value} (${a.owner})?`)) return;
    try { const r = await jsend('/api/assignments?id=' + a.id, 'DELETE'); toast(`Deleted. ${num(r.rows)} recent log${r.rows === 1 ? '' : 's'} released.`); D = G = null; refresh() } catch (x) { toast(x.message) }
  });
  $('#asimp').onclick = async () => { try { const r = await jsend('/api/assignments.csv', 'POST', { text: $('#ascsv').value }); $('#asmsg').textContent = `Imported ${r.added}.` + (r.errors.length ? ' Problems: ' + r.errors.join('; ') : ''); if (!r.errors.length) $('#ascsv').value = ''; refresh() } catch (x) { $('#asmsg').textContent = x.message } };
}

function renderStaff(B) {
  const S = STAFF || { staff: [], unverified: [], status: {} }, st = S.status || {}, q = STQ.toLowerCase();
  const rows = (S.staff || []).filter(s => (STSHOW === 'all' || (STSHOW === 'active') === s.active) && (!q || [s.user, s.display, s.dept, s.title, s.email].join(' ').toLowerCase().includes(q)));
  B.innerHTML = `<div class="card"><div class="ch"><h3>Staff</h3><span class="hint">${!st.enabled ? 'The staff list is off: Settings &gt; Staff directory.' : st.error ? `<span class="err">${esc(st.error)}</span>`
      : st.loaded ? `${num(st.active)} active, ${num(st.former)} former · ${num(st.computers)} domain computers${st.imported ? ' · read ' + ldt(st.imported) : ''}` : 'Waiting for staff.csv in ' + esc(st.path || '(no folder set)')}</span>
    ${st.enabled ? '<button type="button" id="stimp" style="margin-left:auto">Read the file now</button>' : ''}</div>
    <div class="dvfilter"><input id="stq" placeholder="Search name, account, department…" value="${esc(STQ)}"><div class="seg sm">${[['active', 'Active'], ['former', 'Former'], ['all', 'All']].map(([k, l]) => `<button type="button" data-st="${k}" class="${k === STSHOW ? 'on' : ''}">${l}</button>`).join('')}</div><span class="muted">${rows.length} shown</span></div>
    ${rows.length ? `<div class="tablewrap" style="max-height:520px"><table class="dvt"><thead><tr><th>Account</th><th>Name</th><th>Department</th><th>Status</th><th class="n">Devices</th><th>Last seen</th><th class="n">Events (30 days)</th><th></th></tr></thead><tbody>
    ${rows.map(s => `<tr><td><b>${esc(s.user)}</b></td><td>${esc(s.display || '')}<br><small class="muted">${esc(s.title || '')}</small></td><td>${esc(s.dept || '')}</td>
      <td>${s.active ? '<span class="pill ok">active</span>' : `<span class="pill bad">left${s.left && !String(s.left).startsWith('0001') ? ' ' + ldt(s.left).split(',')[0] : ''}</span>`}</td>
      <td class="n">${s.devices || ''}</td><td>${s.last_seen ? ago(new Date(s.last_seen) / 1000) : '<span class="muted">not seen</span>'}</td><td class="n">${num(s.events)}</td>
      <td class="acts"><button type="button" data-asfor="${esc(s.user)}">Assign a device</button><button type="button" data-k="user" data-v="${esc(s.user)}">Activity</button></td></tr>`).join('')}</tbody></table></div>` : '<p class="muted">Nobody matches.</p>'}</div>
    ${(S.unverified || []).length ? `<div class="card" style="margin-top:12px"><div class="ch"><h3>Usernames that are not staff</h3><span class="hint">Seen in the last 30 days but not in staff.csv: service accounts, guests, typos, or accounts from another domain. They are not counted as people.</span></div>
      <div class="chips2">${S.unverified.map(u => `<span class="chip2" data-k="user" data-v="${esc(u.user)}">${esc(u.user)} <small>${num(u.events)}</small></span>`).join('')}</div></div>` : ''}`;
  $('#stq').oninput = e => { STQ = e.target.value; const p = e.target.selectionStart; renderStaff(B); $('#stq').focus(); $('#stq').setSelectionRange(p, p) };
  B.querySelectorAll('[data-st]').forEach(b => b.onclick = () => { STSHOW = b.dataset.st; renderStaff(B) });
  B.querySelectorAll('[data-asfor]').forEach(b => b.onclick = () => assignDialog({ type: 'person', owner: b.dataset.asfor }));
  if ($('#stimp')) $('#stimp').onclick = async () => { try { await jsend('/api/staff', 'POST', {}); STAFF = null; toast('Staff list read.'); refresh() } catch (x) { toast(x.message) } };
}

function renderWarnings(w) {
  const B = $('#dvbody'), LBL = { former: 'Former staff', unknown_person: 'Not in the staff list', expired: 'Expired', overlap: 'Overlap', idle: 'No traffic', mac: 'Different device' };
  B.innerHTML = `<div class="card"><div class="ch"><h3>Warnings</h3><span class="hint">Assignments to review: people who left, overlaps, addresses now used by another device, entries with no traffic for 30 days.</span></div>
    ${w.length ? `<table><thead><tr><th>Device</th><th>Assigned to</th><th>Issue</th><th></th></tr></thead><tbody>${w.map(x => `<tr><td><b>${esc(x.value)}</b></td><td>${esc(x.owner)}</td>
      <td><span class="pill ${x.kind === 'former' || x.kind === 'mac' ? 'bad' : ''}">${LBL[x.kind] || x.kind}</span> ${esc(x.message)}</td><td class="acts"><button type="button" data-ed="${x.id}">Edit</button></td></tr>`).join('')}</tbody></table>`
      : '<p class="muted">Nothing to review.</p>'}</div>`;
  B.querySelectorAll('[data-ed]').forEach(b => b.onclick = () => assignDialog((ASG.assignments || []).find(a => a.id === +b.dataset.ed)));
}

function renderHistory(B) {
  const H = HIST || [];
  B.innerHTML = `<div class="card"><div class="ch"><h3>History</h3><span class="hint">Who added, changed or deleted an assignment. Last 300 changes.</span></div>
    ${H.length ? `<table><thead><tr><th>When</th><th>Who</th><th>What</th><th>Device</th><th>Type</th><th>Person or label</th></tr></thead><tbody>${H.map(h => `<tr><td>${ldt(h.at)}</td><td>${esc(h.by)}</td><td>${esc(h.action)}</td><td>${esc(h.value)}</td><td>${h.type ? tpill(h.type) : ''}</td><td>${esc(h.owner)}</td></tr>`).join('')}</tbody></table>`
      : '<p class="muted">No changes yet.</p>'}</div>`;
}

// ------------------------------------------------------------ assign dialog
function assignDialog(a = {}) {
  const d = document.createElement('div'); d.className = 'modal';
  const edit = !!a.id, ip = a.value && /^[0-9.]+$/.test(a.value) ? a.value : '';
  const quick = [ip && ['This address', ip], a.mac && ['This device (MAC)', a.mac], a.host && ['Host name', a.host.split('.')[0]], ip && ['Whole /24', ip.replace(/\.\d+$/, '.0/24')]].filter(Boolean);
  d.innerHTML = `<form class="card mbox wide2"><h2>${edit ? 'Edit assignment' : 'Assign a device'}</h2>
    <label>Device: IP address, subnet, MAC address or host name<input name="value" value="${esc(a.value || '')}" required placeholder="10.10.5.20, 10.20.1.0/24, 00:1a:2b:3c:4d:5e or HO-PC-031"></label>
    ${quick.length > 1 ? `<div class="qpick">${quick.map(([l, v]) => `<button type="button" data-v="${esc(v)}">${l}: <b>${esc(v)}</b></button>`).join('')}</div>` : ''}
    <div class="typegrid">${Object.entries(DTYPES).filter(([k]) => k !== 'unknown').map(([k, v]) => `<label class="tcard${(a.type || 'person') === k ? ' on' : ''}" style="--c:${v[1]}"><input type="radio" name="type" value="${k}"${(a.type || 'person') === k ? ' checked' : ''}>${v[0]}</label>`).join('')}</div>
    <label id="ownl">Person<input name="owner" list="dl-staff" value="${esc(a.owner || '')}" autocomplete="off" placeholder="start typing a name"></label><div id="ownhint" class="hint"></div>
    <div class="formgrid" style="margin:0"><label>Department<input name="dept" value="${esc(a.dept || '')}"></label><label>Until (optional)<input name="until" type="date" value="${a.until ? new Date(a.until).toISOString().slice(0, 10) : ''}"></label></div>
    <label>Note<input name="note" value="${esc(a.note || '')}" maxlength="200"></label>
    <label id="macl">Expected device MAC (optional: warns when another device takes this address)<input name="mac" value="${esc(a.mac && a.value !== a.mac ? a.mac : '')}"></label>
    <p class="hint">A <b>person</b> assignment puts the name on this device's logs when the firewall and NPS do not know the user (and on the last ${'' + (CFG && CFG.compress_after_days || 2)} days already stored). Other types only label the device.</p>
    <div class="actions"><span id="amsg" class="err"></span><span class="sep"></span><button type="button" id="acancel">Cancel</button><button class="primary">Save</button></div></form>`;
  document.body.appendChild(d); staffList();
  const f = d.querySelector('form'), syncType = () => {
    const t = f.type.value, person = t === 'person';
    d.querySelectorAll('.tcard').forEach(c => c.classList.toggle('on', c.querySelector('input').checked));
    $('#ownl').firstChild.textContent = person ? 'Person' : 'Label (e.g. File server, Reception PC)';
    f.owner.setAttribute('list', person ? 'dl-staff' : ''); f.owner.placeholder = person ? 'start typing a name' : 'what is this device?';
    const s = person && STAFFIDX && STAFFIDX.get(f.owner.value.trim().toLowerCase());
    $('#ownhint').innerHTML = !person ? '' : !STAFFIDX ? '' : s ? `${esc(s.display || '')}${s.dept ? ' · ' + esc(s.dept) : ''}${s.active ? '' : ' · <span class="err">has left</span>'}` : f.owner.value ? '<span class="err">Not in the staff list</span>' : '';
    if (s && (!f.dept.value || f.dept.dataset.auto)) { f.dept.value = s.dept || ''; f.dept.dataset.auto = '1' }
    if (!person && f.dept.dataset.auto) { f.dept.value = ''; delete f.dept.dataset.auto }
    $('#macl').hidden = !/^[0-9.]+$/.test(f.value.value.trim());
  };
  d.querySelectorAll('input[name=type]').forEach(r => r.onchange = syncType); f.owner.oninput = syncType; f.value.oninput = syncType;
  f.dept.oninput = () => delete f.dept.dataset.auto;
  d.querySelectorAll('.qpick button').forEach(b => b.onclick = () => { f.value.value = b.dataset.v; syncType() });
  syncType(); (a.value ? f.owner : f.value).focus();
  d.querySelector('#acancel').onclick = () => d.remove();
  d.addEventListener('keydown', e => { if (e.key === 'Escape') d.remove() });
  f.onsubmit = async e => {
    e.preventDefault();
    const body = { id: edit ? a.id : 0, value: f.value.value.trim(), type: f.type.value, owner: f.owner.value.trim(), dept: f.dept.value.trim(), note: f.note.value.trim(), mac: $('#macl').hidden ? '' : f.mac.value.trim() };
    if (f.until.value) body.until = new Date(f.until.value + 'T23:59:59').toISOString();
    try { const r = await jsend('/api/assignments', 'POST', body); d.remove(); toast(`Saved ${r.value}.${r.rows ? ` ${num(r.rows)} recent log${r.rows === 1 ? '' : 's'} now carry the name.` : ''}`); D = G = null; DVSEL.delete(body.value); refresh() }
    catch (x) { $('#amsg').textContent = x.message }
  };
}
$('#dvnew').onclick = () => assignDialog({});

function toast(t) {
  let el = $('#toast'); if (!el) { el = document.createElement('div'); el.id = 'toast'; document.body.appendChild(el) }
  el.textContent = t; el.className = 'show'; clearTimeout(el._t); el._t = setTimeout(() => el.className = '', 5000);
}

// ------------------------------------------------------------ alerts
let ALST = 'open', ALSEL = new Set(), AL = null, ALFW = ''; // v5.14: ALFW = one firewall
// v5.15: order of the list: newest first, most severe first, or grouped by firewall
let ALSORT = (() => { try { return localStorage.getItem('fortilog.alsort') || 'newest' } catch { return 'newest' } })();
const SEVR = { red: 2, amber: 1 };
function alertCard(a, canEdit) {
  const fws = a.fw ? a.fw.split(', ') : [];
  return `<div class="al ${a.severity} st-${a.status}">${canEdit ? `<input type="checkbox" data-alsel="${a.id}"${ALSEL.has(a.id) ? ' checked' : ''} aria-label="Select">` : '<span></span>'}
    <div><div class="alh"><span class="tag2 ${a.severity}">${a.severity === 'red' ? 'High' : 'Medium'}</span>${fws.length ? fws.map(f => `<span class="tagfw" title="Firewall">${esc(f)}</span>`).join('') : '<span class="tagfw none" title="Firewall not known for this alert">Firewall ?</span>'}<b>${esc(a.title)}</b>${a.via ? `<span class="pill via" title="How the firewall was reached">${esc(a.via)}</span>` : ''}<span class="pill">${esc(ALKIND[a.kind] || a.kind)}</span>${a.status !== 'open' ? `<span class="pill">${a.status === 'ack' ? 'acknowledged' : 'ignored'}${a.by ? ' by ' + esc(a.by) : ''}</span>` : ''}</div>
      <p>${esc(a.detail)}</p><small class="muted">First ${ldt(a.first)} · last ${ldt(a.last)}${a.count > 1 ? ' · count ' + num(a.count) : ''}${a.subject ? ` · <a href="#" data-alsub="${esc(a.subject)}" data-alfw="${esc(a.fw || '')}" data-alkind="${esc(a.kind)}">see activity</a>` : ''}</small></div>
    <div class="acts">${canEdit ? (a.status === 'open' ? `<button type="button" data-alset="ack" data-id="${a.id}">Acknowledge</button><button type="button" data-alset="ignored" data-id="${a.id}">Ignore</button>` : `<button type="button" data-alset="open" data-id="${a.id}">Reopen</button>`) : ''}</div></div>`;
}
const ALKIND = { signin_attack: 'Sign-in attack', bruteforce: 'Brute force', spray: 'Password spraying', success_after_fail: 'Sign-in after failures', config_offhours: 'Out-of-hours change',
  firewall_silent: 'Firewall silent', collector_silent: 'No logs', blocked_burst: 'Blocked burst', large_upload: 'Large upload', unknown_heavy: 'Unknown device' };
async function loadAlerts(signal) { AL = await api('/api/alerts?status=' + ALST + (ALFW ? '&fw=' + encodeURIComponent(ALFW) : ''), { signal }); renderAlerts(); badge(AL) }
function renderAlerts() {
  $('#alseg').innerHTML = [['open', 'Open'], ['ack', 'Acknowledged'], ['ignored', 'Ignored'], ['all', 'All']].map(([k, l]) => `<button type="button" data-al="${k}" class="${k === ALST ? 'on' : ''}">${l}</button>`).join('');
  const FL = AL.firewalls || [];
  $('#alfw').innerHTML = '<option value="">All firewalls</option>' + FL.map(f => `<option${f === ALFW ? ' selected' : ''}>${esc(f)}</option>`).join('');
  $('#alfw').hidden = !FL.length && !ALFW;
  $('#alinfo').textContent = AL.enabled ? `${num(AL.open)} open${AL.open_red ? `, ${num(AL.open_red)} red` : ''}` : 'Alerts are off (Settings > Alerts).';
  const L = AL.alerts || [], canEdit = ME && ME.role !== 'viewer';
  $('#alsort').innerHTML = [['newest', 'Newest first'], ['severity', 'Most severe'], ['firewall', 'By firewall']].map(([k, l]) => `<button type="button" data-als="${k}" class="${k === ALSORT ? 'on' : ''}">${l}</button>`).join('');
  const t = x => +new Date(x.last) || 0, L2 = [...L];
  if (ALSORT === 'severity') L2.sort((x, y) => (SEVR[y.severity] || 0) - (SEVR[x.severity] || 0) || t(y) - t(x));
  else L2.sort((x, y) => t(y) - t(x));
  let body = '';
  if (ALSORT === 'firewall') {
    const groups = new Map();
    // an alert seen on several firewalls is listed under each of them
    L2.forEach(x => (x.fw ? x.fw.split(', ') : ['Firewall not known']).forEach(k => { if (!groups.has(k)) groups.set(k, []); groups.get(k).push(x) }));
    body = [...groups.entries()].sort((x, y) => x[0] === 'Firewall not known' ? 1 : y[0] === 'Firewall not known' ? -1 : x[0].localeCompare(y[0]))
      .map(([fw, l]) => `<div class="algrp"><h3><span class="tagfw">${esc(fw)}</span> ${l.length} alert${l.length === 1 ? '' : 's'}${l.filter(x => x.status === 'open').length ? ` · ${l.filter(x => x.status === 'open').length} open` : ''}${l.some(x => x.severity === 'red' && x.status === 'open') ? ' · <span class="tag2 red">High</span>' : ''}</h3>${l.map(x => alertCard(x, canEdit)).join('')}</div>`).join('');
  } else body = L2.map(x => alertCard(x, canEdit)).join('');
  $('#albody').innerHTML = L.length ? `<div class="alist">${body}</div>`
    : `<div class="card"><p class="muted">${ALST === 'open' ? 'No open alerts.' : 'Nothing here.'}</p></div>`;
  const upd = () => { $('#alack').disabled = $('#align').disabled = !ALSEL.size };
  $$('#albody [data-alsel]').forEach(c => c.onchange = () => { c.checked ? ALSEL.add(+c.dataset.alsel) : ALSEL.delete(+c.dataset.alsel); upd() }); upd();
  $$('#albody [data-alset]').forEach(b => b.onclick = () => setAlerts([+b.dataset.id], b.dataset.alset));
  // v5.14: the Log explorer, filtered to the source (address or subnet) and the alert's firewall(s)
  $$('#albody [data-alsub]').forEach(x => x.onclick = e => {
    e.preventDefault(); const v = x.dataset.alsub, fw = x.dataset.alfw, k = x.dataset.alkind;
    F = { ...DEF, range: '24' };
    if (/^[0-9a-f.:]+(\/\d+)?$/i.test(v) && /[.:]/.test(v)) F.src = '=' + v; else F.user = '=' + v;
    if (fw) F.fw = fw.split(', ').map(f => '=' + f).join(', ');
    if (['signin_attack', 'bruteforce', 'spray', 'success_after_fail', 'config_offhours'].includes(k)) F.type = 'event';
    toInputs(); renderChips(); setView('logs');
  });
}
async function setAlerts(ids, status) { try { await jsend('/api/alerts', 'POST', { ids, status }); ALSEL.clear(); refresh() } catch (x) { toast(x.message) } }
$('#alseg').addEventListener('click', e => { const b = e.target.closest('[data-al]'); if (!b) return; ALST = b.dataset.al; ALSEL.clear(); refresh() });
$('#alsort').addEventListener('click', e => { const b = e.target.closest('[data-als]'); if (!b) return; ALSORT = b.dataset.als; try { localStorage.setItem('fortilog.alsort', ALSORT) } catch { } renderAlerts() });
$('#alfw').onchange = e => { ALFW = e.target.value; ALSEL.clear(); refresh() };
$('#alack').onclick = () => setAlerts([...ALSEL], 'ack'); $('#align').onclick = () => setAlerts([...ALSEL], 'ignored');
function badge(a) { const el = $('#alertcount'); if (!el || !a) return; el.hidden = !a.open; el.textContent = a.open > 99 ? '99+' : a.open; el.classList.toggle('red', !!a.open_red) }
async function pollAlerts() { try { const a = await api('/api/alerts?status=open'); badge(a) } catch { } }
setInterval(pollAlerts, 60000); setTimeout(pollAlerts, 2000);
