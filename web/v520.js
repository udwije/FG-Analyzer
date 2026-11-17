// v5.20: blocklist (FortiGate threat feed) from the alerts and in Settings; WAN links: firewall health below the charts.

// ------------------------------------------------------------ alerts: "Add to blocklist"
{
  const _card = alertCard;
  alertCard = function (a, canEdit) {
    let h = _card(a, canEdit);
    const c = a.block || [], ok = c.filter(x => !x.why), open = ok.filter(x => !x.listed);
    if (!c.length) return h;
    let tag = '';
    if (ok.length && !open.length) tag = '<span class="pill blk" title="Every source of this alert is on the blocklist">blocklisted</span>';
    else if (ok.length && open.length < ok.length) tag = '<span class="pill blk part" title="Some sources are on the blocklist">partly blocklisted</span>';
    const rep = Math.max(0, ...c.map(x => x.repeat_days || 0)); // v5.21
    if (rep > 1) tag += `<span class="pill rep" title="This source was in sign-in attack alerts on ${rep} days in the last 30">repeat attacker</span>`;
    if (tag) h = h.replace('<div class="alh">', '<div class="alh">' + tag);
    if (canEdit && open.length) h = h.replace('<div class="acts">', `<div class="acts"><button type="button" class="blkbtn" data-blk="${a.id}">Add to blocklist</button>`);
    return h;
  };
}
$('#albody').addEventListener('click', e => {
  const b = e.target.closest('[data-blk]'); if (!b) return;
  e.preventDefault(); e.stopPropagation();
  const a = (AL && AL.alerts || []).find(x => x.id === +b.dataset.blk);
  if (a) blockDialog(a);
}, true);

let BL = null;
async function blInfo() { BL = await api('/api/blocklist'); return BL }

async function blockDialog(a) {
  let info = BL;
  try { info = await blInfo() } catch { }
  const c = a.block || [], srcs = c.filter(x => !x.group), grp = c.find(x => x.group && !x.why && !x.listed);
  const useGroup = grp && srcs.filter(x => !x.why).length > 1; // several addresses of one /24: offer the /24 first
  const days = info ? info.default_days : 30;
  const d = document.createElement('div'); d.className = 'modal';
  const row = x => {
    const dis = x.why || x.listed, on = !dis && ((x.group ? useGroup : !useGroup) || x.repeat_days > 1); // v5.21: repeat attackers pre-selected
    return `<label class="blrow${dis ? ' dis' : ''}"><input type="checkbox" value="${esc(x.entry)}"${on ? ' checked' : ''}${dis ? ' disabled' : ''}>
      <span class="mono">${esc(x.entry)}</span>${x.group ? '<small>whole subnet the alert groups</small>' : ''}${x.repeat_days > 1 ? `<span class="pill rep">repeat attacker · ${x.repeat_days} days in 30</span>` : ''}
      ${x.why ? `<small class="err">${esc(x.why)}</small>` : x.listed ? `<small class="okc">already listed (${esc(x.listed)})</small>` : ''}</label>`;
  };
  d.innerHTML = `<form class="mbox wide2 card"><h2>Add to the blocklist</h2>
    <p class="hint">${esc(a.title)}</p>
    ${info && !info.enabled ? '<div class="notice">The blocklist feed is off: entries are saved, but the FortiGates only see them once it is turned on in Settings &gt; Blocklist.</div>' : ''}
    <div class="bllist">${c.map(row).join('')}</div>
    <div class="formgrid"><label>Keep for<select name="days">${[[7, '7 days'], [30, '30 days'], [90, '90 days'], [365, '1 year'], [0, 'Until removed']].map(([v, l]) =>
      `<option value="${v}"${v === days ? ' selected' : ''}>${l}</option>`).join('')}</select></label>
      <label>Note<input name="note" maxlength="300" value="${esc(a.title)}"></label></div>
    <p class="hint">The FortiGates read the list as an external threat feed and drop these addresses in the policies that use it. Internal addresses, your firewalls and the addresses in Never block are never listed. The alert is acknowledged.</p>
    <p id="blmsg" class="err"></p>
    <div class="actions"><button type="button" id="blcancel">Cancel</button><button type="submit" class="primary">Add to blocklist</button></div></form>`;
  document.body.appendChild(d);
  d.querySelector('#blcancel').onclick = () => d.remove();
  d.addEventListener('keydown', e => { if (e.key === 'Escape') d.remove() });
  const f = d.querySelector('form');
  f.onsubmit = async e => {
    e.preventDefault();
    const entries = [...f.querySelectorAll('input[type=checkbox]:checked')].map(x => x.value);
    if (!entries.length) { $('#blmsg').textContent = 'Choose at least one address.'; return }
    try {
      const r = await jsend('/api/blocklist', 'POST', { entries, note: f.note.value, alert_id: a.id, days: +f.days.value });
      d.remove();
      toast(`Added to the blocklist: ${r.added.join(', ')}.${r.problems.length ? ' Not added: ' + r.problems.join('; ') : ''}${r.enabled ? '' : ' The feed is off (Settings > Blocklist).'}`);
      refresh();
    } catch (x) { $('#blmsg').textContent = x.message }
  };
}

// ------------------------------------------------------------ Settings > Blocklist
function blocklistPanel() {
  const w = document.createElement('div'); w.id = 'blpanel';
  w.innerHTML = '<p class="muted">Loading…</p>';
  return w;
}
async function blLoad() {
  const w = $('#blpanel'); if (!w) return;
  let B;
  try { B = await blInfo() } catch (x) { w.innerHTML = `<p class="err">${esc(x.message)}</p>`; return }
  const ed = B.can_edit, now = Date.now();
  const lf = B.last_fetch ? `Last read by ${esc(B.last_fetch.from)} ${ago(new Date(B.last_fetch.at) / 1000)}.` : 'Not read by a FortiGate since the service started.';
  const url = B.url || '(turn the feed on to create its address)';
  w.innerHTML = `<div class="formgrid">
      <label class="check"><input type="checkbox" id="bl-on"${B.enabled ? ' checked' : ''}${ed ? '' : ' disabled'}>Publish the blocklist for the FortiGates</label>
      <label>New entries are kept for<select id="bl-days"${ed ? '' : ' disabled'}>${[[7, '7 days'], [30, '30 days'], [90, '90 days'], [365, '1 year'], [0, 'Until removed']].map(([v, l]) =>
        `<option value="${v}"${v === B.default_days ? ' selected' : ''}>${l}</option>`).join('')}</select></label></div>
    <label>Never block (one address or subnet per line: partners, your own public ranges, monitoring services)
      <textarea id="bl-never" rows="3"${ed ? '' : ' disabled'}>${esc((B.never_block || []).join('\n'))}</textarea></label>
    <p class="hint">Internal addresses (private ranges and Settings &gt; Internal networks), the firewalls' own addresses and subnets larger than /16 are refused anyway.</p>
    <div class="cardsave inline">${ed ? '<button type="button" id="bl-save" class="primary">Save blocklist settings</button><button type="button" id="bl-token">New feed address</button>' : '<span class="muted">Only an admin can change these settings.</span>'}<span id="bl-msg" class="cmsg"></span></div>
    <h3 class="formsub">Feed address</h3>
    <div class="blurl"><code id="bl-url">${esc(url)}</code>${B.url ? '<button type="button" id="bl-copy">Copy</button>' : ''}</div>
    <p class="hint">${B.live} address${B.live === 1 ? '' : 'es'} in the feed now. ${lf} Treat the address like a password: anyone who has it can read the list. "New feed address" replaces it (update the FortiGates afterwards).</p>
    <details class="blhow"><summary>FortiGate set-up</summary><pre>config system external-resource
    edit "LogSikka-Blocklist"
        set type address
        set resource "${esc(B.url || 'https://<logsikka>:9876/feed/<token>/blocklist.txt')}"
        set refresh-rate 5
    next
end</pre>
      <p class="hint">With LogSikka's self-signed certificate the FortiGate must be told not to verify it (on FortiOS versions that have it: <code>set server-identity-check none</code>), or install a certificate from your CA (Settings &gt; System health). Then use <b>LogSikka-Blocklist</b> as the source address of a deny policy above your internet and VPN policies (and in a local-in policy for the admin page, where your FortiOS version accepts external addresses there). The FortiGate must reach this server on the dashboard port.</p></details>
    <h3 class="formsub">Entries</h3>
    ${(B.entries || []).length ? `<div class="scrollbox"><table><thead><tr><th>Address or subnet</th><th>Note</th><th>Added</th><th>Expires</th><th class="n" title="Connections from this entry the firewalls blocked since it was added (needs logging on the deny policy)">Blocked since added</th><th></th></tr></thead><tbody>${B.entries.map(x => `<tr class="${x.live ? '' : 'blexp'}">
      <td class="mono"><b>${esc(x.entry)}</b></td><td>${esc(x.note || '')}${x.alert_id ? ` <small class="muted">alert ${x.alert_id}</small>` : ''}</td>
      <td>${ldt(x.added)}${x.by ? ' · ' + esc(x.by) : ''}</td><td>${x.expires ? (x.live ? ldt(x.expires) : 'expired ' + ldt(x.expires)) : 'never'}</td>
      <td class="n">${x.hits ? `<b>${num(x.hits)}</b><br><small class="muted">last ${ago(new Date(x.last_hit) / 1000)}</small>` : '<span class="muted" title="No blocked connection from it was logged since it was added">none yet</span>'}</td>
      <td class="acts">${ME && ME.role !== 'viewer' ? `<button type="button" data-blrm="${x.id}">Remove</button>` : ''}</td></tr>`).join('')}</tbody></table></div>` : '<p class="muted">The blocklist is empty. Add attackers from the Alerts tab, or below.</p>'}
    ${ME && ME.role !== 'viewer' ? `<div class="bladd"><input id="bl-new" placeholder="203.0.113.7, 198.51.100.0/24"><button type="button" id="bl-add">Add</button></div>` : ''}`;
  const msg = (t, cls) => { const m = $('#bl-msg'); if (m) { m.textContent = t; m.className = 'cmsg ' + (cls || '') } };
  const save = async newToken => {
    try {
      await jsend('/api/blocklist/settings', 'PUT', { enabled: $('#bl-on').checked, default_days: +$('#bl-days').value, never_block: lines($('#bl-never').value), new_token: newToken });
      await blLoad(); msg(newToken ? 'New feed address created: update the FortiGates.' : 'Saved.', 'okc');
    } catch (x) { msg(x.message, 'err') }
  };
  if ($('#bl-save')) $('#bl-save').onclick = () => save(false);
  if ($('#bl-token')) $('#bl-token').onclick = () => { if (confirm('Create a new feed address? The old one stops working, so every FortiGate must be updated.')) save(true) };
  if ($('#bl-copy')) $('#bl-copy').onclick = () => { try { navigator.clipboard.writeText(B.url); $('#bl-copy').textContent = 'Copied' } catch { } };
  w.querySelectorAll('[data-blrm]').forEach(b => b.onclick = async () => {
    const x = B.entries.find(y => y.id === +b.dataset.blrm);
    if (!confirm(`Remove ${x.entry} from the blocklist? The FortiGates allow it again at their next refresh.`)) return;
    try { await jsend('/api/blocklist?id=' + x.id, 'DELETE'); blLoad() } catch (e) { msg(e.message, 'err') }
  });
  if ($('#bl-add')) $('#bl-add').onclick = async () => {
    const entries = $('#bl-new').value.split(/[\s,;]+/).filter(Boolean);
    if (!entries.length) return;
    try {
      const r = await jsend('/api/blocklist', 'POST', { entries, note: 'added by hand' });
      await blLoad(); msg((r.added.length ? 'Added ' + r.added.join(', ') + '. ' : '') + (r.problems.length ? 'Not added: ' + r.problems.join('; ') : ''), r.problems.length ? 'err' : 'okc');
    } catch (x) { msg(x.message, 'err') }
  };
}

// ------------------------------------------------------------ WAN links: firewall health below the charts
const FGLAST = new Map();
const fgFull = fgExtra;
fgExtra = function (d) { // the tile keeps the compact CPU / memory / sessions line only
  FGLAST.set(d.name, d);
  const x = d.extra; if (!x) return '';
  const meter = (v, l) => v == null ? '' : `<span class="fgm"><small>${l}</small><i><em class="${v >= 85 ? 'r' : v >= 70 ? 'a' : ''}" style="width:${Math.min(100, v)}%"></em></i><b>${v}%</b></span>`;
  const sla = x.sla || [], dead = sla.filter(s => !s.alive).length;
  const sum = [sla.length ? (dead ? `<span class="err">${dead} SD-WAN member${dead === 1 ? '' : 's'} dead</span>` : `SD-WAN ${sla.length} checks ok`) : '',
    (x.vpn || []).length ? (x.vpn_down ? `<span class="err">${x.vpn_down} tunnel${x.vpn_down === 1 ? '' : 's'} down</span>` : `${x.vpn_up} tunnels up`) : ''].filter(Boolean).join(' · ');
  return (x.cpu != null || x.mem != null || x.sessions != null) ? `<div class="fgsys">${meter(x.cpu, 'CPU')}${meter(x.mem, 'Memory')}${x.sessions != null ? `<span class="fgm"><small>Sessions</small><b>${num(x.sessions)}</b></span>` : ''}${sum ? `<span class="fgsum">${sum}</span>` : ''}</div>` : '';
};
function fgHealthCard() {
  let el = $('#fghealth');
  const devs = [...FGLAST.values()].filter(d => d.extra && ((d.extra.sla || []).length || (d.extra.vpn || []).length));
  if (!devs.length) { if (el) el.remove(); return }
  if (!el) {
    el = document.createElement('div'); el.id = 'fghealth'; el.className = 'card';
    const diag = $('#wandiag');
    diag ? diag.before(el) : $('#wanbody').append(el);
  }
  const open = new Set([...el.querySelectorAll('details[open]')].map(x => x.dataset.k));
  el.innerHTML = `<div class="ch"><h3>SD-WAN health and IPsec tunnels</h3><span class="hint">From the FortiGate MIB, about once a minute. Problems first.</span></div>
    <div class="fghgrid">${devs.map(d => {
      const body = fgFull({ ...d, extra: { ...d.extra, cpu: null, mem: null, sessions: null } });
      return `<div class="fghdev"><h4>${esc(d.name)}</h4>${body}</div>`;
    }).join('')}</div>`;
  // keep the open / closed state of each table across refreshes
  el.querySelectorAll('.fghdev').forEach(dv => dv.querySelectorAll('details').forEach((x, i) => {
    x.dataset.k = dv.querySelector('h4').textContent + i;
    if (open.has(x.dataset.k)) x.open = true;
  }));
}
{
  const _rw = renderWAN;
  renderWAN = function () { FGLAST.clear(); _rw(); fgHealthCard() };
  const _wt = wanTile;
  let pend = null;
  wanTile = function (d) { const h = _wt(d); clearTimeout(pend); pend = setTimeout(fgHealthCard, 50); return h };
}

