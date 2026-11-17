// v5.17: themes, organised dashboards (collapsible groups), a settings page made of cards, the WAN links overhaul.

// ------------------------------------------------------------ themes
const THEMES = [['light', 'Light'], ['dark', 'Dark'], ['midnight', 'Midnight'], ['ocean', 'Ocean'], ['contrast', 'High contrast']];
const ACCENTS = [['teal', '#0e7490'], ['blue', '#2563eb'], ['violet', '#6d5bd0'], ['green', '#15803d'], ['amber', '#b45309'], ['rose', '#be185d']];
const THEME = (() => { try { return JSON.parse(localStorage.getItem('fortilog.theme') || '{}') } catch { return {} } })();
function applyTheme() {
  const r = document.documentElement;
  let t = THEME.theme || 'light';
  if (t === 'auto') t = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  r.dataset.theme = t;
  const a = ACCENTS.find(x => x[0] === THEME.accent);
  if (a) r.style.setProperty('--accent', a[1]); else r.style.removeProperty('--accent');
  r.dataset.density = THEME.density || 'normal';
}
applyTheme();
function themePanel() {
  const w = document.createElement('div'); w.className = 'tpanel';
  w.innerHTML = `<h4>Theme</h4><div class="tgrid">${[['auto', 'Follow the system'], ...THEMES].map(([k, l]) => `<button type="button" data-th="${k}" class="tsw tsw-${k}"><i></i>${l}</button>`).join('')}</div>
    <h4>Accent colour</h4><div class="agrid">${[['', 'Default'], ...ACCENTS].map(([k, c]) => `<button type="button" data-ac="${k}" title="${k || 'default'}" style="--c:${c || 'var(--accent0)'}"></button>`).join('')}</div>
    <h4>Density</h4><div class="seg sm">${[['normal', 'Normal'], ['compact', 'Compact'], ['large', 'Large (wall screen)']].map(([k, l]) => `<button type="button" data-dn="${k}">${l}</button>`).join('')}</div>
    <p class="hint" style="margin-top:12px">Kept in this browser only. Reports and PDFs always print light.</p>`;
  const mark = () => {
    w.querySelectorAll('[data-th]').forEach(b => b.classList.toggle('on', b.dataset.th === (THEME.theme || 'light')));
    w.querySelectorAll('[data-ac]').forEach(b => b.classList.toggle('on', b.dataset.ac === (THEME.accent || '')));
    w.querySelectorAll('[data-dn]').forEach(b => b.classList.toggle('on', b.dataset.dn === (THEME.density || 'normal')));
  };
  w.addEventListener('click', e => {
    const b = e.target.closest('button'); if (!b) return;
    if (b.dataset.th) THEME.theme = b.dataset.th;
    if (b.dataset.ac !== undefined) THEME.accent = b.dataset.ac;
    if (b.dataset.dn) THEME.density = b.dataset.dn;
    try { localStorage.setItem('fortilog.theme', JSON.stringify(THEME)) } catch { }
    applyTheme(); mark();
  });
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => { if (THEME.theme === 'auto') applyTheme() });
  mark();
  return w;
}

// ------------------------------------------------------------ v5.18: compact header (brand, tabs, three icon menus)
function compactHeader() {
  const top = $('.top'); if (!top || top.dataset.compact) return;
  top.dataset.compact = '1';
  const tabs = $('#tabs'), title = $('#title'), sub = $('#subtitle');
  const bar = document.createElement('div'); bar.className = 'hbar';
  bar.innerHTML = `<div class="brand" title="LogSikka: your network's security guard"><img class="logo" src="/favicon.svg" alt=""><span class="bt">Log<b>Sikka</b></span><span class="bver" id="bver"></span></div>`;
  bar.append(tabs);
  const st = tabs.querySelector('[data-view=settings]'); if (st) { st.hidden = true; st.classList.add('gearonly') }
  tabs.querySelectorAll('.tabsp').forEach(x => x.remove());
  const icons = document.createElement('div'); icons.className = 'hicons';
  const dd = (id, icon, label, html) => `<div class="hdd"><button type="button" class="hib" data-dd="${id}" title="${label}" aria-label="${label}" aria-haspopup="true">${icon}</button><div class="hmenu" id="${id}" hidden>${html}</div></div>`;
  const ic = {
    status: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" fill="currentColor"/></svg>',
    report: '<svg viewBox="0 0 24 24"><path d="M6 3h9l4 4v14H6z" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M9 12h7M9 16h7M9 8h4" stroke="currentColor" stroke-width="1.8"/></svg>',
    more: '<svg viewBox="0 0 24 24"><circle cx="5" cy="12" r="1.9" fill="currentColor"/><circle cx="12" cy="12" r="1.9" fill="currentColor"/><circle cx="19" cy="12" r="1.9" fill="currentColor"/></svg>',
    gear: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3.2" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M12 2.8v3M12 18.2v3M2.8 12h3M18.2 12h3M5.5 5.5l2.1 2.1M16.4 16.4l2.1 2.1M5.5 18.5l2.1-2.1M16.4 7.6l2.1-2.1" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    user: '<svg viewBox="0 0 24 24"><circle cx="12" cy="8.5" r="3.8" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M4.5 20c1.4-3.6 4.2-5.4 7.5-5.4s6.1 1.8 7.5 5.4" fill="none" stroke="currentColor" stroke-width="1.8"/></svg>'
  };
  icons.innerHTML = dd('m-status', ic.status, 'Collector status', '<div class="mh">Collector</div><div id="m-health"></div><div class="mrow" id="m-upd"></div>')
    + dd('m-report', ic.report, 'Reports and print', '<div class="mh">Reports</div><a class="mi" href="/exec.html" target="_blank">Executive summary</a><a class="mi" href="/ai-report.html" target="_blank">AI usage report</a><button type="button" class="mi" data-act="print">Print or save this page as PDF</button>')
    + dd('m-more', ic.more, 'Page options', '<div class="mh">This page</div><label class="mi chk" id="m-auto"></label><button type="button" class="mi" data-act="customise">Customise (hide or show panels)</button><button type="button" class="mi" data-act="refresh">Refresh now</button>')
    + `<div class="hdd"><button type="button" class="hib" data-act="settings" title="Settings" aria-label="Settings">${ic.gear}</button></div>`
    + dd('m-user', ic.user, 'Account', '<div class="mh" id="m-who"></div><button type="button" class="mi" data-act="pw">Change password</button><button type="button" class="mi" data-act="look">Appearance…</button><button type="button" class="mi" data-act="logout">Sign out</button>');
  bar.append(icons);
  top.prepend(bar);
  // the old controls stay (other scripts use them) but live hidden in the menus
  const health = $('#health'); $('#m-health').append(health);
  $('#m-upd').append($('#updated'));
  const auto = $('#auto'); $('#m-auto').append(auto, document.createTextNode(' Auto-refresh every minute'));
  const keep = document.createElement('div'); keep.hidden = true;
  keep.append($('#execlink'), $('#customise'), $('#print'), $('#pwbtn'), $('#logout'), $('#who'));
  document.body.append(keep);
  $('.top .trow').remove();
  const hdr = document.createElement('div'); hdr.className = 'pagehead'; hdr.append(title, sub); top.after(hdr);
  // status dot colour follows the badge
  const sync = () => { const b = icons.querySelector('[data-dd=m-status]'); b.className = 'hib ' + (health.classList.contains('ok') ? 'okdot' : 'warndot'); b.title = health.textContent };
  new MutationObserver(sync).observe(health, { attributes: true, childList: true, characterData: true, subtree: true }); sync();
  new MutationObserver(() => { $('#m-who').textContent = $('#who').textContent || 'Account' }).observe($('#who'), { childList: true, characterData: true, subtree: true });
  $('#m-who').textContent = $('#who').textContent || 'Account';
  icons.addEventListener('click', e => {
    e.stopPropagation();
    const t = e.target.closest('[data-dd]');
    if (t) { const m = $('#' + t.dataset.dd), was = m.hidden; $$('.hmenu').forEach(x => x.hidden = true); m.hidden = !was; return }
    const a = e.target.closest('[data-act]'); if (!a) return;
    $$('.hmenu').forEach(x => x.hidden = true);
    ({ settings: () => setView('settings'), print: () => $('#print').click(), customise: () => $('#customise').click(), refresh: () => refresh(), pw: () => $('#pwbtn').click(), logout: () => $('#logout').click(),
       look: () => { setView('settings'); setTimeout(() => setupSettings.show && setupSettings.show('set-appearance'), 50) } })[a.dataset.act]();
  });
  document.addEventListener('click', () => $$('.hmenu').forEach(x => x.hidden = true));
  const gear = icons.querySelector('[data-act=settings]').parentElement, role = () => { gear.hidden = !!(typeof ME !== 'undefined' && ME && ME.role !== 'admin') };
  [500, 1500, 4000].forEach(t => setTimeout(role, t));
}

// ------------------------------------------------------------ collapsible groups (All logs) and the section bar
const GRPS = new Set((() => { try { return JSON.parse(localStorage.getItem('fortilog.grps') || '[]') } catch { return [] } })()); // collapsed
function setupGroups() {
  const sec = $('#global');
  $$('#global .grp').forEach(g => {
    const k = g.dataset.grp, h = g.querySelector('.grph');
    const set = c => { g.classList.toggle('closed', c); h.setAttribute('aria-expanded', String(!c)) };
    set(GRPS.has(k));
    h.onclick = () => { const c = !g.classList.contains('closed'); c ? GRPS.add(k) : GRPS.delete(k); try { localStorage.setItem('fortilog.grps', JSON.stringify([...GRPS])) } catch { } set(c); navMark() };
  });
  const nav = $('#gsecnav');
  const items = () => $$('#global .grp').filter(g => !g.hidden);
  const draw = () => {
    nav.innerHTML = items().map(g => `<a href="#" data-goto="${g.dataset.grp}">${esc(g.querySelector('.gt').textContent)}</a>`).join('') +
      '<span class="sep"></span><button type="button" data-all="open">Expand all</button><button type="button" data-all="close">Collapse all</button>';
    navMark();
  };
  nav.onclick = e => {
    const a = e.target.closest('[data-goto]'), b = e.target.closest('[data-all]');
    if (a) {
      e.preventDefault();
      const g = sec.querySelector(`.grp[data-grp="${a.dataset.goto}"]`);
      if (g.classList.contains('closed')) g.querySelector('.grph').click();
      g.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    if (b) {
      items().forEach(g => { const c = b.dataset.all === 'close'; if (g.classList.contains('closed') !== c) g.querySelector('.grph').click() });
    }
  };
  setupGroups.draw = draw;
  draw();
}
function navMark() { $$('#gsecnav [data-goto]').forEach(a => { const g = $(`#global .grp[data-grp="${a.dataset.goto}"]`); a.classList.toggle('closed', !!g && g.classList.contains('closed')) }) }
{
  const _ra = renderAdvanced;
  renderAdvanced = function (X) {
    _ra(X);
    const adv = view === 'advanced';
    $('#gadvgrp').hidden = !adv;
    $('#gadvrow').hidden = !adv;
    if (setupGroups.draw) setupGroups.draw();
  };
}

// ------------------------------------------------------------ settings: cards, section list, sticky save bar
function setupSettings() {
  const form = $('#config'); if (!form || form.dataset.cards) return;
  form.dataset.cards = '1';
  const kids = [...form.children], cards = [];
  let cur = null;
  const tail = $('#testdb').parentElement, msgEl = $('#message');
  kids.forEach(el => {
    if (el.tagName === 'H2') {
      cur = document.createElement('section'); cur.className = 'scard';
      cur.id = 'set-' + el.textContent.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
      cur.innerHTML = `<div class="sch"><h2>${esc(el.textContent)}</h2><span class="ss" data-sum></span></div><div class="scb"></div>`;
      form.insertBefore(cur, el); el.remove(); cards.push(cur); return;
    }
    if (el === tail || el === msgEl) return;
    if (cur) cur.querySelector('.scb').append(el);
  });
  // v5.18: every section has its own Save (the whole configuration is saved; the button sits where you are working)
  cards.forEach(c => {
    const row = document.createElement('div'); row.className = 'cardsave';
    row.innerHTML = '<span class="cmsg" aria-live="polite"></span><span class="sep"></span><button type="submit" class="primary">Save</button>';
    if (c.id === 'set-postgresql') row.insertBefore($('#testdb'), row.querySelector('button'));
    c.append(row);
  });
  tail.remove(); msgEl.hidden = true; form.append(msgEl);
  form.addEventListener('submit', () => { const c = cards.find(x => !x.hidden); if (c) { c.querySelector('.cmsg').textContent = 'Saving…'; c.querySelector('.cmsg').className = 'cmsg' } }, true);
  new MutationObserver(() => { const c = [...cards, ...extra].find(x => !x.hidden), m = c && c.querySelector('.cmsg'); if (m && msgEl.textContent) { m.textContent = msgEl.textContent; m.className = 'cmsg ' + (/fail|error|invalid|enter |needs|must|not /i.test(msgEl.textContent) ? 'err' : 'okc') } })
    .observe(msgEl, { childList: true, characterData: true, subtree: true });
  form.addEventListener('input', e => { const c = e.target.closest('.scard'); if (c) { const m = c.querySelector('.cmsg'); m.textContent = 'Unsaved changes'; m.className = 'cmsg warnc' } });
  // layout: section list on the left, ONE section on the right
  const sec = $('#settings'), wrap = document.createElement('div'); wrap.className = 'setlayout';
  const side = document.createElement('aside'); side.className = 'setnav card';
  const main = document.createElement('div'); main.className = 'setmain';
  sec.prepend(wrap); wrap.append(side, main);
  const mk = (id, title, sub, node) => { const c = document.createElement('section'); c.className = 'scard'; c.id = id;
    c.innerHTML = `<div class="sch"><h2>${title}</h2><span class="ss">${sub}</span></div><div class="scb"></div>`; if (node) c.querySelector('.scb').append(node); return c };
  const health = $('#syshealth'); health.classList.remove('card');
  const hcard = mk('set-system-health', 'System health', 'database, disk, background work, certificate', health);
  const look = mk('set-appearance', 'Appearance', 'theme, accent colour and density, for this browser', themePanel());
  const acard = mk('set-accounts', 'Accounts and audit log', 'who can sign in, and what they did', $('#acct'));
  const bcard = mk('set-blocklist', 'Blocklist (threat feed)', 'attackers the FortiGates drop, from the alerts', blocklistPanel()); // v5.20
  const extra = [hcard, look, acard, bcard];
  main.append(hcard, look, form, bcard, acard);
  const groups = [['Overview', [hcard]], ['Collection', cards.filter(c => /syslog|firewalls|internal|nps|staff|wan/.test(c.id))],
    ['Detection and reports', [...cards.filter(c => /ai-detection|alerts|executive/.test(c.id)), bcard]], ['System', [...cards.filter(c => /postgresql|storage|dashboard/.test(c.id)), acard, look]]];
  const placed = new Set(groups.flatMap(g => g[1])); cards.forEach(c => { if (!placed.has(c)) groups[3][1].push(c) });
  const all = groups.flatMap(g => g[1]);
  side.innerHTML = `<input type="search" id="setq" placeholder="Find a setting…" aria-label="Find a setting">${groups.map(([g, l]) => `<h5>${g}</h5><nav>${l.map(c => `<a href="#" data-card="${c.id}">${esc(c.querySelector('h2').textContent)}</a>`).join('')}</nav>`).join('')}`;
  const show = id => {
    if (!all.some(c => c.id === id)) id = all[0].id;
    all.forEach(c => c.hidden = c.id !== id);
    form.hidden = !cards.some(c => c.id === id);
    $$('.setnav [data-card]').forEach(a => a.classList.toggle('on', a.dataset.card === id));
    try { localStorage.setItem('fortilog.setcard', id) } catch { }
    main.scrollTop = 0; window.scrollTo({ top: 0 });
    if (id === 'set-blocklist' && typeof blLoad === 'function') blLoad(); // v5.20
  };
  side.onclick = e => { const a = e.target.closest('[data-card]'); if (a) { e.preventDefault(); show(a.dataset.card) } };
  $('#setq').oninput = e => {
    const q = e.target.value.trim().toLowerCase();
    let first = null;
    all.forEach(c => {
      const hit = !q || c.textContent.toLowerCase().includes(q) || [...c.querySelectorAll('input,textarea,select')].some(x => (x.name || '').toLowerCase().includes(q));
      $(`.setnav [data-card="${c.id}"]`).hidden = !hit; if (hit && !first) first = c.id;
    });
    if (q && first) show(first);
  };
  setupSettings.show = show;
  show((() => { try { return localStorage.getItem('fortilog.setcard') } catch { return '' } })() || 'set-system-health');
}
function settingsSummaries() {
  const c = CFG || {}, f = $('#config').elements, set = (id, t) => { const el = $('#' + id + ' [data-sum]'); if (el) el.textContent = t };
  set('set-syslog-listener', `${c.listen_address || ''}${c.tcp_enabled ? ' · TCP' : ''}${c.udp_enabled ? ' · UDP' : ''}`);
  set('set-firewalls', `${(c.firewalls || []).length} firewall${(c.firewalls || []).length === 1 ? '' : 's'}`);
  set('set-internal-networks', `${(c.internal_networks || []).length} extra ranges · ${(c.infra_networks || []).length} network devices · ${(c.tunnel_interfaces || []).length} tunnels`);
  set('set-ai-detection', `${(c.ai_rules || []).length} AI tools`);
  set('set-nps-user-mapping-wireless', (c.nps || {}).enabled ? 'on' : 'off');
  set('set-postgresql', `${(c.database || {}).host || ''}:${(c.database || {}).port || ''} / ${(c.database || {}).name || ''}`);
  set('set-storage', `keep ${c.retention_days} days · compress after ${c.compress_after_days} days`);
  set('set-staff-directory', (c.directory || {}).enabled ? 'on' : 'off');
  set('set-alerts', (c.alerts || {}).enabled ? 'on' : 'off');
  set('set-executive-summary', (c.exec || {}).org_name || '');
  const w = c.wan || {};
  set('set-wan-links-snmpv3', w.enabled ? `on · ${(w.devices || []).length} firewall${(w.devices || []).length === 1 ? '' : 's'} · ${(w.devices || []).reduce((a, d) => a + (d.interfaces || []).length, 0)} links` : 'off');
  set('set-dashboard-access', `${c.web_listen_address || ''}${c.web_tls ? ' · HTTPS' : ''}`);
}
{
  const _lc = loadConfig;
  loadConfig = async function () { setupSettings(); await _lc(); settingsSummaries(); $$('.scard .cmsg').forEach(m => { if (/Unsaved|Saving/.test(m.textContent)) { m.textContent = '' } }) };
}

// ------------------------------------------------------------ WAN settings: passphrases survive every redraw, test button
wanDevHTML = function (d, i) {
  const sel = (n, list, v) => `<select data-f="${n}">${list.map(x => `<option${x === v ? ' selected' : ''}>${x}</option>`).join('')}</select>`;
  // v5.19: say whether a passphrase is saved on the server (they are never sent to the browser)
  const ph = set => set ? 'saved: leave empty to keep' : 'required: none saved';
  const tag = set => set ? '<span class="pill ok">saved</span>' : '<span class="pill bad">not saved</span>';
  return `<fieldset class="wandev" data-i="${i}"><legend>${esc(d.name || 'Firewall ' + (i + 1))}</legend><div class="formgrid three">
    <label>Name<input data-f="name" value="${esc(d.name || '')}" placeholder="HO-FW"></label><label>Address<input data-f="host" value="${esc(d.host || '')}" placeholder="10.0.0.1"></label>
    <label>SNMP port<input data-f="port" type="number" value="${d.port || 161}"></label><label>SNMPv3 username<input data-f="username" value="${esc(d.username || '')}" placeholder="fgt-monitor"></label>
    <label>Security level${sel('security_level', ['authPriv', 'authNoPriv'], d.security_level || 'authPriv')}</label><label>Authentication${sel('auth_protocol', ['SHA256', 'SHA512', 'SHA1', 'MD5'], d.auth_protocol || 'SHA256')}</label>
    <label>Privacy${sel('priv_protocol', ['AES128', 'AES256'], d.priv_protocol || 'AES128')}</label>
    <label>Auth passphrase ${tag(d.auth_set)}<input data-f="auth_pass" type="password" autocomplete="new-password" value="${esc(d.auth_pass || '')}" placeholder="${ph(d.auth_set)}"></label>
    <label>Priv passphrase ${(d.security_level || 'authPriv') === 'authPriv' ? tag(d.priv_set) : ''}<input data-f="priv_pass" type="password" autocomplete="new-password" value="${esc(d.priv_pass || '')}" placeholder="${(d.security_level || 'authPriv') === 'authPriv' ? ph(d.priv_set) : 'not used (authNoPriv)'}"></label></div>
    <table class="wanif"><thead><tr><th>Interface</th><th>Label on the dashboard</th><th>Download Mbps</th><th>Upload Mbps</th><th></th></tr></thead><tbody>${(d.interfaces || []).map((f, j) => `<tr data-j="${j}">
      <td><input data-g="name" value="${esc(f.name)}"></td><td><input data-g="label" value="${esc(f.label || '')}" placeholder="e.g. SLT 100M ILL"></td><td><input data-g="down_mbps" type="number" value="${f.down_mbps || ''}"></td><td><input data-g="up_mbps" type="number" value="${f.up_mbps || ''}"></td>
      <td><button type="button" data-rmif="${j}">Remove</button></td></tr>`).join('')}</tbody></table>
    <div class="actions left"><button type="button" data-test="${i}">Test connection</button><button type="button" data-find="${i}">Find interfaces</button><button type="button" data-addif="${i}">+ Interface by name</button><span class="sep"></span><button type="button" data-rmdev="${i}">Remove this firewall</button></div>
    <div class="wanfound" id="wanfound${i}"></div></fieldset>`;
};
{
  const _rd = readWANDevs;
  readWANDevs = function () {
    const l = _rd();
    $$('#wandevs .wandev').forEach((fs, i) => { const o = (WANDEVS || [])[+fs.dataset.i] || {}; if (l[i]) { l[i].auth_set = !!o.auth_set; l[i].priv_set = !!o.priv_set } });
    return l;
  };
}
$('#wandevs').addEventListener('click', async e => {
  const b = e.target.closest('[data-test]'); if (!b) return;
  const i = +b.dataset.test, d = readWANDevs()[i], el = $('#wanfound' + i);
  el.innerHTML = '<p class="muted">Testing…</p>';
  try { const r = await jsend('/api/wan/discover', 'POST', d); el.innerHTML = `<p class="okc">Connected to <b>${esc(r.sys_name)}</b>: ${r.interfaces.length} interfaces. Remember to Save.</p>` }
  catch (x) { el.innerHTML = `<p class="err">${esc(x.message)}</p>` }
}, true);

// ------------------------------------------------------------ WAN links: firewall tiles, live charts, data usage
const capOf = (l, dir) => {
  const c = (dir === 'down' ? l.down_mbps : l.up_mbps || l.down_mbps) * 1e6;
  if (c) return c;
  const lv = ((WAN && WAN.status || []).find(d => d.name === l.dev) || {}).live || {}, x = lv[l.iface] || {}; // v5.19: FortiGate estimate
  return ((dir === 'down' ? x.est_down_kbps : x.est_up_kbps) || 0) * 1e3;
};
const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
function utilBar(v, cap, label) {
  const p = cap ? Math.min(100, 100 * v / cap) : 0, cls = p >= 80 ? 'r' : p >= 60 ? 'a' : '';
  return `<div class="ubar"><span>${label}</span><i class="${cls}"><em style="width:${p.toFixed(1)}%"></em></i><b>${bps(v)}</b><small>${cap ? Math.round(p) + '%' : ''}</small></div>`;
}
// line chart: series [{name, color, pts: [[t, v]]}], optional capacity line, y in bits per second
function lineChart(el, series, cap, h = 190, opts = {}) {
  if (!el) return;
  const W = Math.max(320, Math.round(el.clientWidth) || 900), H = h, L = 84, R = 10, T = 10, B = 24, pw = W - L - R, ph = H - T - B, NT = W < 520 ? 3 : W < 800 ? 4 : 6;
  const all = series.flatMap(s => s.pts);
  if (!all.length) { el.innerHTML = '<p class="muted">No samples yet.</p>'; return }
  const t0 = opts.t0 || Math.min(...all.map(p => p[0])), t1 = opts.t1 || Math.max(...all.map(p => p[0])), span = Math.max(1, t1 - t0);
  const mx = Math.max(1, cap || 0, ...all.map(p => p[1])) * 1.05;
  const X = t => L + (t - t0) / span * pw, Y = v => T + ph - v / mx * ph;
  const lab = s => { const d = new Date(s * 1000); return span > 36 * 3600 ? d.toLocaleDateString([], { month: 'short', day: 'numeric' }) : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) };
  let g = '';
  [0, .25, .5, .75, 1].forEach(f => { const y = T + ph - f * ph; g += `<line x1="${L}" x2="${W - R}" y1="${y}" y2="${y}" class="grid"/><text x="${L - 6}" y="${y + 4}" text-anchor="end">${bps(mx * f)}</text>` });
  for (let i = 0; i <= NT; i++) { const t = t0 + i * span / NT; g += `<text x="${X(t)}" y="${H - 6}" text-anchor="${i === 0 ? 'start' : i === NT ? 'end' : 'middle'}">${lab(t)}</text>` }
  if (cap) g += `<line x1="${L}" x2="${W - R}" y1="${Y(cap)}" y2="${Y(cap)}" class="capl"/><text x="${W - R - 4}" y="${Y(cap) - 4}" text-anchor="end" class="capt">capacity ${bps(cap)}</text>`;
  let p = '';
  series.forEach(s => {
    if (!s.pts.length) return;
    const pts = s.pts.map(q => `${X(q[0]).toFixed(1)},${Y(q[1]).toFixed(1)}`).join(' ');
    if (s.fill) p += `<polygon points="${X(s.pts[0][0]).toFixed(1)},${T + ph} ${pts} ${X(s.pts[s.pts.length - 1][0]).toFixed(1)},${T + ph}" fill="${s.color}" opacity=".14"/>`;
    p += `<polyline points="${pts}" fill="none" stroke="${s.color}" stroke-width="2" stroke-linejoin="round"/>`;
  });
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:${H}px">${g}${p}<line class="hov" x1="0" x2="0" y1="${T}" y2="${T + ph}" hidden/><rect x="${L}" y="${T}" width="${pw}" height="${ph}" fill="transparent" class="ov"/></svg><div class="tip2" hidden></div>`;
  const svg = el.firstChild, tip = el.querySelector('.tip2'), hov = svg.querySelector('.hov');
  svg.querySelector('.ov').onmousemove = e => {
    const r = svg.getBoundingClientRect(), t = t0 + ((e.clientX - r.left) / r.width * W - L) / pw * span;
    const near = series.map(s => { let b = null; s.pts.forEach(q => { if (!b || Math.abs(q[0] - t) < Math.abs(b[0] - t)) b = q }); return [s, b] }).filter(x => x[1]);
    if (!near.length) return;
    const x = X(near[0][1][0]); hov.setAttribute('x1', x); hov.setAttribute('x2', x); hov.hidden = false;
    tip.hidden = false; tip.style.left = Math.min(e.clientX - el.getBoundingClientRect().left + 12, el.clientWidth - 200) + 'px';
    tip.innerHTML = `<b>${new Date(near[0][1][0] * 1000).toLocaleString()}</b>` + near.map(([s, q]) => `<br><span style="color:${s.color}">●</span> ${esc(s.name)}: ${bps(q[1])}${cap ? ` (${Math.round(100 * q[1] / cap)}%)` : ''}`).join('');
  };
  svg.querySelector('.ov').onmouseleave = () => { tip.hidden = true; hov.hidden = true };
}
let WANLIVE = null, WANTIMER = null;
renderWAN = function () {
  const W = WAN, links = W.links || [], st = W.status || [];
  const U = W.usage || {};
  const sumU = k => links.reduce((a, l) => a + ((U[l.dev + '|' + l.iface] || {})[k] || 0), 0);
  renderPeriod({ from: W.from, to: W.to }, [[num(links.length), 'Circuits'], [W.enabled ? W.poll_seconds + ' s' : 'off', 'Polling'],
    [bytes(sumU('down')), 'Downloaded'], [bytes(sumU('up')), 'Uploaded']]);
  if (!W.enabled) { $('#wanstatus').innerHTML = `<div class="card notice">WAN polling is off. Add the firewalls and their internet interfaces in <a href="#" data-goview="settings">Settings &gt; WAN links</a>.</div>`; $('#wanbody').innerHTML = ''; }
  else $('#wanstatus').innerHTML = '';
  $$('#wanstatus [data-goview]').forEach(a => a.onclick = e => { e.preventDefault(); setView(a.dataset.goview) });
  if (!W.enabled) return;
  const byDev = new Map(); st.forEach(d => byDev.set(d.name, { ...d, links: [] }));
  links.forEach(l => { if (!byDev.has(l.dev)) byDev.set(l.dev, { name: l.dev, links: [] }); byDev.get(l.dev).links.push(l) });
  $('#wanbody').innerHTML = `<div class="wtiles" id="wtiles">${[...byDev.values()].map(d => wanTile(d)).join('')}</div>
    <div class="card"><div class="ch"><h3>Live</h3><span class="hint">Last 30 minutes at full resolution · refreshes every ${W.poll_seconds} s</span></div><div class="wlive">${links.map((l, i) => `<div><div class="wlh"><b>${esc(l.label)}</b> <small class="muted">${esc(l.dev)} · ${esc(l.iface)}</small></div><div class="chartwrap" id="wl${i}"></div></div>`).join('')}</div></div>
    <div class="card"><div class="ch"><h3>Data used</h3><span class="hint">Volume carried by each circuit, from the interface counters (what the ISP counts).</span></div>
      ${table([['Circuit'], ['Downloaded', 1], ['Uploaded', 1], ['Total', 1], ['Month to date ↓ / ↑', 1], ['Busiest day', 1]], links.map(l => {
        const u = U[l.dev + '|' + l.iface] || {}, days = u.days || [], top = days.reduce((a, d) => !a || d.down + d.up > a.down + a.up ? d : a, null);
        return `<tr><td><b>${esc(l.label)}</b> <small class="muted">${esc(l.dev)}</small></td><td class="n">${bytes(u.down)}</td><td class="n">${bytes(u.up)}</td><td class="n"><b>${bytes((u.down || 0) + (u.up || 0))}</b></td>
          <td class="n">${bytes(u.month_down)} / ${bytes(u.month_up)}</td><td class="n">${top ? new Date(top.day).toLocaleDateString([], { day: 'numeric', month: 'short' }) + ' · ' + bytes(top.down + top.up) : '–'}</td></tr>`;
      }), 'No circuits.')}
      <div class="wdays">${links.map((l, i) => `<div><div class="wlh"><b>${esc(l.label)}</b> <small class="muted">per day</small></div><div class="chartwrap" id="wu${i}"></div></div>`).join('')}</div></div>
    <div class="card"><div class="ch"><h3>Period detail</h3><span class="hint">Average, 95th percentile (what the circuit carried 95% of the time), peak, and the share of the time above 80% of capacity.</span></div>
      ${table([['Circuit'], ['Capacity'], ['Average ↓ / ↑', 1], ['95th pct ↓ / ↑', 1], ['Peak ↓ / ↑', 1], ['Busy ↓ / ↑', 1], ['Link down', 1]], links.map(l => {
        const n = +l.samples || 0;
        return `<tr><td><b>${esc(l.label)}</b></td><td>${mbps(l.down_mbps)}${l.up_mbps && l.up_mbps !== l.down_mbps ? ' / ' + mbps(l.up_mbps) : ''}</td>${!n ? '<td class="n" colspan="5"><span class="muted">no samples in this period</span></td>' : `
          <td class="n">${bps(l.avg_down)} / ${bps(l.avg_up)}</td><td class="n">${bps(l.p95_down)} / ${bps(l.p95_up)}</td><td class="n">${bps(l.peak_down)} / ${bps(l.peak_up)}</td>
          <td class="n">${pc(l.busy_down, n)}% / ${pc(l.busy_up, n)}%</td><td class="n">${l.down_samples ? pc(l.down_samples, n) + '%' : 'never'}</td>`}</tr>`;
      }))}
      <div class="wper">${links.map((l, i) => `<div><div class="wlh"><b>${esc(l.label)}</b> <small class="muted">${esc(l.dev)} · ${esc(l.iface)}</small></div><div class="chartwrap" id="wp${i}"></div>
        ${l.by_hour_down ? `<p class="hint" style="margin:8px 0 4px">Busiest hours (average download${l.down_mbps ? ', share of capacity' : ''})</p><div class="hrow">${l.by_hour_down.map((v, h) => { const p = l.down_mbps ? v / (l.down_mbps * 1e6) : v / Math.max(1, ...l.by_hour_down); return `<i title="${String(h).padStart(2, '0')}:00 ${bps(v)}" style="background:color-mix(in srgb,var(--accent) ${Math.round(8 + 85 * Math.min(1, p))}%,transparent)">${h % 3 ? '' : h}</i>` }).join('')}</div>` : ''}</div>`).join('')}</div></div>`;
  const cD = css('--down') || '#0e7490', cU = css('--up') || '#6d5bd0';
  links.forEach((l, i) => {
    lineChart($('#wp' + i), [{ name: 'Download', color: cD, fill: 1, pts: (l.series || []).map(r => [r[0], r[1]]) }, { name: 'Upload', color: cU, pts: (l.series || []).map(r => [r[0], r[2]]) }], capOf(l, 'down'), 200,
      { t0: new Date(W.from) / 1000, t1: Math.min(Date.now(), new Date(W.to)) / 1000 });
    const days = ((U[l.dev + '|' + l.iface] || {}).days || []).map(d => ({ t: d.day, down: d.down, up: d.up }));
    $('#wu' + i).innerHTML = days.length ? dayBars(days) : '<p class="muted">No data yet.</p>';
  });
  wanLiveTick(true);
  wanDiagCard(links.some(l => +l.samples > 0));
};
async function wanDiagCard(hasData) {
  let el = $('#wandiag');
  if (!el) { el = document.createElement('details'); el.id = 'wandiag'; el.className = 'card wdiag'; $('#wanbody').append(el) }
  el.open = !hasData;
  el.innerHTML = '<summary><b>Diagnostics</b> <span class="muted">why a circuit shows no data</span></summary><p class="muted">Checking…</p>';
  let D;
  try { D = await api('/api/wan?diag=1') } catch (x) { el.innerHTML = `<summary><b>Diagnostics</b></summary><p class="err">${esc(x.message)}</p>`; return }
  const ok = v => v === 'ok' ? '<span class="pill ok">ok</span>' : `<span class="pill bad">failed</span> <span class="err">${esc(v || '')}</span>`;
  const P = Object.fromEntries((D.poller || []).map(p => [p.name, p])), S = D.samples || [];
  const steps = (D.config || []).map(c => {
    const p = P[c.name] || {}, s = S.filter(x => x.dev === c.name), tips = [];
    if (!D.enabled) tips.push('Polling is switched off: Settings > WAN links > Poll the WAN links.');
    if (!c.auth_pass_set || (c.level === 'authPriv' && !c.priv_pass_set)) tips.push('A passphrase is not saved for this firewall: type both passphrases and press Save.');
    if (!c.interfaces.length) tips.push('No interfaces chosen.');
    if (D.enabled && !p.last_try) tips.push('The poller has not tried this firewall yet: wait one poll interval, or restart the service if this stays.');
    if (p.error) tips.push('Last poll failed: ' + p.error);
    if (p.last_ok && !p.stored) tips.push('Polls answer, but no sample stored yet (the first poll only sets the counters; data starts with the second).');
    if (p.stored && !s.length) tips.push('Samples were stored, but none in the last hour.');
    if (D.store_error) tips.push('Storing samples failed: ' + D.store_error);
    return `<tr><td><b>${esc(c.name)}</b><br><small>${esc(c.host)} · ${esc(c.user)} · ${esc(c.level)} ${esc(c.auth)}/${esc(c.priv)}</small></td>
      <td>${c.auth_pass_set ? '✓' : '<span class="err">missing</span>'} / ${c.priv_pass_set ? '✓' : (c.level === 'authPriv' ? '<span class="err">missing</span>' : '–')}</td>
      <td>${esc(c.interfaces.join(', ') || '–')}</td><td>${p.last_try ? ago(new Date(p.last_try) / 1000) : 'never'}</td><td>${p.last_ok ? ago(new Date(p.last_ok) / 1000) : '<span class="err">never</span>'}</td>
      <td class="n">${num(p.stored || 0)}</td><td>${s.map(x => `${esc(x.iface)}: ${num(x.last_hour)}`).join('<br>') || '<span class="err">none</span>'}</td>
      <td>${tips.length ? tips.map(t => `<div class="wtip">${esc(t)}</div>`).join('') : '<span class="okc">Looks fine</span>'}</td></tr>`;
  }).join('');
  el.innerHTML = `<summary><b>Diagnostics</b> <span class="muted">why a circuit shows no data</span></summary>
    <p class="hint">Polling ${D.enabled ? 'on, every ' + D.poll_seconds + ' s' : '<b>off</b>'}. Database queries: ${Object.entries(D.checks || {}).map(([k, v]) => `${k} ${ok(v)}`).join(' · ') || esc(D.database || '')}</p>
    <div class="scrollbox"><table><thead><tr><th>Firewall</th><th>Passphrases</th><th>Interfaces</th><th>Last try</th><th>Last answer</th><th class="n">Stored</th><th>Last hour</th><th>What to do</th></tr></thead><tbody>${steps || '<tr><td colspan="8" class="muted">No firewall configured.</td></tr>'}</tbody></table></div>
    <p class="hint">On the server: <code>journalctl -u logsikka | grep "WAN links"</code></p>`;
}
function dayBars(days) {
  const W = 640, H = 150, L = 60, B = 22, T = 8, pw = W - L - 6, ph = H - T - B, n = days.length, bw = pw / n, mx = Math.max(1, ...days.map(d => Math.max(d.down, d.up)));
  let g = ''; [0, .5, 1].forEach(f => { const y = T + ph - f * ph; g += `<line x1="${L}" x2="${W - 6}" y1="${y}" y2="${y}" class="grid"/><text x="${L - 6}" y="${y + 4}" text-anchor="end">${bytes(mx * f)}</text>` });
  const step = Math.max(1, Math.ceil(n / 8));
  days.forEach((d, i) => {
    const x = L + i * bw, w = Math.max(1, bw * .38);
    if (i % step === 0) g += `<text x="${x + bw / 2}" y="${H - 6}" text-anchor="middle">${new Date(d.t).toLocaleDateString([], { day: 'numeric', month: 'short' })}</text>`;
    g += `<rect x="${x + bw * .1}" y="${T + ph - d.down / mx * ph}" width="${w}" height="${d.down / mx * ph}" class="bd" rx="2"><title>${new Date(d.t).toLocaleDateString()} downloaded ${bytes(d.down)}</title></rect>`;
    g += `<rect x="${x + bw * .1 + w + 1}" y="${T + ph - d.up / mx * ph}" width="${w}" height="${d.up / mx * ph}" class="bu" rx="2"><title>${new Date(d.t).toLocaleDateString()} uploaded ${bytes(d.up)}</title></rect>`;
  });
  return `<svg viewBox="0 0 ${W} ${H}" style="width:100%">${g}</svg><div class="legend"><i class="bd"></i>Downloaded<i class="bu"></i>Uploaded</div>`;
}
function wanTile(d) {
  const live = d.live || {}, err = d.error;
  return `<article class="card wtile${err ? ' bad' : ''}" data-dev="${esc(d.name)}"><div class="wth"><i class="sd ${err ? 'bad' : d.last_ok ? 'ok' : ''}"></i><b>${esc(d.name)}</b><small class="muted">${esc(d.host || '')}</small>
    <span class="wts">${err ? '' : d.last_ok ? 'polled ' + ago(new Date(d.last_ok) / 1000) : 'waiting for the first poll'}</span></div>
    ${err ? `<p class="err wterr">${esc(err)}</p>` : ''}
    ${fgExtra(d)}
    <div class="wtl">${d.links.map(l => {
      const lv = live[l.iface] || {};
      if (lv.found === false) return `<div class="wtr"><div class="wtn"><b>${esc(l.label)}</b><small>${esc(l.iface)} · not found on the firewall</small></div></div>`;
      return `<div class="wtr"><div class="wtn"><i class="sd ${lv.at ? (lv.up ? 'ok' : 'bad') : ''}" title="${lv.at ? (lv.up ? 'link up' : 'link down') : 'no data'}"></i><b>${esc(l.label)}</b><small>${esc(l.iface)}${lv.alias ? ' · ' + esc(lv.alias) : ''}${l.down_mbps ? ' · ' + mbps(l.down_mbps) : ''}</small></div>
        ${utilBar(lv.rx || 0, capOf(l, 'down'), '↓')}${utilBar(lv.tx || 0, capOf(l, 'up'), '↑')}<div class="wsp" data-sp="${esc(l.dev + '|' + l.iface)}"></div></div>`;
    }).join('') || '<p class="muted">No interfaces chosen.</p>'}</div></article>`;
}
function sparkLine(pts, cap, color) {
  if (!pts || pts.length < 2) return '';
  const w = 300, h = 34, t0 = pts[0][0], t1 = pts[pts.length - 1][0], mx = Math.max(1, cap || 0, ...pts.map(p => p[1]));
  const line = pts.map(p => `${((p[0] - t0) / Math.max(1, t1 - t0) * w).toFixed(1)},${(h - 2 - p[1] / mx * (h - 4)).toFixed(1)}`).join(' ');
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="width:100%;height:${h}px"><polygon points="0,${h} ${line} ${w},${h}" fill="${color}" opacity=".15"/><polyline points="${line}" fill="none" stroke="${color}" stroke-width="1.6"/></svg>`;
}
async function wanLiveTick(first) {
  clearTimeout(WANTIMER);
  if (view !== 'wan' || !WAN || !WAN.enabled) return;
  try {
    const r = await api('/api/wan?live=1');
    WANLIVE = r.live || {};
    const st = r.status || [], links = WAN.links || [];
    if (!first) { // refresh the tiles with the newest rates
      const byDev = new Map(); st.forEach(d => byDev.set(d.name, { ...d, links: [] }));
      links.forEach(l => { if (!byDev.has(l.dev)) byDev.set(l.dev, { name: l.dev, links: [] }); byDev.get(l.dev).links.push(l) });
      if ($('#wtiles')) $('#wtiles').innerHTML = [...byDev.values()].map(wanTile).join('');
    }
    const cD = css('--down') || '#0e7490', cU = css('--up') || '#6d5bd0';
    links.forEach((l, i) => {
      const pts = WANLIVE[l.dev + '|' + l.iface] || [];
      lineChart($('#wl' + i), [{ name: 'Download', color: cD, fill: 1, pts: pts.map(p => [p[0], p[1]]) }, { name: 'Upload', color: cU, pts: pts.map(p => [p[0], p[2]]) }], capOf(l, 'down'), 160,
        { t0: Date.now() / 1000 - 1800, t1: Date.now() / 1000 });
      const sp = document.querySelector(`[data-sp="${CSS.escape(l.dev + '|' + l.iface)}"]`);
      if (sp) sp.innerHTML = sparkLine(pts.map(p => [p[0], p[1]]), capOf(l, 'down'), cD);
    });
  } catch { }
  WANTIMER = setTimeout(() => wanLiveTick(false), Math.max(10, WAN.poll_seconds || 30) * 1000);
}

{
  const _sv = setView;
  setView = function (v) { document.body.dataset.view = v; _sv(v) };
}
// ------------------------------------------------------------ start
window.addEventListener('DOMContentLoaded', () => { compactHeader(); setupGroups() });

// v5.19: what the FortiGate MIB adds to a tile: CPU / memory / sessions, SD-WAN health per member, IPsec tunnels.
function fgExtra(d) {
  const x = d.extra; if (!x) return '';
  const meter = (v, l) => v == null ? '' : `<span class="fgm"><small>${l}</small><i><em class="${v >= 85 ? 'r' : v >= 70 ? 'a' : ''}" style="width:${Math.min(100, v)}%"></em></i><b>${v}%</b></span>`;
  let h = (x.cpu != null || x.mem != null || x.sessions != null) ? `<div class="fgsys">${meter(x.cpu, 'CPU')}${meter(x.mem, 'Memory')}${x.sessions != null ? `<span class="fgm"><small>Sessions</small><b>${num(x.sessions)}</b></span>` : ''}</div>` : '';
  const sla = x.sla || [];
  if (sla.length) h += `<details class="fgsla" open><summary>SD-WAN health <small class="muted">${sla.filter(s => !s.alive).length ? `<span class="err">${sla.filter(s => !s.alive).length} member(s) dead</span>` : 'all alive'}</small></summary>
    <table><thead><tr><th>Member</th><th>Check</th><th class="n">Latency</th><th class="n">Jitter</th><th class="n">Loss</th></tr></thead><tbody>${sla.map(s => `<tr${s.alive ? '' : ' class="slabad"'}>
      <td><i class="sd ${s.alive ? 'ok' : 'bad'}"></i>${esc(s.iface || '?')}</td><td>${esc(s.name)}</td><td class="n">${s.latency_ms.toFixed(1)} ms</td><td class="n">${s.jitter_ms.toFixed(1)} ms</td>
      <td class="n ${s.loss_pct >= 2 ? 'err' : ''}">${s.loss_pct.toFixed(1)}%</td></tr>`).join('')}</tbody></table></details>`;
  const vpn = x.vpn || [];
  if (vpn.length) h += `<details class="fgsla"${x.vpn_down ? ' open' : ''}><summary>IPsec tunnels <small class="muted">${x.vpn_up} up${x.vpn_down ? ` · <span class="err">${x.vpn_down} down</span>` : ''}</small></summary>
    <table><thead><tr><th>Tunnel</th><th>Remote gateway</th><th class="n">↓ / ↑ now</th></tr></thead><tbody>${vpn.slice(0, 12).map(v => `<tr${v.up ? '' : ' class="slabad"'}>
      <td><i class="sd ${v.up ? 'ok' : 'bad'}"></i>${esc(v.name)}</td><td class="mono">${esc(v.remote)}</td><td class="n">${v.up ? bps(v.rx_bps) + ' / ' + bps(v.tx_bps) : 'down'}</td></tr>`).join('')}</tbody></table>
    ${vpn.length > 12 ? `<p class="hint">${vpn.length - 12} more</p>` : ''}</details>`;
  return h;
}
