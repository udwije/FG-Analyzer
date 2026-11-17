// Signed-in user, role-based tabs, password change, and (admins) accounts and the audit log.
let ME = null;
const ROLES = [['viewer', 'Viewer: dashboards only (wall screens)'], ['analyst', 'Analyst: + log explorer, export, investigation, mapping'], ['admin', 'Admin: + settings, accounts, audit log']];
const jsend = async (url, method, body) => {
  const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!r.ok) throw new Error(await errText(r));
  return r.json();
};

async function loadMe() {
  try { ME = await api('/api/me') } catch { return }
  $('#who').hidden = false; $('#pwbtn').hidden = false;
  $('#who').textContent = `${ME.username} · ${ME.role}`;
  const hide = { viewer: ['investigate', 'mapping', 'devices', 'logs', 'reports', 'settings'], analyst: ['settings'], admin: [] }[ME.role] || [];
  $$('#tabs button').forEach(b => b.hidden = hide.includes(b.dataset.view));
  if (hide.includes(view)) setView('global');
  if (ME.role !== 'analyst' && ME.role !== 'admin') $('#export').hidden = true;
  if (ME.must_change) pwDialog(true);
}

function pwDialog(forced) {
  const d = document.createElement('div');
  d.className = 'modal';
  d.innerHTML = `<form class="mbox"><h2>${forced ? 'Choose your own password' : 'Change password'}</h2>
    ${forced ? '<p class="hint">You signed in with a one-time password. Choose a new one to continue.</p>' : ''}
    <label>Current password<input type="password" name="old" autocomplete="current-password" required></label>
    <label>New password (10+ characters)<input type="password" name="new" autocomplete="new-password" minlength="10" required></label>
    <label>Repeat the new password<input type="password" name="rep" autocomplete="new-password" minlength="10" required></label>
    <p class="err" id="pwmsg"></p><div class="actions">${forced ? '' : '<button type="button" id="pwcancel">Cancel</button>'}<button class="primary">Save password</button></div></form>`;
  document.body.appendChild(d);
  const f = d.querySelector('form');
  f.old.focus();
  if (!forced) d.querySelector('#pwcancel').onclick = () => d.remove();
  f.onsubmit = async e => {
    e.preventDefault();
    if (f.new.value !== f.rep.value) { d.querySelector('#pwmsg').textContent = 'The new passwords do not match.'; return }
    try { await jsend('/api/password', 'POST', { old: f.old.value, new: f.new.value }); d.remove(); ME.must_change = false }
    catch (x) { d.querySelector('#pwmsg').textContent = x.message }
  };
}

$('#pwbtn').onclick = () => pwDialog(false);
$('#logout').onclick = async () => { try { await jsend('/api/logout', 'POST', {}) } catch { } location.href = '/login.html' };

// ------------------------------------------------------------ accounts and audit (admins, under Settings)
let AUQ = '';
async function loadAccounts() {
  if (!ME || ME.role !== 'admin') { $('#acct').innerHTML = ''; return }
  let users = [], audit = [];
  try { [users, audit] = await Promise.all([api('/api/users'), api('/api/audit?q=' + encodeURIComponent(AUQ))]) }
  catch (x) { $('#acct').innerHTML = `<div class="notice err">${esc(x.message)}</div>`; return }
  const ropt = sel => ROLES.map(([v]) => `<option${v === sel ? ' selected' : ''}>${v}</option>`).join('');
  $('#acct').innerHTML = `<form class="acct" onsubmit="return false"><h2>Accounts</h2>
    <p class="hint">${ROLES.map(r => esc(r[1])).join(' · ')}. New accounts and reset passwords must be changed at the next sign-in.</p>
    ${table([['Username'], ['Role'], ['State'], ['Last sign-in'], ['Created'], ['']], users.map(u => `<tr data-u="${esc(u.username)}">
      <td><b>${esc(u.username)}</b>${u.username === ME.username ? ' <span class="pill">you</span>' : ''}${u.must_change ? ' <span class="pill">must change password</span>' : ''}</td>
      <td><select data-act="role">${ropt(u.role)}</select></td>
      <td>${u.disabled ? '<span class="pill bad">Disabled</span>' : '<span class="pill ok">Enabled</span>'}</td>
      <td>${u.last_login && !u.last_login.startsWith('0001') ? ldt(u.last_login) : 'never'}</td><td>${ldt(u.created)}</td>
      <td class="r"><button type="button" data-act="reset">Reset password</button> <button type="button" data-act="toggle">${u.disabled ? 'Enable' : 'Disable'}</button> <button type="button" data-act="del">Delete</button></td></tr>`), 'No accounts.')}
    <h3 style="margin-top:16px">Add an account</h3>
    <div class="mapform"><label>Username<input id="nu-name" autocomplete="off"></label><label>Role<select id="nu-role">${ropt('viewer')}</select></label>
      <label>One-time password (10+)<input id="nu-pw" type="text" autocomplete="off"></label><div class="mbtns"><button type="button" id="nu-gen">Generate</button><button type="button" class="primary" id="nu-add">Add account</button></div></div>
    <p id="acmsg" class="hint" role="status"></p>
    <h2>Audit log</h2><p class="hint">Sign-ins, failed sign-ins, exports, settings and account changes. Last 300 entries.</p>
    <div class="mapform"><label>Search<input id="au-q" value="${esc(AUQ)}" placeholder="username, action or IP"></label><div class="mbtns"><button type="button" id="au-go">Search</button></div></div>
    <div class="scrollbox">${table([['Time'], ['User'], ['From'], ['Action'], ['Detail']], audit.map(a => `<tr><td>${ldt(a.at)}</td><td>${esc(a.user)}</td><td>${esc(a.ip)}</td><td>${esc(a.action.replace(/_/g, ' '))}</td><td class="wrap" title="${esc(a.detail)}">${esc(a.detail)}</td></tr>`), 'Nothing recorded yet.')}</div></form>`;
  const msg = t => { $('#acmsg').textContent = t };
  const gen = () => { const a = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789', b = new Uint32Array(14); crypto.getRandomValues(b); return [...b].map(x => a[x % a.length]).join('') };
  $('#nu-gen').onclick = () => { $('#nu-pw').value = gen() };
  $('#nu-add').onclick = async () => {
    const n = $('#nu-name').value.trim(), p = $('#nu-pw').value;
    try { await jsend('/api/users', 'POST', { create: true, username: n, role: $('#nu-role').value, password: p }); await loadAccounts(); msg(`Added ${n}. Give them the one-time password: ${p}`) }
    catch (x) { msg(x.message) }
  };
  $('#au-go').onclick = () => { AUQ = $('#au-q').value.trim(); loadAccounts() };
  $('#au-q').onkeydown = e => { if (e.key === 'Enter') $('#au-go').click() };
  $$('#acct tr[data-u]').forEach(tr => {
    const u = tr.dataset.u, act = async (body, done) => { try { await jsend('/api/users', 'POST', { username: u, ...body }); await loadAccounts(); if (done) msg(done) } catch (x) { msg(x.message); loadAccounts() } };
    tr.querySelector('[data-act=role]').onchange = e => act({ role: e.target.value }, `${u} is now ${e.target.value}.`);
    tr.querySelector('[data-act=toggle]').onclick = e => act({ disabled: e.target.textContent === 'Disable' });
    tr.querySelector('[data-act=reset]').onclick = () => { const p = gen(); if (confirm(`Reset the password of ${u}? They will be signed out everywhere.`)) act({ password: p }, `New one-time password for ${u}: ${p}`) };
    tr.querySelector('[data-act=del]').onclick = async () => { if (!confirm(`Delete the account ${u}?`)) return; try { await jsend('/api/users?username=' + encodeURIComponent(u), 'DELETE'); loadAccounts() } catch (x) { msg(x.message) } };
  });
}
const _loadConfig = loadConfig;
loadConfig = async function () { try { await _loadConfig() } finally { loadAccounts() } };

loadMe();
