// Settings form. Lists are edited as text: one item per line.
const lines = v => (v || '').split(/\r?\n/).map(x => x.trim()).filter(Boolean);
let CFG = null;
// v6.0.13: the revision of the settings this page shows; sent back with every save (If-Match). A 409 means
// someone changed the settings in between: nothing was saved, reload and make the change again.
let CFG_REV = '';
// A settings change made from another card of this page (sites, summary settings, blocklist, certificate) returns
// the new revision too: take it, so the next save is not refused as a conflict with ourselves.
{
  const _fetch = window.fetch.bind(window);
  window.fetch = async (url, opt) => {
    const r = await _fetch(url, opt);
    const m = ((opt && opt.method) || 'GET').toUpperCase();
    if (r.ok && m !== 'GET') { const v = r.headers.get('X-Config-Revision'); if (v) CFG_REV = v }
    return r;
  };
}
async function getConfig() {
  const r = await fetch('/api/config');
  if (!r.ok) throw new Error(await errText(r));
  CFG_REV = r.headers.get('X-Config-Revision') || '';
  return r.json();
}
function cfgHeaders() {
  const h = { 'Content-Type': 'application/json' };
  if (CFG_REV) h['If-Match'] = CFG_REV;
  return h;
}
function cfgSaveError(r, msg) {
  return r.status === 409 ? 'Not saved: ' + msg + ' Refresh the page (F5) to load the latest settings.' : msg;
}
async function loadConfig() {
  const c = CFG = await getConfig(), f = $('#config').elements, n = c.nps || {};
  ['listen_address', 'web_listen_address', 'retention_days', 'batch_size', 'spool_directory', 'spool_max_mb', 'compress_after_days', 'query_concurrency', 'session_hours', 'tls_cert_file', 'tls_key_file'].forEach(k => f[k].value = c[k] ?? '');
  f.web_tls.checked = !!c.web_tls;
  const x = c.exec || {};
  [['ex_org', 'org_name'], ['ex_bua', 'blocked_up_amber'], ['ex_bur', 'blocked_up_red'], ['ex_afa', 'admin_fail_amber'], ['ex_afr', 'admin_fail_red'], ['ex_raa', 'risk_apps_amber'],
   ['ex_rar', 'risk_apps_red'], ['ex_aiu', 'ai_upload_up_amber'], ['ex_qam', 'quiet_amber_min'], ['ex_qrh', 'quiet_red_hours'], ['ex_dbd', 'device_blocks_day']].forEach(([n, k]) => f[n].value = x[k] ?? '');
  f.ex_src.value = (x.exclude_sources || []).join('\n'); f.ex_dst.value = (x.exclude_destinations || []).join('\n');
  f.ex_usr.value = (x.exclude_users || []).join('\n'); f.ex_sub.value = (x.exclude_subtypes || []).join(', ');
  f.ex_ignfw.value = (x.ignore_firewalls || []).join('\n'); f.ex_intdom.value = (x.internal_domains || []).join('\n'); f.ex_showint.checked = !!x.show_internal_dests;
  f.internal_networks.value = (c.internal_networks || []).join('\n');
  const dr = c.directory || {}, al = c.alerts || {};
  f.dir_enabled.checked = !!dr.enabled; f.dir_path.value = dr.path || ''; f.dir_norm.checked = !!dr.normalize_users; f.dir_drop.checked = !!dr.drop_unverified; f.dir_poll.value = dr.poll_minutes || 5;
  f.al_enabled.checked = !!al.enabled; f.al_bf.value = al.brute_force; f.al_spray.value = al.spray_users; f.al_ws.value = al.work_start; f.al_we.value = al.work_end;
  f.al_wknd.checked = !!al.work_weekend; f.al_silent.value = al.silent_min; f.al_blk.value = al.blocked_per_hour; f.al_up.value = al.upload_mb; f.al_unk.value = al.unknown_gb;
  f.tcp_enabled.checked = c.tcp_enabled; f.udp_enabled.checked = c.udp_enabled;
  f.allowed_sources.value = (c.allowed_sources || []).join(', '); f.keep_subtypes.value = (c.keep_subtypes || []).join(', ');
  f.firewalls.value = (c.firewalls || []).map(x => `${x.name}, ${x.ip}`).join('\n');
  f.ai_categories.value = (c.ai_categories || []).join('\n');
  f.ai_rules.value = (c.ai_rules || []).map(r => `${r.tool}: ${(r.patterns || []).join(', ')}`).join('\n');
  f.nps_enabled.checked = !!n.enabled; f.nps_learn_mac.checked = !!n.learn_from_mac; f.nps_paths.value = (n.paths || []).join('\n');
  f.nps_poll.value = n.poll_seconds ?? 5; f.nps_idle.value = n.idle_hours ?? 10; f.nps_backfill.value = n.backfill_hours ?? 24;
  f.nps_strip.checked = !!n.strip_domain; f.nps_lower.checked = !!n.lowercase;
  f.db_host.value = c.database.host; f.db_port.value = c.database.port; f.db_name.value = c.database.name; f.db_user.value = c.database.user; f.db_ssl.value = c.database.ssl_mode;
  try {
    const s = await api('/api/status');
          const ds = s.directory || {};
      $('#dirstatus').innerHTML = !ds.enabled ? 'Off.' : ds.error ? `<span class="err">${esc(ds.error)}</span>` : ds.loaded
        ? `Loaded: <b>${num(ds.active)}</b> active staff, ${num(ds.former)} former, ${num(ds.computers)} computers${ds.imported ? ' · read ' + ldt(ds.imported) : ''}.` : 'Waiting for the first staff.csv in that folder.';
      const ex = s.exclusions || {};
    $('#exclstatus').innerHTML = !ex.active ? 'No exclusions: the executive summary shows all traffic.'
      : `Active: ${(ex.rules || []).map(esc).join(' · ')}. ${ex.pending_hours ? `<b>${num(ex.pending_hours)} hours of history still to recalculate</b> (in the background).` : 'History is up to date.'}${(ex.skipped_hours || []).length ? ` <span class="err">Skipped after repeated time-outs: ${ex.skipped_hours.map(esc).join(', ')} (retried after a restart).</span>` : ''}${ex.last_error ? ` <span class="err">Last problem: ${esc(ex.last_error)}</span>` : ''}`;
    $('#fwstatus').innerHTML = (s.firewalls || []).length ? 'Seen since the service started: ' + s.firewalls.map(x => `<b>${esc(x.name)}</b> (${esc(x.ip)}) ${x.last ? num(x.received) + ' logs, last ' + ago(x.last) : 'nothing yet'}${x.configured ? '' : ' · not in the list'}`).join(' · ') : 'No logs received since the service started.';
  } catch { }
  reclassPoll();
}
function parseFirewalls(v) {
  return lines(v).map(l => { const p = l.split(/[,;\t]/).map(x => x.trim()).filter(Boolean); return p.length === 1 ? { name: '', ip: p[0] } : { name: p.slice(0, -1).join(' '), ip: p[p.length - 1] } });
}
function parseRules(v) {
  return lines(v).map(l => { const i = l.indexOf(':'); if (i < 1) throw new Error(`AI tool line "${l}" needs the form Tool: pattern, pattern`); return { tool: l.slice(0, i).trim(), patterns: l.slice(i + 1).split(',').map(x => x.trim()).filter(Boolean) } });
}
function formConfig() {
  const f = $('#config').elements, c = CFG || {};
  return {
    listen_address: f.listen_address.value, web_listen_address: f.web_listen_address.value, tcp_enabled: f.tcp_enabled.checked, udp_enabled: f.udp_enabled.checked,
    allowed_sources: f.allowed_sources.value.split(',').map(x => x.trim()).filter(Boolean), keep_subtypes: f.keep_subtypes.value.split(',').map(x => x.trim()).filter(Boolean),
    max_message_bytes: c.max_message_bytes || 1048576, queue_capacity: c.queue_capacity || 200000, batch_size: +f.batch_size.value, batch_interval_ms: c.batch_interval_ms || 1000,
    retention_days: +f.retention_days.value, spool_directory: f.spool_directory.value, spool_max_mb: +f.spool_max_mb.value, admin_token: '',
    compress_after_days: +f.compress_after_days.value || 2, query_concurrency: +f.query_concurrency.value || 6, session_hours: +f.session_hours.value || 12,
    exec: { org_name: f.ex_org.value.trim(), blocked_up_amber: +f.ex_bua.value, blocked_up_red: +f.ex_bur.value, admin_fail_amber: +f.ex_afa.value, admin_fail_red: +f.ex_afr.value,
      risk_apps_amber: +f.ex_raa.value, risk_apps_red: +f.ex_rar.value, ai_upload_up_amber: +f.ex_aiu.value, quiet_amber_min: +f.ex_qam.value, quiet_red_hours: +f.ex_qrh.value,
      device_blocks_day: +f.ex_dbd.value, exclude_sources: lines(f.ex_src.value), exclude_destinations: lines(f.ex_dst.value),
      exclude_users: lines(f.ex_usr.value), exclude_subtypes: f.ex_sub.value.split(',').map(x => x.trim()).filter(Boolean),
      ignore_firewalls: lines(f.ex_ignfw.value), internal_domains: lines(f.ex_intdom.value), show_internal_dests: f.ex_showint.checked },
          internal_networks: lines(f.internal_networks.value),
      directory: { enabled: f.dir_enabled.checked, path: f.dir_path.value.trim(), normalize_users: f.dir_norm.checked, drop_unverified: f.dir_drop.checked, poll_minutes: +f.dir_poll.value || 5 },
      alerts: { enabled: f.al_enabled.checked, brute_force: +f.al_bf.value, spray_users: +f.al_spray.value, work_start: +f.al_ws.value, work_end: +f.al_we.value,
        work_weekend: f.al_wknd.checked, silent_min: +f.al_silent.value, blocked_per_hour: +f.al_blk.value, upload_mb: +f.al_up.value, unknown_gb: +f.al_unk.value },
    web_tls: f.web_tls.checked, tls_cert_file: f.tls_cert_file.value.trim(), tls_key_file: f.tls_key_file.value.trim(),
    firewalls: parseFirewalls(f.firewalls.value), ai_categories: lines(f.ai_categories.value), ai_rules: parseRules(f.ai_rules.value),
    nps: { enabled: f.nps_enabled.checked, paths: lines(f.nps_paths.value), poll_seconds: +f.nps_poll.value || 5, idle_hours: +f.nps_idle.value || 10, backfill_hours: +f.nps_backfill.value,
      strip_domain: f.nps_strip.checked, lowercase: f.nps_lower.checked, learn_from_mac: f.nps_learn_mac.checked },
    database: { host: f.db_host.value, port: +f.db_port.value, name: f.db_name.value, user: f.db_user.value, password: f.db_password.value, ssl_mode: f.db_ssl.value, max_connections: (c.database || {}).max_connections || 10 }
  };
}
$('#config').onsubmit = async e => {
  e.preventDefault();
  try {
    const r = await fetch('/api/config', { method: 'PUT', headers: cfgHeaders(), body: JSON.stringify(formConfig()) });
    if (!r.ok) throw new Error(cfgSaveError(r, await errText(r)));
    const j = await r.json(); D = G = null;
    $('#message').textContent = j.restart_required ? 'Saved. Restart the service to apply the listener, HTTPS, firewall list or database changes.' : 'Saved. The changes are already in use.';
    loadConfig();
  } catch (x) { $('#message').textContent = x.message }
};
$('#testdb').onclick = async () => { try { const r = await fetch('/api/database/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(formConfig().database) }); if (!r.ok) throw new Error(await r.text()); $('#message').textContent = 'Database connection successful' } catch (x) { $('#message').textContent = 'Database test failed: ' + x.message } };
let reclassTimer = null;
async function reclassPoll() {
  clearTimeout(reclassTimer);
  try {
    const s = await api('/api/ai/reclassify');
    $('#reclassmsg').textContent = s.error ? 'Stopped: ' + s.error : s.running ? `Working… ${s.hours_done || 0} of ${s.days_total * 24} hours, ${num(s.rows_changed)} logs changed` : s.days_total ? `Done: ${num(s.rows_changed)} logs changed.${s.note ? ' ' + s.note : ''} The AI summaries of the changed hours are rebuilt within a few minutes.` : '';
    if (s.running && view === 'settings') reclassTimer = setTimeout(reclassPoll, 3000);
  } catch { }
}
$('#reclass').onclick = async () => {
  const days = +$('#config').elements.reclass_days.value || 7;
  if (!confirm(`Re-check the last ${days} days of stored logs with the saved AI rules? Save your rule changes first. This can take a while on large databases.`)) return;
  try { const r = await fetch('/api/ai/reclassify?days=' + days, { method: 'POST', headers: { 'X-LogSikka': '1' } }); if (!r.ok) throw new Error(await r.text()); D = G = null; reclassPoll() } catch (x) { $('#reclassmsg').textContent = x.message }
};

// v5.10: add the built-in AI tools an older configuration does not have yet (own rules and their order are kept)
$('#aidefaults').onclick = async () => {
  try {
    const d = await api('/api/ai/defaults'), f = $('#config').elements, have = new Set(parseRules(f.ai_rules.value).map(r => r.tool.toLowerCase()));
    const add = d.rules.filter(r => !have.has(r.tool.toLowerCase()));
    const cats = lines(f.ai_categories.value), lc = new Set(cats.map(c => c.toLowerCase())), addc = d.categories.filter(c => !lc.has(c.toLowerCase()));
    if (!add.length && !addc.length) { $('#reclassmsg').textContent = 'Every built-in tool is already in your list.'; return }
    f.ai_rules.value = [f.ai_rules.value.trim(), ...add.map(r => `${r.tool}: ${r.patterns.join(', ')}`)].filter(Boolean).join('\n');
    if (addc.length) f.ai_categories.value = [...cats, ...addc].join('\n');
    $('#reclassmsg').textContent = `Added ${add.length} tool${add.length === 1 ? '' : 's'}${add.length ? ': ' + add.map(r => r.tool).join(', ') : ''}. Save the configuration, then Re-classify to tag older logs.`;
  } catch (x) { $('#reclassmsg').textContent = x.message }
};
