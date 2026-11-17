// v5.21: WAN health history on the WAN links tab, WAN alerts, the alert limits in Settings.

Object.assign(ALKIND, { wan_busy: 'Circuit near capacity', wan_sla: 'SD-WAN member', wan_tunnel: 'IPsec tunnel down', fw_load: 'Firewall load', wan_poll: 'WAN monitor' });

// ------------------------------------------------------------ Settings > Alerts: WAN limits
{
  const F = [['al_wbp', 'wan_busy_pct'], ['al_wbm', 'wan_busy_min'], ['al_wlp', 'wan_loss_pct'], ['al_tdm', 'tunnel_down_min'], ['al_fwl', 'fw_load_pct']];
  const _fc = formConfig;
  formConfig = function () {
    const c = _fc(), f = $('#config').elements;
    F.forEach(([n, k]) => { if (f[n]) c.alerts[k] = +f[n].value || 0 });
    return c;
  };
  const _lc = loadConfig;
  loadConfig = async function () {
    await _lc();
    const f = $('#config').elements, a = (CFG || {}).alerts || {};
    F.forEach(([n, k]) => { if (f[n]) f[n].value = a[k] ?? '' });
  };
}

// ------------------------------------------------------------ small line chart with its own number format
function hLine(el, series, fmt, opts = {}) {
  if (!el) return;
  const W = Math.max(300, Math.round(el.clientWidth) || 600), H = opts.h || 150, L = 58, R = 8, T = 8, B = 22, pw = W - L - R, ph = H - T - B;
  const pts = series.flatMap(s => s.pts.filter(p => p[1] >= 0));
  if (!pts.length) { el.innerHTML = '<p class="muted">No data in this period.</p>'; return }
  const t0 = opts.t0 || Math.min(...pts.map(p => p[0])), t1 = opts.t1 || Math.max(...pts.map(p => p[0])), span = Math.max(1, t1 - t0);
  const mx = opts.max || Math.max(1, ...pts.map(p => p[1])) * 1.1;
  const X = t => L + (t - t0) / span * pw, Y = v => T + ph - Math.min(v, mx) / mx * ph;
  const lab = s => { const d = new Date(s * 1000); return span > 36 * 3600 ? d.toLocaleDateString([], { month: 'short', day: 'numeric' }) : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) };
  let g = '';
  [0, .5, 1].forEach(f => { const y = T + ph - f * ph; g += `<line x1="${L}" x2="${W - R}" y1="${y}" y2="${y}" class="grid"/><text x="${L - 6}" y="${y + 4}" text-anchor="end">${fmt(mx * f)}</text>` });
  for (let i = 0; i <= 4; i++) { const t = t0 + i * span / 4; g += `<text x="${X(t)}" y="${H - 6}" text-anchor="middle">${lab(t)}</text>` }
  if (opts.limit) g += `<line x1="${L}" x2="${W - R}" y1="${Y(opts.limit)}" y2="${Y(opts.limit)}" class="capl"/>`;
  let p = '';
  series.forEach(s => {
    // break the line where a sample is missing (-1)
    let seg = [];
    const flush = () => { if (seg.length > 1) p += `<polyline points="${seg.join(' ')}" fill="none" stroke="${s.color}" stroke-width="1.8"/>`; else if (seg.length === 1) { const [x, y] = seg[0].split(','); p += `<circle cx="${x}" cy="${y}" r="2" fill="${s.color}"/>` } seg = [] };
    s.pts.forEach(q => { if (q[1] < 0) flush(); else seg.push(`${X(q[0]).toFixed(1)},${Y(q[1]).toFixed(1)}`) });
    flush();
  });
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:${H}px;cursor:default">${g}${p}</svg>
    <div class="legend">${series.map(s => `<i style="background:${s.color}"></i>${esc(s.name)}`).join('')}</div>`;
}

// ------------------------------------------------------------ WAN links: health over the period
let WH = null;
async function wanHealthCard() {
  if (view !== 'wan' || !WAN || !WAN.enabled) return;
  let el = $('#wanhist');
  if (!el) {
    el = document.createElement('div'); el.id = 'wanhist'; el.className = 'card';
    const diag = $('#wandiag');
    diag ? diag.before(el) : $('#wanbody').append(el);
  }
  el.innerHTML = '<div class="ch"><h3>Health over the period</h3><span class="hint">Loading…</span></div>';
  try { WH = await api('/api/wan?health=1&' + qs()) } catch (x) { el.innerHTML = `<div class="ch"><h3>Health over the period</h3></div><p class="err">${esc(x.message)}</p>`; return }
  const devs = [...new Set([...Object.keys(WH.sys || {}), ...(WH.sla || []).map(s => s.dev), ...(WH.vpn || []).map(v => v.dev)])].sort();
  if (!devs.length) {
    el.innerHTML = '<div class="ch"><h3>Health over the period</h3></div><p class="muted">Nothing stored yet. CPU, memory, SD-WAN health and tunnels are stored from v5.21 on: the history fills from now.</p>';
    return;
  }
  const t0 = new Date(WAN.from) / 1000, t1 = Math.min(Date.now(), new Date(WAN.to)) / 1000, pct = v => Math.round(v) + '%';
  const qCls = v => v >= 99 ? 'ok' : v >= 95 ? 'a' : 'r';
  const PAL2 = ['#0e7490', '#6d5bd0', '#c2417a', '#0f9d8a', '#e08a00', '#3b82c4'];
  el.innerHTML = `<div class="ch"><h3>Health over the period</h3><span class="hint">Stored every poll (load) and about once a minute (SD-WAN, tunnels). Link quality = time alive with under 2% loss and under 150 ms.</span></div>
    ${devs.map((d, i) => {
      const sla = (WH.sla || []).filter(s => s.dev === d), vpn = (WH.vpn || []).filter(v => v.dev === d && v.ever_up), never = (WH.vpn || []).filter(v => v.dev === d && !v.ever_up).length;
      return `<div class="whdev"><h4>${esc(d)}</h4><div class="whgrid">
        <div><h5>CPU and memory</h5><div class="chartwrap" id="whs${i}"></div></div>
        <div><h5>SD-WAN latency (ms)</h5><div class="chartwrap" id="whl${i}"></div></div>
        <div><h5>SD-WAN packet loss</h5><div class="chartwrap" id="whp${i}"></div></div></div>
        <div class="whgrid2">
        <div>${sla.length ? `<table><thead><tr><th>Member</th><th>Check</th><th class="n">Quality</th><th class="n">Latency</th><th class="n">Jitter</th><th class="n">Loss</th><th class="n">Dead</th></tr></thead><tbody>
          ${sla.map(s => `<tr><td><b>${esc(s.iface)}</b></td><td>${esc(s.check)}</td><td class="n"><span class="upill ${qCls(s.quality_pct)}">${s.quality_pct.toFixed(1)}%</span></td>
            <td class="n">${s.latency_ms.toFixed(1)} ms</td><td class="n">${s.jitter_ms.toFixed(1)} ms</td><td class="n">${s.loss_pct.toFixed(2)}%</td>
            <td class="n">${s.dead_samples ? pc(s.dead_samples, s.samples) + '%' : 'never'}</td></tr>`).join('')}</tbody></table>` : '<p class="muted">No SD-WAN health checks.</p>'}</div>
        <div>${vpn.length ? `<table><thead><tr><th>Tunnel</th><th class="n">Uptime</th><th class="n">Drops</th><th class="n">Average ↓ / ↑</th><th>Last down</th></tr></thead><tbody>
          ${vpn.sort((a, b) => a.up_pct - b.up_pct).slice(0, 15).map(v => `<tr><td>${esc(v.tunnel)}</td><td class="n"><span class="upill ${qCls(v.up_pct)}">${v.up_pct.toFixed(2)}%</span></td>
            <td class="n">${num(v.drops)}</td><td class="n">${bps(v.rx_avg)} / ${bps(v.tx_avg)}</td><td>${v.last_down && v.down_samples ? ldt(v.last_down) : '–'}</td></tr>`).join('')}</tbody></table>
          ${vpn.length > 15 ? `<p class="hint">${vpn.length - 15} more (least available first)</p>` : ''}` : '<p class="muted">No IPsec tunnels were up in this period.</p>'}
          ${never ? `<p class="hint">${never} tunnel${never === 1 ? '' : 's'} never up in this period (dial-up templates or unused): not counted.</p>` : ''}</div></div></div>`;
    }).join('')}`;
  devs.forEach((d, i) => {
    const s = (WH.sys || {})[d] || [];
    hLine($('#whs' + i), [{ name: 'CPU', color: '#e4572e', pts: s.map(r => [r[0], r[1]]) }, { name: 'Memory', color: '#6d5bd0', pts: s.map(r => [r[0], r[2]]) }], pct, { t0, t1, max: 100, limit: 85 });
    const keys = Object.keys(WH.sla_series || {}).filter(k => k.startsWith(d + '|'));
    const nm = k => k.split('|').slice(1).join(' · ');
    hLine($('#whl' + i), keys.map((k, j) => ({ name: nm(k), color: PAL2[j % 6], pts: WH.sla_series[k].map(r => [r[0], r[4] > 0 ? r[1] : -1]) })), v => Math.round(v) + ' ms', { t0, t1 });
    hLine($('#whp' + i), keys.map((k, j) => ({ name: nm(k), color: PAL2[j % 6], pts: WH.sla_series[k].map(r => [r[0], Math.min(100, r[3])]) })), v => v.toFixed(v < 10 ? 1 : 0) + '%', { t0, t1, limit: 2, max: Math.max(5, ...keys.flatMap(k => WH.sla_series[k].map(r => Math.min(100, r[3]))) ) * 1.1 });
  });
}
{
  const _rw = renderWAN;
  renderWAN = function () { _rw(); wanHealthCard() };
}
