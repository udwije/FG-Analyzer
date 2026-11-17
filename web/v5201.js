// v5.20.1: several firewalls with the same SNMPv3 user: "Same SNMPv3 user as" copies the user and its passphrases.
{
  const _wd = wanDevHTML;
  wanDevHTML = function (d, i) {
    let h = _wd(d, i);
    const others = (WANDEVS || []).filter((x, j) => j !== i && (x.name || x.host));
    if (others.length) {
      const cur = d.creds_from || '';
      const sel = `<label>Same SNMPv3 user as<select data-f="creds_from" data-copy="${i}"><option value="">(own user and passphrases)</option>${others.map(x => {
        const n = x.name || x.host; return `<option${n === cur ? ' selected' : ''} value="${esc(n)}">${esc(n)}</option>`;
      }).join('')}</select></label>`;
      h = h.replace('<label>Security level', sel + '<label>Security level');
    }
    if (d.creds_from && !d.auth_set) {
      const t = `<span class="pill ok">copied from ${esc(d.creds_from)}</span>`;
      h = h.split('<span class="pill bad">not saved</span>').join(t)
        .replace(/placeholder="required: none saved"/g, `placeholder="from ${esc(d.creds_from)} (leave empty)"`);
    }
    return h;
  };
  $('#wandevs').addEventListener('change', e => {
    const s = e.target.closest('[data-copy]'); if (!s) return;
    const i = +s.dataset.copy; WANDEVS = readWANDevs();
    const src = WANDEVS.find((x, j) => j !== i && (x.name || x.host) === s.value);
    if (src) ['username', 'security_level', 'auth_protocol', 'priv_protocol', 'port'].forEach(k => { if (src[k]) WANDEVS[i][k] = src[k] });
    WANDEVS[i].creds_from = s.value;
    renderWANDevs();
  });
  // a new firewall starts with the user of the first firewall that has one (they are usually set up the same way)
  $('#wanadd').onclick = () => {
    WANDEVS = readWANDevs();
    const src = WANDEVS.find(x => (x.auth_set || x.auth_pass) && (x.name || x.host));
    WANDEVS.push(src ? { port: src.port || 161, username: src.username, security_level: src.security_level, auth_protocol: src.auth_protocol,
      priv_protocol: src.priv_protocol, creds_from: src.name || src.host, interfaces: [] } : { port: 161, interfaces: [] });
    renderWANDevs();
  };
}
