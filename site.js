(() => {
  'use strict';

  /* ---------- Record definitions ---------- */
  const isSpf = (txt) => /^v=spf1(\s|$)/i.test(txt);

  const RECORDS = [
    { id: 'A',      type: 1,   desc: 'IPv4 address' },
    { id: 'AAAA',   type: 28,  desc: 'IPv6 address' },
    { id: 'CNAME',  type: 5,   desc: 'Canonical name (alias)' },
    { id: 'NS',     type: 2,   desc: 'Authoritative name servers' },
    { id: 'TXT',    type: 16,  desc: 'Text records' },
    { id: 'SPF',    type: 16,  desc: 'Sender policy (TXT starting v=spf1)', filter: isSpf },
    { id: 'TLSA',   type: 52,  desc: 'TLS certificate association (DANE)', tlsa: true },
    { id: 'MX',     type: 15,  desc: 'Mail exchangers' },
    { id: 'SOA',    type: 6,   desc: 'Start of authority' },
    { id: 'CAA',    type: 257, desc: 'Certificate authority authorization' },
    { id: 'DS',     type: 43,  desc: 'Delegation signer (DNSSEC)' },
    { id: 'DNSKEY', type: 48,  desc: 'DNSSEC public keys' },
  ];
  const DEFAULTS = ['A', 'AAAA', 'CNAME', 'NS', 'TXT', 'SPF', 'TLSA', 'MX', 'SOA', 'CAA'];

  const RESOLVERS = {
    google:     { label: 'Google',     url: 'https://dns.google/resolve' },
    cloudflare: { label: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
  };

  const RCODES = {
    0: 'OK',
    1: 'Format error',
    2: 'Server failure',
    3: 'Domain does not exist (NXDOMAIN)',
    4: 'Not implemented',
    5: 'Query refused',
  };

  const TLSA_USAGE = { 0: 'PKIX-TA', 1: 'PKIX-EE', 2: 'DANE-TA', 3: 'DANE-EE' };
  const TLSA_SELECTOR = { 0: 'full certificate', 1: 'public key (SPKI)' };
  const TLSA_MATCH = { 0: 'exact match', 1: 'SHA-256', 2: 'SHA-512' };

  /* ---------- DOM helpers ---------- */
  const $ = (id) => document.getElementById(id);

  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === false || v == null) continue;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? '' : v);
      }
    }
    for (const kid of kids.flat()) {
      if (kid == null || kid === false) continue;
      el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }

  const els = {
    form: $('form'), domain: $('domain'), resolver: $('resolver'), go: $('go'),
    chips: $('chips'), all: $('all'), none: $('none'), defaults: $('defaults'),
    tlsaOpts: $('tlsa-opts'), tlsaPort: $('tlsa-port'), tlsaProto: $('tlsa-proto'),
    error: $('error'), summary: $('summary'), summaryText: $('summary-text'),
    copyJson: $('copy-json'), results: $('results'),
  };

  /* ---------- State ---------- */
  const selected = new Set(DEFAULTS);
  let lastExport = null;
  let runId = 0;

  /* ---------- Chips ---------- */
  function renderChips() {
    els.chips.replaceChildren(
      ...RECORDS.map((r) =>
        h('button', {
          type: 'button',
          class: 'chip',
          'aria-pressed': selected.has(r.id) ? 'true' : 'false',
          title: r.desc,
          onclick: () => {
            if (selected.has(r.id)) selected.delete(r.id); else selected.add(r.id);
            renderChips();
          },
        }, r.id)
      )
    );
    els.tlsaOpts.hidden = !selected.has('TLSA');
  }

  els.all.addEventListener('click', () => { RECORDS.forEach((r) => selected.add(r.id)); renderChips(); });
  els.none.addEventListener('click', () => { selected.clear(); renderChips(); });
  els.defaults.addEventListener('click', () => { selected.clear(); DEFAULTS.forEach((d) => selected.add(d)); renderChips(); });

  /* ---------- Input cleanup ---------- */
  function normalizeDomain(raw) {
    let s = String(raw || '').trim().toLowerCase();
    s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
    s = s.split(/[\/?#]/)[0];
    s = s.replace(/^.*@/, '');
    s = s.replace(/:\d+$/, '');
    s = s.replace(/\.+$/, '');
    if (!s) return '';
    try { s = new URL('http://' + s).hostname; } catch { return ''; }
    if (!/^[a-z0-9_.-]+$/.test(s) || !s.includes('.')) return '';
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return '';
    return s;
  }

  /* ---------- DNS over HTTPS ---------- */
  async function dohFetch(resolverKey, name, type) {
    const base = RESOLVERS[resolverKey].url;
    const url = `${base}?name=${encodeURIComponent(name)}&type=${type}`;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 9000);
    try {
      const res = await fetch(url, { headers: { accept: 'application/dns-json' }, signal: ctrl.signal });
      if (!res.ok) throw new Error(`${RESOLVERS[resolverKey].label} returned HTTP ${res.status}`);
      return await res.json();
    } finally {
      clearTimeout(timer);
    }
  }

  async function dohWithFallback(primary, name, type) {
    const order = [primary, ...Object.keys(RESOLVERS).filter((k) => k !== primary)];
    let lastErr;
    for (const key of order) {
      try {
        const json = await dohFetch(key, name, type);
        return { json, resolver: key };
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr || new Error('Lookup failed');
  }

  /* ---------- Record data formatting ---------- */
  function txtValue(data) {
    const parts = [...String(data).matchAll(/"((?:[^"\\]|\\.)*)"/g)];
    if (!parts.length) return String(data);
    return parts.map((m) => m[1].replace(/\\(["\\])/g, '$1')).join('');
  }

  function genericHex(data) {
    const m = /^\\#\s+(\d+)\s*([0-9a-fA-F\s]*)$/.exec(String(data).trim());
    return m ? m[2].replace(/\s+/g, '').toLowerCase() : null;
  }

  function hexToText(hex) {
    let out = '';
    for (let i = 0; i + 1 < hex.length; i += 2) out += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
    return out;
  }

  function decodeTlsa(data) {
    const hex = genericHex(data);
    if (hex === null || hex.length < 6) return String(data);
    const u = parseInt(hex.slice(0, 2), 16);
    const s = parseInt(hex.slice(2, 4), 16);
    const m = parseInt(hex.slice(4, 6), 16);
    return `${u} ${s} ${m} ${hex.slice(6)}`;
  }

  function decodeCaa(data) {
    const hex = genericHex(data);
    if (hex === null || hex.length < 4) return String(data);
    const flags = parseInt(hex.slice(0, 2), 16);
    const tagLen = parseInt(hex.slice(2, 4), 16);
    const tag = hexToText(hex.slice(4, 4 + tagLen * 2));
    const value = hexToText(hex.slice(4 + tagLen * 2));
    return `${flags} ${tag} "${value}"`;
  }

  function formatData(def, raw) {
    if (def.id === 'TXT' || def.id === 'SPF') return txtValue(raw);
    if (def.id === 'TLSA') return decodeTlsa(raw);
    if (def.id === 'CAA') return decodeCaa(raw);
    return String(raw);
  }

  function tlsaHint(text) {
    const p = text.split(/\s+/);
    if (p.length < 4) return '';
    const [u, s, m] = p.map(Number);
    if (![u, s, m].every(Number.isInteger)) return '';
    return `${TLSA_USAGE[u] ?? 'usage ' + u} · ${TLSA_SELECTOR[s] ?? 'selector ' + s} · ${TLSA_MATCH[m] ?? 'match ' + m}`;
  }

  function spfTokens(text) {
    const tokens = text.trim().split(/\s+/).slice(1);
    let lookups = 0;
    const chips = tokens.map((t) => {
      const body = t.replace(/^[+\-~?]/, '').toLowerCase();
      if (/^(include|a|mx|ptr|exists|redirect)([:=\/]|$)/.test(body)) lookups++;
      let cls = '';
      if (t.startsWith('-')) cls = 'deny';
      else if (t.startsWith('~') || t.startsWith('?')) cls = 'soft';
      else if (/^(include|ip4|ip6|a|mx|redirect)/.test(body)) cls = 'allow';
      return h('span', { class: 'tok ' + cls }, t);
    });
    return { chips, lookups };
  }

  /* ---------- Rendering ---------- */
  function copyText(btn, text) {
    const done = () => {
      const old = btn.textContent;
      btn.textContent = 'Copied';
      setTimeout(() => { btn.textContent = old; }, 1200);
    };
    const fallback = () => {
      const ta = h('textarea', { style: 'position:fixed;opacity:0;top:0;left:0' });
      ta.value = text;
      document.body.append(ta);
      ta.select();
      try { document.execCommand('copy'); done(); } catch { /* ignore */ }
      ta.remove();
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, fallback);
    } else {
      fallback();
    }
  }

  function makeCard(def) {
    const body = h('div', { class: 'card-body' }, h('div', { class: 'msg spin' }, 'Looking up…'));
    const head = h('div', { class: 'card-head' },
      h('span', { class: 'rtype' }, def.id),
      h('span', { class: 'rdesc' }, def.desc),
    );
    const card = h('article', { class: 'card', 'data-type': def.id }, head, body);
    return { card, head, body };
  }

  function setBadge(head, text, cls) {
    head.querySelector('.badge')?.remove();
    head.append(h('span', { class: 'badge ' + cls }, text));
  }

  function fillCard(parts, def, result) {
    const { head, body } = parts;
    const { records, notes, rcode, ad, queryName, error } = result;

    if (def.tlsa) {
      head.querySelector('.qname')?.remove();
      head.append(h('div', { class: 'qname' }, queryName));
    }

    if (error) {
      setBadge(head, 'failed', 'bad');
      body.replaceChildren(h('div', { class: 'msg bad' }, error));
      return;
    }

    if (rcode !== 0) {
      setBadge(head, RCODES[rcode] ? `rcode ${rcode}` : `rcode ${rcode}`, 'bad');
      body.replaceChildren(h('div', { class: 'msg bad' }, RCODES[rcode] || `Resolver returned code ${rcode}`));
      return;
    }

    if (!records.length) {
      setBadge(head, 'none', '');
      const extra = notes.map((n) => h('div', { class: 'note' }, n));
      body.replaceChildren(h('div', { class: 'msg' }, 'No ' + def.id + ' records found.'), ...extra);
      return;
    }

    setBadge(head, `${records.length} record${records.length === 1 ? '' : 's'}${ad ? ' · DNSSEC verified' : ''}`, ad ? 'ok' : '');

    const rows = records.map((r) => {
      const cell = h('td', { class: 'data' }, r.text);
      if (def.id === 'TLSA') {
        const hint = tlsaHint(r.text);
        if (hint) cell.append(h('span', { class: 'sub' }, hint));
      }
      if (def.id === 'SPF') {
        const { chips, lookups } = spfTokens(r.text);
        cell.append(h('div', { class: 'tokens' }, chips));
        cell.append(h('span', { class: 'sub' }, `${lookups} DNS lookup${lookups === 1 ? '' : 's'} (limit is 10)`));
      }
      const btn = h('button', { type: 'button', class: 'copy', 'aria-label': 'Copy value' }, 'Copy');
      btn.addEventListener('click', () => copyText(btn, r.text));
      return h('tr', null,
        h('td', { class: 'nm' }, r.name),
        h('td', { class: 'ttl' }, formatTtl(r.ttl)),
        cell,
        h('td', { class: 'act' }, btn),
      );
    });

    const table = h('table', null,
      h('thead', null, h('tr', null,
        h('th', null, 'Name'), h('th', null, 'TTL'), h('th', null, 'Value'), h('th', { 'aria-label': 'Actions' }),
      )),
      h('tbody', null, rows),
    );
    body.replaceChildren(
      ...notes.map((n) => h('div', { class: 'note' }, n)),
      h('div', { class: 'scroll' }, table),
    );
  }

  function formatTtl(sec) {
    if (!Number.isFinite(sec)) return '';
    if (sec >= 86400 && sec % 86400 === 0) return `${sec / 86400}d`;
    if (sec >= 3600 && sec % 3600 === 0) return `${sec / 3600}h`;
    if (sec >= 60 && sec % 60 === 0) return `${sec / 60}m`;
    return `${sec}s`;
  }

  /* ---------- Lookup ---------- */
  function showError(msg) {
    els.error.textContent = msg;
    els.error.hidden = !msg;
  }

  async function runLookup() {
    showError('');
    const domain = normalizeDomain(els.domain.value);
    if (!domain) {
      showError('Enter a domain name such as example.com.');
      els.domain.focus();
      return;
    }
    const defs = RECORDS.filter((r) => selected.has(r.id));
    if (!defs.length) {
      showError('Pick at least one record type.');
      return;
    }

    const port = Math.min(65535, Math.max(1, parseInt(els.tlsaPort.value, 10) || 443));
    const proto = els.tlsaProto.value;
    const primary = els.resolver.value;
    const myRun = ++runId;
    const started = performance.now();

    els.domain.value = domain;
    try {
      const u = new URL(location.href);
      u.searchParams.set('d', domain);
      history.replaceState(null, '', u);
    } catch { /* file:// or sandboxed, ignore */ }

    els.go.disabled = true;
    els.go.textContent = 'Looking up…';
    els.summary.hidden = true;
    els.results.replaceChildren();

    const parts = new Map();
    for (const def of defs) {
      const p = makeCard(def);
      parts.set(def.id, p);
      els.results.append(p.card);
    }

    const cache = new Map();
    const usedResolvers = new Set();
    const exportData = { domain, queried_at: new Date().toISOString(), records: {} };
    let totalRecords = 0;
    let failures = 0;

    const tasks = defs.map(async (def) => {
      const queryName = def.tlsa ? `_${port}._${proto}.${domain}` : domain;
      const key = `${queryName}|${def.type}`;
      if (!cache.has(key)) cache.set(key, dohWithFallback(primary, queryName, def.type));

      let result;
      try {
        const { json, resolver } = await cache.get(key);
        usedResolvers.add(resolver);
        const answers = Array.isArray(json.Answer) ? json.Answer : [];
        const notes = [];

        const cnames = answers.filter((a) => a.type === 5);
        if (def.type !== 5 && cnames.length) {
          notes.push('Followed CNAME: ' + cnames.map((c) => `${c.name} → ${c.data}`).join(', '));
        }

        let records = answers
          .filter((a) => a.type === def.type)
          .map((a) => ({ name: a.name, ttl: a.TTL, text: formatData(def, a.data) }));
        if (def.filter) records = records.filter((r) => def.filter(r.text));

        result = { records, notes, rcode: json.Status ?? 0, ad: !!json.AD, queryName };
        if (result.rcode === 0) totalRecords += records.length;
        exportData.records[def.id] = records.map(({ name, ttl, text }) => ({ name, ttl, value: text }));
      } catch (err) {
        failures++;
        const aborted = err && err.name === 'AbortError';
        result = {
          error: aborted ? 'The resolver took too long to answer.' : 'Could not reach a DNS resolver. Check your connection and try again.',
          queryName,
        };
        exportData.records[def.id] = { error: result.error };
      }
      if (myRun === runId) fillCard(parts.get(def.id), def, result);
    });

    await Promise.all(tasks);
    if (myRun !== runId) return;

    const ms = Math.round(performance.now() - started);
    const via = [...usedResolvers].map((k) => RESOLVERS[k].label).join(' + ') || RESOLVERS[primary].label;
    lastExport = exportData;

    els.summaryText.replaceChildren(
      h('strong', null, domain),
      ` · ${totalRecords} record${totalRecords === 1 ? '' : 's'} across ${defs.length} type${defs.length === 1 ? '' : 's'} · via ${via} · ${ms} ms`,
    );
    els.summary.hidden = false;
    if (failures === defs.length) showError('Every lookup failed. The resolvers may be blocked on this network.');

    els.go.disabled = false;
    els.go.textContent = 'Look up';
  }

  els.form.addEventListener('submit', (e) => {
    e.preventDefault();
    runLookup();
  });

  els.copyJson.addEventListener('click', () => {
    if (lastExport) copyText(els.copyJson, JSON.stringify(lastExport, null, 2));
  });

  /* ---------- Boot ---------- */
  renderChips();
  try {
    const q = new URLSearchParams(location.search).get('d');
    if (q) {
      els.domain.value = q;
      runLookup();
    } else {
      runLookup();
    }
  } catch {
    runLookup();
  }
})();
