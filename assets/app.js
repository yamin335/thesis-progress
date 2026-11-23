/* Progress dashboard: reads data/manifest.json (written by experiments/publish_progress.py in the
   thesis repository) plus the CSV files it points to, and renders everything client-side.
   No build step, no tracking, no storage except the theme choice (and, if asked, the session key).

   Access protection: GitHub Pages cannot run a server, so the data is published ENCRYPTED under
   vault/<path>.enc (AES-256-GCM, nonce || ciphertext || tag). The login form derives the key from
   "user:password" with PBKDF2-SHA256 (salt and iteration count in vault/verify.json), checks it
   against a small verifier, and every fetch below then decrypts on the fly with Web Crypto. The
   credentials never leave the browser; a wrong password simply fails the authentication tag. */
(function () {
  'use strict';

  var MANIFEST_URL = 'data/manifest.json';
  var REFRESH_MS = 5 * 60 * 1000;
  var state = { manifest: null, charts: {}, csv: {}, generatedAt: null, key: null, blobUrls: {}, refreshTimer: null };
  var VERIFY_URL = 'vault/verify.json';
  var VERIFY_TEXT = 'thesis-progress ok';
  var SESSION_KEY = 'progress-session-key';
  var ARCH_COLORS = { yolov8n: '#2b6cb0', yolo11n: '#2e7d32', yolo26n: '#b7791f', yolo26s: '#b02a37' };
  var PALETTE = ['#2b6cb0', '#2e7d32', '#b7791f', '#b02a37', '#6b46c1', '#0e7490', '#9d174d', '#4d7c0f', '#92400e', '#1e40af'];

  // ------------------------------------------------------------------ small helpers
  function $(id) { return document.getElementById(id); }
  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (key) {
        if (key === 'class') { node.className = attrs[key]; }
        else if (key === 'html') { node.innerHTML = attrs[key]; }
        else if (key === 'text') { node.textContent = attrs[key]; }
        else if (key.indexOf('on') === 0) { node.addEventListener(key.slice(2), attrs[key]); }
        else if (attrs[key] === null || attrs[key] === undefined || attrs[key] === false) { /* absent attribute */ }
        else if (attrs[key] === true) { node.setAttribute(key, ''); }
        else { node.setAttribute(key, attrs[key]); }
      });
    }
    (children || []).forEach(function (child) {
      if (child === null || child === undefined) { return; }
      node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
    });
    return node;
  }
  function clear(node) {
    // A missing element (for example after a page/script version mismatch from a stale cache) must
    // not take the whole render down: return a detached container instead of throwing.
    if (!node) { return document.createElement('div'); }
    while (node.firstChild) { node.removeChild(node.firstChild); }
    return node;
  }
  function fmt(value, digits) {
    if (value === null || value === undefined || value === '') { return ''; }
    if (typeof value === 'number') {
      if (Number.isInteger(value)) { return value.toLocaleString('en-GB'); }
      return value.toFixed(digits === undefined ? 3 : digits);
    }
    return String(value);
  }
  function fmtDate(iso) {
    if (!iso) { return ''; }
    var d = new Date(iso);
    if (isNaN(d.getTime())) { return iso; }
    return d.toLocaleString('en-GB', { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
  }
  function daysUntil(iso) {
    if (!iso) { return null; }
    var target = new Date(iso + 'T23:59:59');
    return Math.ceil((target - new Date()) / 86400000);
  }
  function pill(text, kind, live) {
    return el('span', { class: 'pill ' + (kind || 'gray') + (live ? ' live' : ''), text: text });
  }
  function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
  function bust(url) { return url + (url.indexOf('?') < 0 ? '?' : '&') + 't=' + Date.now(); }
  // ------------------------------------------------------------------ vault (encrypted files)
  function bytesFromBase64(text) { var bin = atob(text); var out = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); } return out; }
  function base64FromBytes(bytes) { var bin = ''; for (var i = 0; i < bytes.length; i++) { bin += String.fromCharCode(bytes[i]); } return btoa(bin); }
  function hexToBytes(hex) { var out = new Uint8Array(hex.length / 2); for (var i = 0; i < out.length; i++) { out[i] = parseInt(hex.substr(i * 2, 2), 16); } return out; }
  function cryptoAvailable() { return !!(window.crypto && window.crypto.subtle && window.TextEncoder); }
  function deriveKeyBits(user, password, saltHex, iterations) {
    // Same derivation as experiments/publish_progress.py: PBKDF2-HMAC-SHA256 over "user:password".
    var material = new TextEncoder().encode(user + ':' + password);
    return crypto.subtle.importKey('raw', material, 'PBKDF2', false, ['deriveBits']).then(function (base) {
      return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: hexToBytes(saltHex), iterations: iterations }, base, 256);
    });
  }
  function importAesKey(rawBits) { return crypto.subtle.importKey('raw', rawBits, { name: 'AES-GCM' }, false, ['decrypt']); }
  function decryptBuffer(buffer) {
    var bytes = new Uint8Array(buffer);
    if (bytes.length < 28) { return Promise.reject(new Error('ciphertext too short')); }
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12), tagLength: 128 }, state.key, bytes.slice(12));
  }
  function rawFetch(url) { return fetch(bust(url), { cache: 'no-store' }).then(function (r) { if (!r.ok) { throw new Error(r.status + ' ' + url); } return r; }); }
  function vaultFetch(path) {
    // path is the plaintext path the manifest uses (data/..., figures/...); the file lives at vault/<path>.enc
    return rawFetch('vault/' + path + '.enc').then(function (r) { return r.arrayBuffer(); }).then(decryptBuffer);
  }
  function fetchText(url) { return vaultFetch(url).then(function (buf) { return new TextDecoder().decode(buf); }); }
  function fetchJSON(url) { return fetchText(url).then(function (text) { return JSON.parse(text); }); }
  function vaultImage(path) {
    if (state.blobUrls[path]) { return Promise.resolve(state.blobUrls[path]); }
    return vaultFetch(path).then(function (buf) {
      var url = URL.createObjectURL(new Blob([buf], { type: 'image/png' }));
      state.blobUrls[path] = url;
      return url;
    });
  }
  function downloadDecrypted(path) {
    fetchText(path).then(function (text) {
      var type = /\.json$/i.test(path) ? 'application/json' : (/\.md$/i.test(path) ? 'text/markdown' : 'text/csv');
      var url = URL.createObjectURL(new Blob([text], { type: type }));
      var a = el('a', { href: url, download: path.split('/').pop() });
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
    }).catch(function (err) { alert('Download failed: ' + err.message); });
  }
  function fetchCSV(url) {
    return fetchText(url).then(function (text) {
      var parsed = Papa.parse(text.trim(), { header: true, dynamicTyping: true, skipEmptyLines: true, transformHeader: function (h) { return h.trim(); } });
      return parsed.data;
    });
  }
  function groupSum(rows, keyCol, valueCol) {
    var out = {};
    rows.forEach(function (row) {
      var key = row[keyCol];
      if (key === undefined || key === null || key === '') { return; }
      var value = valueCol ? Number(row[valueCol]) || 0 : 1;
      out[key] = (out[key] || 0) + value;
    });
    return out;
  }
  function meanStd(values) {
    if (!values.length) { return { mean: null, std: null }; }
    var mean = values.reduce(function (a, b) { return a + b; }, 0) / values.length;
    var variance = values.reduce(function (a, b) { return a + (b - mean) * (b - mean); }, 0) / values.length;
    return { mean: mean, std: Math.sqrt(variance) };
  }

  // ------------------------------------------------------------------ charts
  function chartDefaults() {
    if (!window.Chart) { return; }
    Chart.defaults.color = cssVar('--muted') || '#5b6672';
    Chart.defaults.borderColor = cssVar('--line') || '#dde2e8';
    Chart.defaults.font.family = cssVar('--font') || 'system-ui, sans-serif';
    Chart.defaults.font.size = 12;
    Chart.defaults.plugins.legend.labels.boxWidth = 12;
    Chart.defaults.maintainAspectRatio = false;
  }
  function makeChart(target, config) {
    // target: a canvas element or the id of one. Charts are registered by id so a re-render
    // destroys the previous instance instead of stacking two on the same canvas.
    var canvas = typeof target === 'string' ? $(target) : target;
    if (!canvas || !window.Chart) { return null; }
    var id = canvas.id || ('chart-' + Math.random().toString(36).slice(2));
    if (state.charts[id]) { state.charts[id].destroy(); }
    state.charts[id] = new Chart(canvas.getContext('2d'), config);
    return state.charts[id];
  }
  function barChart(id, labels, datasets, options) {
    var opts = options || {};
    return makeChart(id, {
      type: 'bar',
      data: { labels: labels, datasets: datasets },
      options: {
        responsive: true,
        indexAxis: opts.horizontal ? 'y' : 'x',
        plugins: { legend: { display: datasets.length > 1 || !!opts.legend } },
        scales: opts.horizontal ? {
          y: { stacked: !!opts.stacked, grid: { display: false }, ticks: { autoSkip: false } },
          x: { stacked: !!opts.stacked, beginAtZero: true, title: { display: !!opts.yTitle, text: opts.yTitle || '' } }
        } : {
          x: { stacked: !!opts.stacked, grid: { display: false } },
          y: { stacked: !!opts.stacked, beginAtZero: true, title: { display: !!opts.yTitle, text: opts.yTitle || '' } }
        }
      }
    });
  }
  function specChart(canvas, spec) {
    // A bar chart described by the publisher next to a readable table: {labels, datasets[{label,
    // data}], y_title, y_max, stacked}. Many or long labels are drawn as horizontal bars so the
    // names stay readable; the caller sizes the canvas wrapper with specChartHeight().
    var horizontal = specChartHorizontal(spec);
    var value = { stacked: !!spec.stacked, beginAtZero: true, title: { display: !!spec.y_title, text: spec.y_title || '' } };
    if (typeof spec.y_max === 'number') { value.max = spec.y_max; }
    var category = { stacked: !!spec.stacked, grid: { display: false }, ticks: { autoSkip: false } };
    return makeChart(canvas, {
      type: 'bar',
      data: { labels: spec.labels, datasets: spec.datasets.map(function (d, i) { return { label: d.label, data: d.data, backgroundColor: PALETTE[i % PALETTE.length] }; }) },
      options: { responsive: true, indexAxis: horizontal ? 'y' : 'x', plugins: { legend: { display: spec.datasets.length > 1 } }, scales: horizontal ? { x: value, y: category } : { x: category, y: value } }
    });
  }
  function specChartHorizontal(spec) {
    var longest = spec.labels.reduce(function (acc, l) { return Math.max(acc, String(l).length); }, 0);
    return spec.labels.length > 6 || longest > 14;
  }
  function specChartHeight(spec) {
    if (!specChartHorizontal(spec)) { return 260; }
    var perLabel = spec.stacked ? 22 : 9 + 11 * spec.datasets.length;
    return Math.max(200, 70 + spec.labels.length * perLabel);
  }
  function emptyChart(id, message) {
    var canvas = $(id);
    if (!canvas) { return; }
    if (state.charts[id]) { state.charts[id].destroy(); delete state.charts[id]; }
    var wrap = canvas.parentNode;
    var note = wrap.querySelector('.empty');
    if (!note) { note = el('div', { class: 'empty small' }); wrap.appendChild(note); }
    note.textContent = message;
    canvas.classList.add('hidden');
  }
  function showCanvas(id) {
    var canvas = $(id);
    if (!canvas) { return; }
    canvas.classList.remove('hidden');
    var note = canvas.parentNode.querySelector('.empty');
    if (note) { note.parentNode.removeChild(note); }
  }

  // ------------------------------------------------------------------ generic table
  function makeTable(rows, columns, options) {
    var opts = options || {};
    var cols = columns || (rows.length ? Object.keys(rows[0]) : []);
    var wrapper = el('div');
    var tools = el('div', { class: 'table-tools' });
    var filter = el('input', { type: 'search', placeholder: 'Filter rows…', 'aria-label': 'Filter rows' });
    var count = el('span', { class: 'muted small' });
    tools.appendChild(filter);
    tools.appendChild(count);
    if (opts.plain) { tools.classList.add('hidden'); }
    if (opts.download) {
      tools.appendChild(el('a', { href: '#', class: 'small', onclick: function (e) { e.preventDefault(); downloadDecrypted(opts.download); } }, ['Download CSV']));
    }
    wrapper.appendChild(tools);
    var wrap = el('div', { class: 'table-wrap' + (opts.readable && rows.length <= 40 ? ' full' : '') });
    var table = el('table', { class: 'data' + (opts.readable ? ' readable' : '') });
    var thead = el('thead');
    var tbody = el('tbody');
    table.appendChild(thead);
    table.appendChild(tbody);
    wrap.appendChild(table);
    wrapper.appendChild(wrap);
    var sortCol = opts.sort || null;
    var sortDesc = !!opts.desc;
    var numeric = {};
    cols.forEach(function (col) {
      numeric[col] = rows.length > 0 && rows.every(function (r) { return r[col] === '' || r[col] === null || r[col] === undefined || typeof r[col] === 'number'; });
    });
    // readable tables: one number of decimals per column (as many as the values carry, at most 3)
    var decimals = {};
    if (opts.readable) {
      cols.forEach(function (col) {
        if (!numeric[col]) { return; }
        decimals[col] = rows.reduce(function (acc, r) {
          var v = r[col];
          if (typeof v !== 'number' || Number.isInteger(v)) { return acc; }
          var text = String(Math.round(v * 1000) / 1000);
          return Math.max(acc, text.indexOf('.') < 0 ? 0 : text.length - text.indexOf('.') - 1);
        }, 0);
      });
    }
    function render() {
      var needle = filter.value.trim().toLowerCase();
      var shown = rows.filter(function (row) {
        if (!needle) { return true; }
        return cols.some(function (col) { return String(row[col] === null || row[col] === undefined ? '' : row[col]).toLowerCase().indexOf(needle) >= 0; });
      });
      if (sortCol) {
        shown = shown.slice().sort(function (a, b) {
          var x = a[sortCol], y = b[sortCol];
          if (x === y) { return 0; }
          if (x === null || x === undefined || x === '') { return 1; }
          if (y === null || y === undefined || y === '') { return -1; }
          var cmp = (typeof x === 'number' && typeof y === 'number') ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true });
          return sortDesc ? -cmp : cmp;
        });
      }
      clear(thead);
      var tr = el('tr');
      cols.forEach(function (col) {
        var th = el('th', { text: (opts.labels && opts.labels[col]) || col, class: col === sortCol ? 'sorted' + (sortDesc ? ' desc' : '') : '' });
        th.addEventListener('click', function () {
          if (sortCol === col) { sortDesc = !sortDesc; } else { sortCol = col; sortDesc = numeric[col]; }
          render();
        });
        tr.appendChild(th);
      });
      thead.appendChild(tr);
      clear(tbody);
      var limit = opts.limit || 1000;
      shown.slice(0, limit).forEach(function (row) {
        var r = el('tr');
        cols.forEach(function (col) {
          var value = row[col];
          var wraps = opts.readable ? (typeof value === 'string' && value.length > 30) : (opts.wrap || []).indexOf(col) >= 0;
          var cell = el('td', { class: numeric[col] ? 'num' : (wraps ? 'wrap' : '') });
          if (opts.render && opts.render[col]) { cell.appendChild(opts.render[col](value, row)); }
          else if (opts.readable && typeof value === 'number' && decimals[col] > 0) { cell.textContent = value.toFixed(decimals[col]); }
          else { cell.textContent = fmt(value, opts.digits); }
          r.appendChild(cell);
        });
        tbody.appendChild(r);
      });
      count.textContent = shown.length === rows.length ? rows.length + ' rows' : shown.length + ' of ' + rows.length + ' rows';
    }
    filter.addEventListener('input', render);
    render();
    return wrapper;
  }

  // ------------------------------------------------------------------ sections
  function renderHeader(m) {
    var repo = m.repo || {};
    var stamp = $('stamp');
    clear(stamp);
    stamp.appendChild(el('span', { html: 'Last published <strong>' + fmtDate(m.generated_at) + '</strong>' }));
    if (repo.short) {
      stamp.appendChild(document.createTextNode(' · thesis commit '));
      stamp.appendChild(el('code', { text: repo.short }));
      if (repo.dirty) { stamp.appendChild(document.createTextNode(' + uncommitted work')); }
    }
    if (m.training && m.training.running) {
      stamp.appendChild(document.createTextNode(' '));
      stamp.appendChild(pill('training running', 'warn', true));
    }
    if (m.thesis_title) { $('thesis-title').textContent = m.thesis_title; }
  }

  function renderOverview(m) {
    var cards = clear($('overview-cards'));
    var plan = m.plan || {};
    var allItems = (plan.phases || []).reduce(function (acc, p) { return acc.concat(p.items || []); }, []);
    var done = allItems.filter(function (i) { return i.done; }).length;
    var cutoff = daysUntil(plan.technical_cutoff);
    var deadline = daysUntil(plan.deadline);
    var ds = m.dataset || {};
    var total = (ds.splits || []).filter(function (s) { return s.split === 'total'; })[0] || {};
    var tr = m.training || {};
    var doneRuns = (tr.runs || []).filter(function (r) { return r.status === 'done'; }).length;
    var runningRuns = (tr.runs || []).filter(function (r) { return r.status === 'running'; }).length;
    var exps = (m.experiments && m.experiments.experiments) || [];
    var expDone = exps.filter(function (e) { return e.status === 'done'; }).length;

    function card(title, big, small, sub, extra) {
      var c = el('div', { class: 'card' }, [el('h3', { text: title })]);
      var b = el('div', { class: 'big' }, [document.createTextNode(big)]);
      if (small) { b.appendChild(el('small', { text: small })); }
      c.appendChild(b);
      if (sub) { c.appendChild(el('div', { class: 'sub', text: sub })); }
      if (extra) { c.appendChild(extra); }
      return c;
    }
    var pct = allItems.length ? Math.round(100 * done / allItems.length) : 0;
    cards.appendChild(card('Plan items done', done + ' / ' + allItems.length, pct + ' %', 'across ' + (plan.phases || []).length + ' phases',
      el('div', { class: 'bar' }, [el('span', { style: 'width:' + pct + '%' })])));
    cards.appendChild(card('Technical cut-off', cutoff === null ? '–' : (cutoff >= 0 ? cutoff + ' days' : 'passed'), '', plan.technical_cutoff ? 'all measurements frozen on ' + plan.technical_cutoff : ''));
    cards.appendChild(card('Submission deadline', deadline === null ? '–' : (deadline >= 0 ? deadline + ' days' : 'passed'), '', plan.deadline ? 'thesis due ' + plan.deadline : ''));
    cards.appendChild(card('Synthetic dataset kt_v1', total.frames ? fmt(total.frames) : '–', total.frames ? 'frames' : '', total.boxes ? fmt(total.boxes) + ' labelled boxes in ' + total.runs + ' runs' : 'not exported yet'));
    var trainingSub;
    var stageText = (tr.stages || []).map(function (s) { return s.id + ' ' + s.done + '/' + s.planned; }).join(', ');
    trainingSub = (runningRuns ? runningRuns + ' running now \u00b7 ' : '') + stageText;
    cards.appendChild(card('Training runs', doneRuns + ' / ' + (tr.planned_runs || 12), 'done', trainingSub,
      el('div', { class: 'bar ok' }, [el('span', { style: 'width:' + (tr.planned_runs ? Math.round(100 * doneRuns / tr.planned_runs) : 0) + '%' })])));
    var expSkipped = exps.filter(function (e) { return e.status === 'not_carried_out'; }).length;
    var expLive = exps.filter(function (e) { return e.status === 'results' || e.status === 'running' || e.status === 'started'; }).length;
    cards.appendChild(card('Experiments done', expDone + ' / ' + exps.length, '', (expLive ? expLive + ' in progress' : 'none in progress') + (expSkipped ? ' \u00b7 ' + expSkipped + ' not carried out (real footage, future work)' : '') + (exps.length ? ' \u00b7 ' + exps[0].id + ' to ' + exps[exps.length - 1].id : '')));

    var statusCard = clear($('status-card'));
    statusCard.appendChild(el('h3', { text: 'Current status' }));
    if (m.notes_status && m.notes_status.length) {
      var dl = el('dl', { class: 'kv' });
      m.notes_status.forEach(function (item) {
        dl.appendChild(el('dt', { text: item.key }));
        dl.appendChild(el('dd', { html: linkify(item.value) }));
      });
      statusCard.appendChild(dl);
    }
    // The status line of the plan document is a hand-off note between work sessions (file paths,
    // open steps); the curated status above is what a reader needs, so the line is not shown.
  }
  function linkify(text) {
    var escaped = String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return escaped.replace(/(https?:\/\/[^\s)]+)/g, '<a href="$1" target="_blank" rel="noopener">$1</a>');
  }

  function renderTimeline(m) {
    var list = clear($('timeline-list'));
    (m.timeline || []).forEach(function (entry) {
      list.appendChild(el('li', null, [el('time', { text: entry.date }), el('span', { html: linkify(entry.text) })]));
    });
    if (!list.children.length) { list.appendChild(el('li', { class: 'muted', text: 'No entries yet.' })); }
  }

  function renderPlan(m) {
    var box = clear($('phase-list'));
    (m.plan.phases || []).forEach(function (phase, index) {
      var pct = phase.total ? Math.round(100 * phase.done / phase.total) : 0;
      var details = el('details', { class: 'phase', open: index === 0 });
      var summary = el('summary', null, [
        el('strong', { text: phase.title }),
        el('span', { class: 'small muted', text: phase.done + ' / ' + phase.total + ' done' }),
        el('div', { class: 'bar' + (pct === 100 ? ' ok' : '') }, [el('span', { style: 'width:' + pct + '%' })])
      ]);
      details.appendChild(summary);
      var ul = el('ul');
      phase.items.forEach(function (item) { ul.appendChild(el('li', { class: item.done ? 'done' : '', text: item.text })); });
      details.appendChild(ul);
      box.appendChild(details);
    });
  }

  function renderData(m) {
    var cards = clear($('data-cards'));
    var ds = m.dataset || {};
    var mx = m.matrix || {};
    (ds.splits || []).forEach(function (s) {
      cards.appendChild(el('div', { class: 'card' }, [
        el('h3', { text: s.split === 'total' ? 'All splits' : s.split + ' split' }),
        el('div', { class: 'big' }, [document.createTextNode(fmt(s.frames)), el('small', { text: 'frames' })]),
        el('div', { class: 'sub', text: fmt(s.boxes) + ' boxes · ' + s.runs + ' runs' })
      ]));
    });
    if (mx.present) {
      var statusText = Object.keys(mx.by_status || {}).map(function (k) { return mx.by_status[k] + ' ' + k; }).join(', ');
      cards.appendChild(el('div', { class: 'card' }, [
        el('h3', { text: 'Capture matrix' }),
        el('div', { class: 'big' }, [document.createTextNode(mx.runs), el('small', { text: 'runs' })]),
        el('div', { class: 'sub', text: statusText + ' · ' + fmt(mx.frames_on_disk) + ' frames on disk' })
      ]));
    }
    // charts from manifest
    var splits = (ds.splits || []).filter(function (s) { return s.split !== 'total'; });
    if (splits.length) {
      showCanvas('chart-splits');
      makeChart('chart-splits', { type: 'doughnut', data: { labels: splits.map(function (s) { return s.split; }), datasets: [{ data: splits.map(function (s) { return s.frames; }), backgroundColor: PALETTE.slice(0, splits.length) }] }, options: { plugins: { legend: { position: 'right' } }, cutout: '55%' } });
    } else { emptyChart('chart-splits', 'Dataset not exported yet.'); }
    renderDatasets(m);

    var matrixBox = clear($('matrix-table'));
    if (mx.present && mx.csv) {
      fetchCSV(mx.csv).then(function (rows) {
        state.csv.matrix = rows;
        var weather = groupSum(rows, 'weather', 'frames_on_disk');
        var views = groupSum(rows, 'view', 'frames_on_disk');
        showCanvas('chart-weather');
        barChart('chart-weather', Object.keys(weather), [{ label: 'frames', data: Object.keys(weather).map(function (k) { return weather[k]; }), backgroundColor: PALETTE[0] }], { yTitle: 'frames' });
        showCanvas('chart-views');
        barChart('chart-views', Object.keys(views), [{ label: 'frames', data: Object.keys(views).map(function (k) { return views[k]; }), backgroundColor: PALETTE[1] }], { yTitle: 'frames' });
        matrixBox.appendChild(makeTable(rows, ['run', 'kind', 'view', 'axis', 'weather', 'traffic', 'fill', 'seed', 'split', 'frames_on_disk', 'status'], {
          sort: 'run', download: mx.csv,
          render: { status: function (v) { return pill(String(v), v === 'done' ? 'ok' : (v === 'failed' ? 'bad' : 'warn')); } }
        }));
      }).catch(function (err) { matrixBox.appendChild(el('div', { class: 'empty', text: 'Could not load the capture matrix: ' + err.message })); });
    } else {
      matrixBox.appendChild(el('div', { class: 'empty', text: 'No capture matrix yet.' }));
      emptyChart('chart-weather', 'No capture matrix yet.');
      emptyChart('chart-views', 'No capture matrix yet.');
    }
    var card = clear($('dataset-card'));
    if (ds.manifest_md && window.marked) {
      fetchText(ds.manifest_md).then(function (md) { card.innerHTML = marked.parse(md); }).catch(function () { card.textContent = 'Dataset card not available.'; });
    } else { card.textContent = 'Dataset card not available.'; }
  }

  function renderDatasets(m) {
    // One card per dataset (kt_v1, kt_v1p, kt_v2p): what it is, a table of frames and boxes per
    // split and class counted from the label files, and the boxes per class as a stacked chart.
    var box = clear($('dataset-cards'));
    var list = m.datasets || [];
    if (!list.length) { box.appendChild(el('div', { class: 'empty', text: 'No dataset exported yet.' })); return; }
    list.forEach(function (ds) {
      var classIds = Object.keys(ds.classes || {});
      var hasNew = ds.new_runs > 0;
      var rows = (ds.splits || []).concat([ds.total]).map(function (sp) {
        var row = { Split: sp.split === 'total' ? 'all splits' : sp.split, Runs: sp.runs, Frames: sp.frames, Boxes: sp.boxes };
        classIds.forEach(function (cid) { row[ds.classes[cid]] = (sp.per_class || {})[cid] || 0; });
        if (hasNew) {
          row['New runs'] = sp.new_runs;
          row['Frames of the new runs'] = sp.new_frames;
          row['Share of the frames'] = sp.frames ? (100 * sp.new_frames / sp.frames).toFixed(1) + ' %' : '';
        }
        return row;
      });
      var card = el('div', { class: 'card' }, [el('h3', { text: ds.title })]);
      card.appendChild(el('p', { class: 'small muted', text: ds.note + ' Columns: runs and frames per split, boxes in all, then the boxes of each class' + (hasNew ? ', then how many runs and frames of the split come from the ' + ds.new_runs + ' new runs' : '') + '. Counted from the label files.' }));
      var canvas = el('canvas', { id: 'chart-dataset-' + ds.name });
      var inner = el('div', { class: 'dataset-grid' }, [
        el('div', null, [makeTable(rows, null, { plain: true, readable: true })]),
        el('div', { class: 'chart short' }, [canvas])
      ]);
      card.appendChild(inner);
      box.appendChild(card);
      var splitNames = (ds.splits || []).map(function (sp) { return sp.split; });
      barChart(canvas, splitNames, classIds.map(function (cid, i) {
        return { label: ds.classes[cid], data: (ds.splits || []).map(function (sp) { return (sp.per_class || {})[cid] || 0; }), backgroundColor: PALETTE[i % PALETTE.length] };
      }), { stacked: true, legend: true, yTitle: 'boxes' });
    });
  }

  function renderTraining(m) {
    var tr = m.training || { runs: [] };
    var stagesBox = clear($('training-stages'));
    var ladder = tr.ladder || { stages: [] };
    if (ladder.stages.length) {
      var card = el('div', { class: 'card' }, [el('h3', { text: 'Training stages (sim-to-real ladder)' })]);
      card.appendChild(makeTable(ladder.stages, ['stage', 'data', 'purpose', 'status', 'detail'], {
        wrap: ['data', 'purpose', 'detail'], labels: { data: 'training data' }, plain: true,
        render: { status: function (v) { return statusPill(v); } }
      }));
      card.appendChild(el('p', { class: 'small muted', style: 'margin:0.5rem 0 0', text: 'The ladder is the plan made before the work. S2 and S3 need real footage and were not carried out. The training rounds that were run are listed below, one block per stage.' }));
      stagesBox.appendChild(card);
    }
    // One block per training stage. The stages use different datasets and validation sets, so
    // each gets its own explanation, table and curve chart, and figures are never pooled across stages.
    var box = clear($('training-stage-cards'));
    var runs = tr.runs || [];
    var stages = tr.stages || [];
    if (!stages.length) {
      box.appendChild(el('div', { class: 'empty', text: 'No training run has started yet.' }));
      $('training-log-wrap').classList.add('hidden');
      populateMetricSelect([]);
      return;
    }
    stages.forEach(function (stage) {
      var members = runs.filter(function (r) { return r.stage === stage.id; });
      var head = el('h3', null, [document.createTextNode(stage.title), statusPill(stage.status)]);
      var card = el('div', { class: 'card stage', id: 'stage-' + stage.id }, [head]);
      var counts = stage.done + ' of ' + stage.planned + ' runs finished' + (stage.running ? ', ' + stage.running + ' running' : '') + (stage.queued ? ', ' + stage.queued + ' queued' : '');
      if (stage.note) { card.appendChild(el('p', { class: 'small', text: stage.note })); }
      if (stage.validation) { card.appendChild(el('p', { class: 'small muted', text: stage.validation })); }
      card.appendChild(el('p', { class: 'small muted', text: 'Dataset ' + stage.dataset + ' \u00b7 ' + counts + (stage.recipe ? ' \u00b7 recipe: ' + stage.recipe : '') + '.' }));
      if (stage.per_arch && stage.per_arch.length) {
        var pmText = function (mean, std, n) { return typeof mean === 'number' ? mean.toFixed(3) + (n > 1 ? ' \u00b1 ' + std.toFixed(3) : '') : ''; };
        var archRows = stage.per_arch.map(function (a) {
          var row = { Architecture: a.arch, 'Finished runs': a.runs, 'Best val mAP50-95, mean \u00b1 std over seeds': pmText(a.map50_95_mean, a.map50_95_std, a.runs), 'Val mAP50 at the best epoch, mean \u00b1 std': pmText(a.map50_mean, a.map50_std, a.runs) };
          // the run with the best validation mAP50-95 (tested in the app as an alternative, not adopted; seed 0 is in use)
          if (stage.per_arch.some(function (x) { return typeof x.chosen_seed === 'number'; })) {
            row['Best on validation'] = typeof a.chosen_seed === 'number' ? 'seed ' + a.chosen_seed + (typeof a.chosen_map50_95 === 'number' ? ' (' + a.chosen_map50_95.toFixed(4) + ')' : '') : '';
          }
          return row;
        });
        card.appendChild(makeTable(archRows, null, { plain: true, readable: true }));
      }
      var withApp = members.some(function (r) { return typeof r.chosen === 'boolean'; });
      var rows = members.map(function (r) {
        var row = { Run: r.name, Seed: r.seed, Status: r.status };
        if (withApp) { row['In the app'] = r.app || ''; }
        return Object.assign(row, { 'Continued from': r.start_from || '', 'Epochs finished': r.epochs_done || '', 'Best epoch': r.best_epoch, 'Best val mAP50-95': r.best_map50_95, 'Val mAP50 at the best epoch': r.best_map50, Minutes: r.minutes, Updated: r.updated || '' });
      });
      card.appendChild(makeTable(rows, null, {
        sort: 'Run', readable: true, plain: rows.length <= 8,
        render: {
          'In the app': function (v) { return v ? pill(v, /^in use/.test(v) ? 'accent' : 'gray') : document.createTextNode(''); },
          Status: function (v) { return v === 'done' || v === 'running' ? valuePill(v) : statusPill(v); },
          Updated: function (v) { return document.createTextNode(fmtDate(v)); }
        }
      }));
      if (members.some(function (r) { return r.files && r.files.results; })) {
        card.appendChild(el('p', { class: 'small chart-title', text: 'Validation curve per epoch (metric chosen above)' }));
        card.appendChild(el('div', { class: 'chart' }, [el('canvas', { id: 'chart-training-' + stage.id })]));
      }
      box.appendChild(card);
    });
    var withCsv = runs.filter(function (r) { return r.files && r.files.results; });
    Promise.all(withCsv.map(function (r) { return fetchCSV(r.files.results).then(function (rows) { return { run: r, rows: rows }; }).catch(function () { return null; }); })).then(function (loaded) {
      state.csv.training = loaded.filter(Boolean);
      var metrics = {};
      state.csv.training.forEach(function (item) { if (item.rows.length) { Object.keys(item.rows[0]).forEach(function (k) { if (k !== 'epoch' && k !== 'time' && typeof item.rows[0][k] === 'number') { metrics[k] = true; } }); } });
      populateMetricSelect(Object.keys(metrics));
      drawTrainingCurves();
    });
    var logWrap = $('training-log-wrap');
    if (tr.log_tail) {
      logWrap.classList.remove('hidden');
      fetchText(tr.log_tail).then(function (text) { $('training-log').textContent = (tr.log_name ? 'Last lines of ' + tr.log_name + '\n\n' : '') + text; }).catch(function () { logWrap.classList.add('hidden'); });
    } else { logWrap.classList.add('hidden'); }
  }
  function populateMetricSelect(metrics) {
    var select = $('training-metric');
    var current = select.value;
    clear(select);
    var preferred = ['metrics/mAP50-95(B)', 'metrics/mAP50(B)', 'metrics/precision(B)', 'metrics/recall(B)', 'val/box_loss', 'val/cls_loss', 'train/box_loss', 'train/cls_loss'];
    var ordered = preferred.filter(function (p) { return metrics.indexOf(p) >= 0; }).concat(metrics.filter(function (k) { return preferred.indexOf(k) < 0; }));
    ordered.forEach(function (k) { select.appendChild(el('option', { value: k, text: k })); });
    if (ordered.indexOf(current) >= 0) { select.value = current; }
    select.onchange = drawTrainingCurves;
  }
  function drawTrainingCurves() {
    // One line chart per stage. A stage with several architectures colours by architecture and
    // dashes by seed, a stage with one architecture colours by seed.
    var metric = $('training-metric').value;
    var items = state.csv.training || [];
    var stages = (state.manifest.training || {}).stages || [];
    stages.forEach(function (stage) {
      var canvas = $('chart-training-' + stage.id);
      var own = items.filter(function (item) { return item.run.stage === stage.id; });
      if (!canvas || !own.length || !metric) { return; }
      var archs = {}; own.forEach(function (item) { archs[item.run.arch] = 1; });
      var byArch = Object.keys(archs).length > 1;
      var maxEpoch = 0;
      var datasets = own.map(function (item) {
        var pts = item.rows.map(function (row) { maxEpoch = Math.max(maxEpoch, Number(row.epoch) || 0); return { x: Number(row.epoch), y: typeof row[metric] === 'number' ? row[metric] : null }; });
        var seed = item.run.seed || 0;
        var colour = byArch ? (ARCH_COLORS[item.run.arch] || PALETTE[5]) : PALETTE[seed % PALETTE.length];
        return { label: item.run.name + (item.run.status === 'running' ? ' (running)' : ''), data: pts, borderColor: colour, backgroundColor: 'transparent', borderDash: byArch ? (seed === 1 ? [6, 3] : (seed === 2 ? [2, 3] : [])) : [], pointRadius: 0, borderWidth: 1.8, tension: 0.15, spanGaps: true };
      });
      makeChart(canvas, { type: 'line', data: { datasets: datasets }, options: { responsive: true, parsing: false, interaction: { mode: 'nearest', intersect: false }, plugins: { legend: { position: 'bottom' } }, scales: { x: { type: 'linear', title: { display: true, text: 'epoch' }, min: 1, max: Math.max(maxEpoch, 2) }, y: { title: { display: true, text: metric } } } } });
    });
  }

  // ------------------------------------------------------------------ JSON view
  // Renders any JSON value as nested, expandable items: objects and arrays of objects become
  // <details> blocks (arrays of uniform objects become a table), scalars and short arrays
  // stay inline. Used for result records and every JSON file that has no dedicated view.
  function isPlainObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
  function uniformObjects(arr) {
    if (!arr.length || arr.length > 500 || !arr.every(isPlainObject)) { return false; }
    var keys = Object.keys(arr[0]);
    if (!keys.length || keys.length > 40) { return false; }
    return arr.every(function (o) { return Object.keys(o).every(function (k) { return !isPlainObject(o[k]) && !Array.isArray(o[k]); }); });
  }
  function scalarText(v) {
    if (v === null) { return 'null'; }
    if (typeof v === 'number') { return fmt(v, 4); }
    if (typeof v === 'boolean') { return v ? 'true' : 'false'; }
    return String(v);
  }
  function jsonView(value, label, depth) {
    depth = depth || 0;
    if (Array.isArray(value)) {
      if (value.every(function (v) { return !isPlainObject(v) && !Array.isArray(v); })) {
        var shown = value.slice(0, 24).map(scalarText).join(', ') + (value.length > 24 ? ', … (' + value.length + ' items)' : '');
        return el('div', { class: 'json-leaf' }, [el('span', { class: 'json-key', text: label }), el('span', { class: 'json-val', text: '[' + shown + ']' })]);
      }
      var det = el('details', { class: 'json', open: depth === 0 }, [el('summary', null, [el('span', { class: 'json-key', text: label }), el('span', { class: 'muted small', text: ' list of ' + value.length })])]);
      if (uniformObjects(value)) {
        det.appendChild(makeTable(value, null, { limit: 500 }));
      } else {
        value.forEach(function (v, i) { det.appendChild(jsonView(v, '[' + i + ']', depth + 1)); });
      }
      return det;
    }
    if (isPlainObject(value)) {
      var keys = Object.keys(value);
      var block = el('details', { class: 'json', open: depth === 0 }, [el('summary', null, [el('span', { class: 'json-key', text: label }), el('span', { class: 'muted small', text: ' ' + keys.length + ' fields' })])]);
      keys.forEach(function (k) { block.appendChild(jsonView(value[k], k, depth + 1)); });
      return block;
    }
    return el('div', { class: 'json-leaf' }, [el('span', { class: 'json-key', text: label }), el('span', { class: 'json-val', text: scalarText(value) })]);
  }
  function jsonRoot(obj) {
    var box = el('div', { class: 'json-root' });
    if (isPlainObject(obj)) { Object.keys(obj).forEach(function (k) { box.appendChild(jsonView(obj[k], k, 1)); }); }
    else { box.appendChild(jsonView(obj, 'value', 0)); }
    return box;
  }

  // ------------------------------------------------------------------ experiment summaries
  // exp_*_summary.json files written by experiments/plot_exp_*.py share one shape: a list of
  // "cells", each with a grouping key (view), a row key (model), a column key (size) and per
  // metric {mean, std, ci95_runs}. That shape gets pivot tables and grouped bar charts; any
  // other summary falls back to the JSON view.
  function renderCellSummary(summary, idPrefix, mount) {
    // axes: which cell keys form the panel (group), the table rows and the columns; the
    // default is the model-by-input-size layout of EXP-A, EXP-B uses run-by-t_parked.
    var axes = summary.axes || {};
    var GROUP = axes.group || 'view', ROW = axes.row || 'model', COL = axes.col || 'size', UNIT = axes.col_unit === undefined ? ' px' : axes.col_unit;
    var cells = summary.cells;
    var metrics = Object.keys(cells[0]).filter(function (k) { return isPlainObject(cells[0][k]) && 'mean' in cells[0][k]; });
    // what stands behind a mean in the tables: the publisher's own words (axes.stat), an interval
    // when the cells carry one (its meaning is in the line beside the metric), else nothing
    var hasInterval = cells.some(function (c) { return metrics.some(function (mt) { return c[mt] && c[mt].ci95_runs; }); });
    var statLabel = axes.stat || (hasInterval ? 'mean [interval]' : 'mean');
    var views = []; cells.forEach(function (c) { if (views.indexOf(c[GROUP]) < 0) { views.push(c[GROUP]); } });
    var box = el('div');
    mount.appendChild(box);
    var head = el('div', { class: 'table-tools' });
    var sel = el('select', { class: 'metric' });
    metrics.forEach(function (mt) { sel.appendChild(el('option', { value: mt, text: mt })); });
    if (axes.default_metric && metrics.indexOf(axes.default_metric) >= 0) { sel.value = axes.default_metric; }
    head.appendChild(el('span', { class: 'small muted', text: 'Metric' }));
    head.appendChild(sel);
    if (summary.ci) { head.appendChild(el('span', { class: 'small muted', text: 'interval: ' + summary.ci })); }
    box.appendChild(head);
    if (axes.cell_note) { box.appendChild(el('p', { class: 'small muted', text: axes.cell_note })); }
    var panels = el('div', { class: 'grid wide' });
    box.appendChild(panels);
    function draw() {
      clear(panels);
      var metric = sel.value;
      views.forEach(function (view, vi) {
        var sub = cells.filter(function (c) { return c[GROUP] === view; });
        var models = [], sizes = [];
        sub.forEach(function (c) { if (models.indexOf(c[ROW]) < 0) { models.push(c[ROW]); } if (sizes.indexOf(c[COL]) < 0) { sizes.push(c[COL]); } });
        // numeric columns (input size, t_parked) sort by value; text columns (weather names,
        // view labels) keep the order the summary listed them in
        if (sizes.every(function (v) { return typeof v === 'number'; })) { sizes.sort(function (a, b) { return a - b; }); }
        var lookup = {}; sub.forEach(function (c) { lookup[c[ROW] + '|' + c[COL]] = c; });
        var runsPerCell = sub.map(function (c) { return c.runs; }).filter(function (r) { return typeof r === 'number'; });
        var runsText = runsPerCell.length ? (Math.min.apply(null, runsPerCell) === Math.max.apply(null, runsPerCell) ? runsPerCell[0] + ' runs per cell' : Math.min.apply(null, runsPerCell) + ' to ' + Math.max.apply(null, runsPerCell) + ' runs per cell') : '';
        // a panel with many rows or wide cells takes the full width, and many rows are drawn as horizontal bars
        var longestRow = models.reduce(function (acc, mdl) { return Math.max(acc, String(mdl).length); }, 0);
        var wide = models.length > 8 || longestRow * 0.55 + sizes.length * (hasInterval || axes.stat ? 8.5 : 5) > 30;
        var horizontal = models.length > 8;
        var card = el('div', { class: 'card' + (wide ? ' span' : '') }, [el('h3', { text: String(view) + (runsText ? ' (' + runsText.replace('1 runs', '1 run') + ')' : '') })]);
        var canvas = el('canvas', { id: idPrefix + '-' + String(view).replace(/\W+/g, '') + '-chart' });
        card.appendChild(el('div', horizontal ? { class: 'chart', style: 'height:' + (80 + models.length * (9 + 9 * sizes.length)) + 'px' } : { class: 'chart short' }, [canvas]));
        function cellText(c) {
          if (!c || !c[metric] || typeof c[metric].mean !== 'number') { return ''; }
          var ci = c[metric].ci95_runs;
          var mean = c[metric].mean, digits = Math.abs(mean) >= 100 ? 1 : 3;
          if (axes.stat && typeof c[metric].std === 'number') { return mean.toFixed(digits) + ' \u00b1 ' + c[metric].std.toFixed(digits); }
          return mean.toFixed(digits) + (ci && ci.length === 2 ? ' [' + ci[0].toFixed(2) + ', ' + ci[1].toFixed(2) + ']' : '');
        }
        var rows = models.map(function (mdl) {
          var r = {}; r[ROW] = mdl;
          sizes.forEach(function (sz) { r[sz + UNIT] = cellText(lookup[mdl + '|' + sz]); });
          return r;
        });
        var rowLabels = {}; rowLabels[ROW] = ROW + ' \u00b7 ' + statLabel;
        var pivot = makeTable(rows, [ROW].concat(sizes.map(function (sz) { return sz + UNIT; })), { labels: rowLabels, plain: rows.length <= 8 });
        pivot.classList.add('compact');
        card.appendChild(pivot);
        panels.appendChild(card);
        barChart(canvas, models, sizes.map(function (sz, si) {
          return { label: COL + ' ' + sz + UNIT, backgroundColor: PALETTE[si % PALETTE.length], data: models.map(function (mdl) { var c = lookup[mdl + '|' + sz]; return c && c[metric] ? c[metric].mean : null; }) };
        }), { yTitle: metric, legend: true, horizontal: horizontal });
      });
    }
    sel.addEventListener('change', draw);
    draw();
    Object.keys(summary).filter(function (k) { return k.indexOf('best_by_') === 0 && isPlainObject(summary[k]); }).forEach(function (k) {
      var best = Object.keys(summary[k]).map(function (v) {
        var b = summary[k][v];
        return v + ': ' + Object.keys(b).map(function (f) { return f + ' ' + (typeof b[f] === 'number' ? fmt(b[f], 3) : b[f]); }).join(', ');
      });
      box.appendChild(el('p', { class: 'small', style: 'margin-top:0.6rem' }, [el('strong', { text: k.replace('best_by_', 'best by ').replace(/_/g, ' ') + ': ' }), document.createTextNode(best.join(' · '))]));
    });
  }

  // ------------------------------------------------------------------ experiments
  var SHORT_COLUMNS = ['experiment_id', 'model_name', 'seed', 'input_px', 't_parked_s', 'max_range_m', 'dataset_name', 'precision', 'recall', 'f1_score', 'map_score', 'parking_accuracy', 'false_occupied_rate', 'false_free_rate', 'average_inference_time_ms', 'fps'];
  function statusPill(status, live) {
    var map = { done: ['done', 'ok'], results: ['results', 'accent'], running: ['running', 'warn'], planned: ['planned', 'gray'],
      started: ['in progress, not yet scored', 'warn'], not_carried_out: ['not carried out', 'gray'], queued: ['queued', 'gray'],
      'not started': ['not started', 'gray'], stopped: ['stopped', 'gray'] };
    var p = map[status] || [status, 'gray'];
    return pill(p[0], p[1], status === 'running' || live);
  }
  function valuePill(value) {
    // A table cell drawn as a pill: verdicts of a gate (met, passed) and run states.
    var text = String(value === null || value === undefined ? '' : value);
    if (!text) { return document.createTextNode(''); }
    var kind = /^(met|passed|pass|done)$/.test(text) ? 'ok' : (/^(not met|not passed|fail|failed)$/.test(text) ? 'bad' : (text === 'running' ? 'warn' : 'gray'));
    return pill(text, kind, text === 'running');
  }
  function readableTable(t, chartJobs, idPrefix) {
    // One table built by the publisher (READABLE_TABLES in publish_progress.py): title, an
    // optional verdict pill, a note that explains the columns, optional bar charts, the table.
    var head = el('h3', null, [document.createTextNode(t.title)]);
    if (t.verdict) { head.appendChild(pill(t.verdict.text, t.verdict.kind || 'gray')); }
    var card = el('div', { class: 'card' }, [head]);
    if (t.note) { card.appendChild(el('p', { class: 'small muted', text: t.note })); }
    (t.charts || []).forEach(function (spec, ci) {
      if (!spec.labels || !spec.labels.length) { return; }
      var canvas = el('canvas', { id: idPrefix + '-chart-' + ci });
      card.appendChild(el('p', { class: 'small chart-title', text: spec.title || '' }));
      card.appendChild(el('div', { class: 'chart', style: 'height:' + specChartHeight(spec) + 'px' }, [canvas]));
      chartJobs.push(function () { specChart(canvas, spec); });
    });
    var render = {};
    (t.pills || []).forEach(function (col) { render[col] = valuePill; });
    card.appendChild(makeTable(t.rows || [], t.columns, { readable: true, render: render, plain: (t.rows || []).length <= 8 }));
    return card;
  }
  function csvChartControls(rows, canvasId, mount) {
    var cols = Object.keys(rows[0]).filter(function (c) { return rows.some(function (r) { return r[c] !== '' && r[c] !== null && r[c] !== undefined; }); });
    var numericCols = cols.filter(function (c) { return rows.every(function (r) { return r[c] === '' || r[c] === null || r[c] === undefined || typeof r[c] === 'number'; }) && rows.some(function (r) { return typeof r[c] === 'number'; }); });
    var GROUPABLE_NUMERIC = ['input_px', 't_parked_s', 'max_range_m', 'seed'];
    var catCols = cols.filter(function (c) { return numericCols.indexOf(c) < 0 || GROUPABLE_NUMERIC.indexOf(c) >= 0; }).filter(function (c) { var u = {}; rows.forEach(function (r) { u[r[c]] = 1; }); var n = Object.keys(u).length; return n > 1 && n <= 40; });
    if (!numericCols.length || !catCols.length) { return null; }
    var controls = el('div', { class: 'table-tools' });
    var xSel = el('select', { class: 'metric' }); catCols.forEach(function (c) { xSel.appendChild(el('option', { value: c, text: c })); });
    var ySel = el('select', { class: 'metric' }); numericCols.forEach(function (c) { ySel.appendChild(el('option', { value: c, text: c })); });
    var preferY = ['f1_score', 'map_score', 'precision', 'recall', 'parking_accuracy'].filter(function (p) { return numericCols.indexOf(p) >= 0; })[0];
    if (preferY) { ySel.value = preferY; }
    var preferX = ['t_parked_s', 'model_name', 'input_px', 'dataset_name', 'scenario_name', 'experiment_id', 'run'].filter(function (p) { return catCols.indexOf(p) >= 0; })[0];
    if (preferX) { xSel.value = preferX; }
    controls.appendChild(el('span', { class: 'small muted', text: 'Chart: mean of' }));
    controls.appendChild(ySel);
    controls.appendChild(el('span', { class: 'small muted', text: 'grouped by' }));
    controls.appendChild(xSel);
    var canvas = el('canvas', { id: canvasId });
    var wrap = el('div', null, [controls, el('div', { class: 'chart short' }, [canvas])]);
    mount.appendChild(wrap);
    var draw = function () {
      var groups = {};
      rows.forEach(function (r) { if (typeof r[ySel.value] === 'number') { (groups[r[xSel.value]] = groups[r[xSel.value]] || []).push(r[ySel.value]); } });
      var labels = Object.keys(groups);
      barChart(canvas, labels, [{ label: 'mean ' + ySel.value, data: labels.map(function (k) { return meanStd(groups[k]).mean; }), backgroundColor: labels.map(function (_, i) { return PALETTE[i % PALETTE.length]; }) }], { yTitle: ySel.value });
    };
    xSel.onchange = draw; ySel.onchange = draw;
    draw();
    return wrap;
  }
  function figureStrip(names, m) {
    var figs = (m.figures || []).filter(function (f) { return names.indexOf(f.name) >= 0; });
    if (!figs.length) { return null; }
    var grid = el('div', { class: 'figures' });
    figs.forEach(function (f) {
      var img = el('img', { alt: f.caption, loading: 'lazy' });
      vaultImage(f.file).then(function (url) { img.src = url; }).catch(function () { img.alt = 'could not decrypt ' + f.name; });
      img.addEventListener('click', function () { openLightbox(f); });
      grid.appendChild(el('figure', { class: 'fig' }, [img, el('figcaption', null, [document.createTextNode(f.caption), el('span', { class: 'small muted', text: f.name })])]));
    });
    return grid;
  }
  // Which experiment groups and file cards the reader has open; survives the periodic re-render
  // (a new manifest rebuilds the DOM) and the theme toggle. Keyed by element id.
  var openGroups = {};
  function groupSummary(titleNodes, metaNodes) {
    return el('summary', null, [el('span', { class: 'exp-title' }, titleNodes), el('span', { class: 'exp-meta' }, metaNodes)]);
  }
  function lazyDetails(det, loader) {
    // Load the heavy content of a <details> the first time it is opened; remember the state.
    var loaded = false;
    function run() { if (!loaded) { loaded = true; loader(); } }
    det.addEventListener('toggle', function () {
      if (det.id) { openGroups[det.id] = det.open; }
      if (det.open) { run(); }
    });
    if (det.open) { run(); }
    return det;
  }
  function renderExperimentGroup(exp, m, defaultOpen) {
    var id = 'exp-' + exp.id;
    var open = id in openGroups ? openGroups[id] : defaultOpen;
    var det = el('details', { class: 'exp', id: id, open: open });
    det.appendChild(groupSummary(
      [el('strong', { text: exp.id }), document.createTextNode(' ' + exp.name)],
      [statusPill(exp.status), el('span', { class: 'muted small', text: (exp.rows ? exp.rows + ' result rows' : (exp.tables && exp.tables.length ? exp.tables.length + ' tables' : (exp.status === 'not_carried_out' ? 'no result' : 'no rows yet'))) + (exp.updated ? ' · ' + fmtDate(exp.updated) : '') })]
    ));
    var body = el('div', { class: 'exp-body' });
    det.appendChild(body);
    var chartJobs = [];
    if (exp.status_note) {
      body.appendChild(el('div', { class: 'card notice' }, [el('p', { text: exp.status_note })]));
    }
    if (exp.overview) {
      // One paragraph from docs/progress_notes.md ("Experiment overviews"): what the experiment
      // does and what it will report, shown before the plan row so a planned experiment is not
      // just an empty table.
      body.appendChild(el('div', { class: 'card' }, [el('h3', { text: 'Overview' }), el('p', { class: 'overview', text: exp.overview })]));
    }
    var dl = el('dl', { class: 'kv' });
    [['Purpose', exp.purpose], ['Data', exp.data_source], ['Method', exp.method], ['Output', exp.output], ['Metrics', exp.metrics], ['Plan item', exp.plan_item]].forEach(function (pair) {
      if (pair[1]) { dl.appendChild(el('dt', { text: pair[0] })); dl.appendChild(el('dd', { text: pair[1] })); }
    });
    body.appendChild(el('div', { class: 'card' }, [dl]));
    if (exp.log_tail && exp.log_tail.length && exp.status === 'running') {
      body.appendChild(el('div', { class: 'card' }, [el('h3', { text: 'Sweep log (tail)' }), el('pre', { text: exp.log_tail.join('\n') })]));
    }
    // Readable tables the publisher built for experiments whose result is a checklist (EXP-J):
    // drawn before the raw summary so the reader sees the outcome first.
    (exp.tables || []).forEach(function (t, ti) {
      body.appendChild(readableTable(t, chartJobs, id.toLowerCase() + '-t' + ti));
    });
    var sumCard = exp.summary_file ? el('div', { class: 'card' }, [el('h3', null, [document.createTextNode(exp.tables && exp.tables.length ? 'Every metric of the summary ' : 'Summary '), el('span', { class: 'muted small', text: exp.summary_file.split('/').pop() })])]) : null;
    if (sumCard) { body.appendChild(sumCard); }
    if (exp.figures && exp.figures.length) {
      var strip = figureStrip(exp.figures, m);
      if (strip) { body.appendChild(el('div', { class: 'card' }, [el('h3', { text: 'Figures' }), strip])); }
    }
    var rowsCard = exp.rows_file ? el('div', { class: 'card' }, [el('h3', null, [document.createTextNode('Result rows '), el('span', { class: 'muted small', text: exp.rows + ' rows of all_results.csv' })])]) : null;
    if (rowsCard) { body.appendChild(rowsCard); }
    if (exp.details_file) {
      var detId = id + '-records';
      var detCard = el('details', { class: 'card exp-details', id: detId, open: !!openGroups[detId] }, [el('summary', null, [el('strong', { text: 'Per-row result records' }), el('span', { class: 'muted small', text: ' ' + exp.details + ' result.json files, expand to browse' })])]);
      body.appendChild(detCard);
      lazyDetails(detCard, function () {
        var list = el('div', { class: 'json-root' });
        detCard.appendChild(list);
        fetchJSON(exp.details_file).then(function (bundle) {
          var filter = el('input', { type: 'search', placeholder: 'Filter records…', 'aria-label': 'Filter records' });
          list.appendChild(el('div', { class: 'table-tools' }, [filter, el('span', { class: 'muted small', text: Object.keys(bundle).length + ' records' })]));
          var items = el('div');
          list.appendChild(items);
          function draw() {
            clear(items);
            var needle = filter.value.trim().toLowerCase();
            Object.keys(bundle).sort().forEach(function (name) {
              if (needle && name.toLowerCase().indexOf(needle) < 0) { return; }
              var rec = bundle[name];
              var row = (rec && rec.row) || {};
              var brief = ['f1_score', 'precision', 'recall', 'map_score'].filter(function (k) { return typeof row[k] === 'number'; }).map(function (k) { return k.replace('_score', '') + ' ' + row[k].toFixed(3); }).join(' · ');
              var item = el('details', { class: 'json' }, [el('summary', null, [el('span', { class: 'json-key', text: name.replace(exp.id + '-', '') }), el('span', { class: 'muted small', text: ' ' + brief })])]);
              lazyDetails(item, function () { item.appendChild(jsonRoot(rec)); });
              items.appendChild(item);
            });
          }
          filter.addEventListener('input', draw);
          draw();
        }).catch(function (err) { list.appendChild(el('div', { class: 'empty small', text: 'Could not load: ' + err.message })); });
      });
    }
    return lazyDetails(det, function () {
      // charts of the readable tables: drawn now, when the group is open and in the document
      chartJobs.forEach(function (job) { job(); });
      if (sumCard) {
        fetchJSON(exp.summary_file).then(function (summary) {
          if (summary.description) { sumCard.appendChild(el('p', { class: 'small muted', text: summary.description + (typeof summary.settings === 'string' && summary.settings ? ' Settings: ' + summary.settings : '') })); }
          // a summary is drawn as tables when its cells carry the group key its axes name (default: view)
          if (Array.isArray(summary.cells) && summary.cells.length && isPlainObject(summary.cells[0]) && (((summary.axes || {}).group) || 'view') in summary.cells[0]) {
            renderCellSummary(summary, id.toLowerCase(), sumCard);
            var rest = {}; Object.keys(summary).forEach(function (k) { if (['cells', 'description', 'settings', 'axes'].indexOf(k) < 0 && k.indexOf('best_by_') !== 0) { rest[k] = summary[k]; } });
            var more = el('details', { class: 'json', style: 'margin-top:0.6rem' }, [el('summary', { text: 'Other summary fields' })]);
            more.appendChild(jsonRoot(rest));
            sumCard.appendChild(more);
          } else {
            sumCard.appendChild(jsonRoot(summary));
          }
        }).catch(function (err) { sumCard.appendChild(el('div', { class: 'empty small', text: 'Could not load: ' + err.message })); });
      }
      if (rowsCard) {
        fetchCSV(exp.rows_file).then(function (rows) {
          if (!rows.length) { rowsCard.appendChild(el('div', { class: 'empty small', text: 'Empty file.' })); return; }
          csvChartControls(rows, id.toLowerCase() + '-rows-chart', rowsCard);
          var allCols = Object.keys(rows[0]);
          var shortCols = SHORT_COLUMNS.filter(function (c) { return allCols.indexOf(c) >= 0; });
          var holder = el('div');
          var check = el('input', { type: 'checkbox' });
          var toggle = el('label', { class: 'small muted', style: 'display:inline-flex;gap:0.35rem;align-items:center;margin:0.3rem 0' }, [check, document.createTextNode('show all ' + allCols.length + ' columns')]);
          rowsCard.appendChild(toggle);
          rowsCard.appendChild(holder);
          var short = rows.map(function (r) { var o = {}; allCols.forEach(function (c) { o[c] = c === 'experiment_id' ? String(r[c]).replace(exp.id + '-', '') : r[c]; }); return o; });
          function drawTable() {
            clear(holder);
            holder.appendChild(makeTable(short, check.checked ? allCols : shortCols, { download: exp.rows_file, wrap: ['notes', 'experiment_name'], labels: { experiment_id: 'row id (without the experiment prefix)', average_inference_time_ms: 'ms/frame', input_px: 'input px', t_parked_s: 't_parked s', max_range_m: 'max range m' } }));
          }
          check.addEventListener('change', drawTable);
          drawTable();
        }).catch(function (err) { rowsCard.appendChild(el('div', { class: 'empty small', text: 'Could not load: ' + err.message })); });
      }
    });
  }
  function renderExperiments(m) {
    var ex = m.experiments || { experiments: [], files: [] };
    var cards = clear($('experiment-cards'));
    ex.experiments.forEach(function (exp) {
      var c = el('a', { class: 'card exp-card', href: '#exp-' + exp.id }, [
        el('div', { class: 'exp-card-head' }, [el('strong', { text: exp.id }), statusPill(exp.status)]),
        el('div', { class: 'small', text: exp.name }),
        el('div', { class: 'sub', text: exp.rows ? exp.rows + ' rows' + (exp.details ? ' · ' + exp.details + ' records' : '') : (exp.tables && exp.tables.length ? exp.tables.length + ' tables' + (exp.figures && exp.figures.length ? ' · ' + exp.figures.length + (exp.figures.length === 1 ? ' figure' : ' figures') : '') : (exp.summary_file ? 'summary' : (exp.status === 'not_carried_out' ? 'left to future work' : 'no results yet'))) })
      ]);
      c.addEventListener('click', function () { var t = $('exp-' + exp.id); if (t && !t.open) { t.open = true; } });
      cards.appendChild(c);
    });
    var groups = clear($('experiment-groups'));
    var withData = ex.experiments.filter(function (e) { return e.status !== 'planned'; });
    var planned = ex.experiments.filter(function (e) { return e.status === 'planned'; });
    if (!withData.length) { groups.appendChild(el('div', { class: 'empty', text: 'No experiment has produced results yet. Each experiment gets its own group here as soon as rows appear in all_results.csv.' })); }
    // Default: the running experiment, else the first one with data, starts open; the reader's
    // own choices (openGroups) win on every later render.
    var defaultId = (withData.filter(function (e) { return e.status === 'running'; })[0] || withData[0] || {}).id;
    withData.forEach(function (exp) { groups.appendChild(renderExperimentGroup(exp, m, exp.id === defaultId)); });
    if (planned.length) {
      var pl = el('details', { class: 'exp planned', id: 'exp-planned', open: !!openGroups['exp-planned'] });
      pl.appendChild(groupSummary([el('strong', { text: 'Planned' }), document.createTextNode(' ' + planned.length + ' experiments without results yet')], [pill('planned', 'gray')]));
      var pbody = el('div', { class: 'exp-body' });
      pbody.appendChild(makeTable(planned, ['id', 'name', 'purpose', 'data_source', 'metrics'], { wrap: ['purpose', 'metrics', 'name', 'data_source'] }));
      pl.appendChild(pbody);
      groups.appendChild(lazyDetails(pl, function () {}));
    }
    var filesBox = clear($('other-results'));
    if (!ex.files.length) { filesBox.appendChild(el('div', { class: 'empty', text: 'No further result files.' })); return; }
    ex.files.forEach(function (file, index) {
      var fid = 'file-' + file.name.replace(/\W+/g, '-');
      var card = el('details', { class: 'exp file', id: fid, open: !!openGroups[fid] });
      card.appendChild(groupSummary(
        [el('code', { text: file.name }), file.experiment ? el('span', { class: 'muted small', text: ' ' + file.experiment }) : null],
        [el('span', { class: 'muted small', text: (file.rows !== undefined ? file.rows + ' rows · ' : '') + file.size_kb + ' kB · ' + fmtDate(file.updated) })]
      ));
      var body = el('div', { class: 'exp-body' });
      card.appendChild(body);
      if (file.description) { body.appendChild(el('p', { class: 'small muted', text: file.description })); }
      filesBox.appendChild(card);
      lazyDetails(card, function () {
        if (/\.csv$/.test(file.name)) {
          fetchCSV(file.path).then(function (rows) {
            if (!rows.length) { body.appendChild(el('div', { class: 'empty small', text: 'Empty file.' })); return; }
            csvChartControls(rows, 'file-chart-' + index, body);
            body.appendChild(makeTable(rows, null, { download: file.path, wrap: ['notes'] }));
          }).catch(function (err) { body.appendChild(el('div', { class: 'empty small', text: 'Could not load: ' + err.message })); });
        } else {
          fetchJSON(file.path).then(function (obj) {
            body.appendChild(el('div', { class: 'table-tools' }, [el('a', { href: '#', class: 'small', onclick: function (e) { e.preventDefault(); downloadDecrypted(file.path); } }, ['Download JSON'])]));
            body.appendChild(jsonRoot(obj));
          }).catch(function (err) { body.appendChild(el('div', { class: 'empty small', text: 'Could not load: ' + err.message })); });
        }
      });
    });
  }

  function renderModels(m) {
    // Layout: the two weight lists side by side (compact columns), then the app bundle as one
    // full-width table underneath, because it has the most columns.
    var models = m.models || {};
    var box = clear($('model-cards'));
    function section(title, note, table) {
      var card = el('div', { class: 'card' }, [el('h3', { text: title })]);
      if (note) { card.appendChild(el('p', { class: 'small muted', text: note })); }
      card.appendChild(table);
      return card;
    }
    var top = el('div', { class: 'grid wide' });
    box.appendChild(top);
    var pre = models.pretrained || [];
    top.appendChild(section('Pretrained weights (COCO)', 'Checkpoints in models/pretrained/, the zero-shot baselines of EXP-A.',
      pre.length ? makeTable(pre, ['name', 'size_mb', 'date'], { labels: { size_mb: 'MB' }, readable: true, plain: true }) : el('div', { class: 'empty small', text: 'No pretrained weights found.' })));
    var ft = models.fine_tuned || [];
    top.appendChild(section('Fine-tuned weights', 'One best.pt per training run, with the training stage it belongs to (see Training). The validation figure is measured on the validation set of that stage, so it compares only within a stage.',
      ft.length ? makeTable(ft, ['name', 'stage', 'best_epoch', 'best_val_map50_95', 'minutes', 'size_mb'], {
        sort: 'name', readable: true, labels: { best_epoch: 'best epoch', best_val_map50_95: 'val mAP50-95', size_mb: 'MB' }
      }) : el('div', { class: 'empty small', text: 'No fine-tuned model yet.' })));
    var app = models.app_models || [];
    var meta = models.app_meta || {};
    var note = app.length
      ? meta.models + ' models, ' + meta.files + ' ONNX files, ' + meta.total_mb + ' MB in the app' + (meta.input_size ? ', ' + meta.input_size + ' px input' : '') + (meta.thesis_commit ? ', exported at thesis commit ' + meta.thesis_commit : '') + (meta.generated_at ? ' (' + fmtDate(meta.generated_at) + ')' : '') + '. The start page of the app lets the user pick any of them; "verified" means the ONNX output was matched against PyTorch on test frames; NMS-free is the end-to-end export of the YOLO26 models.'
      : 'The app\'s model catalogue (models.json) was not found.';
    box.appendChild(section('Models bundled in the smartphone app', note,
      app.length ? makeTable(app, ['id', 'family', 'arch', 'size_mb', 'classes', 'verified', 'val_map50_95', 'trained_px', 'nms_free_mb', 'nms_free_verified', 'nms_free_agreement'], {
        readable: true, labels: { size_mb: 'MB', val_map50_95: 'val mAP50-95', trained_px: 'trained at px', nms_free_mb: 'NMS-free MB', nms_free_verified: 'NMS-free verified', nms_free_agreement: 'NMS-free agreement' },
        render: {
          family: function (v) { return pill(v === 'fine_tuned' ? 'fine-tuned' : 'pretrained', v === 'fine_tuned' ? 'ok' : 'accent'); },
          verified: function (v) { return pill(v, v === 'yes' ? 'ok' : 'bad'); },
          nms_free_verified: function (v) { return v ? pill(v, v === 'yes' ? 'ok' : 'bad') : document.createTextNode(''); }
        }
      }) : el('div', { class: 'empty small', text: 'MODEL_VERSION / models.json not found.' })));
  }

  function renderFigures(m) {
    var box = clear($('figure-groups'));
    var groups = {};
    (m.figures || []).forEach(function (f) { (groups[f.group] = groups[f.group] || []).push(f); });
    var order = ['Digital twin', 'Parking regions', 'Capture and labels', 'Training', 'Experiments', 'Results', 'Data protection', 'Other'];
    Object.keys(groups).sort(function (a, b) { return (order.indexOf(a) < 0 ? 99 : order.indexOf(a)) - (order.indexOf(b) < 0 ? 99 : order.indexOf(b)); }).forEach(function (group) {
      box.appendChild(el('h3', { text: group, style: 'margin-top:1rem' }));
      var grid = el('div', { class: 'figures' });
      groups[group].forEach(function (f) {
        var img = el('img', { alt: f.caption, loading: 'lazy' });
        vaultImage(f.file).then(function (url) { img.src = url; }).catch(function () { img.alt = 'could not decrypt ' + f.name; });
        img.addEventListener('click', function () { openLightbox(f); });
        grid.appendChild(el('figure', { class: 'fig' }, [img, el('figcaption', null, [document.createTextNode(f.caption), el('span', { class: 'small muted', text: f.name + ' · ' + f.date })])]));
      });
      box.appendChild(grid);
    });
    if (!Object.keys(groups).length) { box.appendChild(el('div', { class: 'empty', text: 'No figures yet.' })); }
  }
  function openLightbox(f) {
    var big = el('img', { alt: f.caption });
    vaultImage(f.file).then(function (url) { big.src = url; });
    var lb = el('div', { class: 'lightbox' }, [big, el('figcaption', { text: f.caption })]);
    lb.addEventListener('click', function () { document.body.removeChild(lb); });
    document.body.appendChild(lb);
  }

  function renderActivity(m) {
    function fill(id, commits) {
      var list = clear($(id));
      (commits || []).forEach(function (c) {
        list.appendChild(el('li', null, [el('code', { text: c.hash }), el('span', { text: c.subject }), el('time', { text: fmtDate(c.date) })]));
      });
      if (!list.children.length) { list.appendChild(el('li', { class: 'muted', text: 'No commits available.' })); }
    }
    fill('commits-thesis', m.commits);
    fill('commits-app', m.app_commits);
  }

  // ------------------------------------------------------------------ orchestration
  function renderAll(m) {
    state.manifest = m;
    chartDefaults();
    renderHeader(m);
    renderOverview(m);
    renderTimeline(m);
    renderPlan(m);
    renderData(m);
    renderTraining(m);
    renderExperiments(m);
    renderModels(m);
    renderFigures(m);
    renderActivity(m);
  }
  function load(first) {
    return fetchJSON(MANIFEST_URL).then(function (m) {
      if (!first && m.generated_at === state.generatedAt) { return; }
      state.generatedAt = m.generated_at;
      $('error').classList.add('hidden');
      renderAll(m);
    }).catch(function (err) {
      var box = $('error');
      box.classList.remove('hidden');
      box.textContent = 'Could not load or decrypt the manifest (' + err.message + '). The dashboard may not have been published yet; try signing out and in again.';
    });
  }
  function setupNav() {
    var links = Array.prototype.slice.call(document.querySelectorAll('nav.tabs a'));
    var sections = links.map(function (a) { return document.querySelector(a.getAttribute('href')); });
    function update() {
      var y = window.scrollY + 90;
      var active = 0;
      sections.forEach(function (s, i) { if (s && s.offsetTop <= y) { active = i; } });
      links.forEach(function (a, i) { a.classList.toggle('active', i === active); });
    }
    window.addEventListener('scroll', update, { passive: true });
    update();
  }
  function setupTheme() {
    var button = $('theme-toggle');
    var saved = null;
    try { saved = localStorage.getItem('progress-theme'); } catch (e) { saved = null; }
    if (saved === 'dark' || saved === 'light') { document.documentElement.setAttribute('data-theme', saved); }
    button.addEventListener('click', function () {
      var current = document.documentElement.getAttribute('data-theme');
      var prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      var isDark = current ? current === 'dark' : prefersDark;
      var next = isDark ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      try { localStorage.setItem('progress-theme', next); } catch (e) { /* storage unavailable */ }
      if (state.manifest) { renderAll(state.manifest); }
    });
  }

  // ------------------------------------------------------------------ login gate
  function unlock() {
    $('login').classList.add('hidden');
    $('topbar').classList.remove('hidden');
    $('main').classList.remove('hidden');
    setupNav();
    load(true);
    if (!state.refreshTimer) { state.refreshTimer = setInterval(function () { load(false); }, REFRESH_MS); }
  }
  function lock() {
    state.key = null;
    try { sessionStorage.removeItem(SESSION_KEY); } catch (e) { /* ignore */ }
    Object.keys(state.blobUrls).forEach(function (k) { URL.revokeObjectURL(state.blobUrls[k]); });
    state.blobUrls = {};
    location.reload();
  }
  function verifyKey(rawBits, verify) {
    // The verifier is a known phrase encrypted under the same key; a wrong password fails the GCM tag.
    return importAesKey(rawBits).then(function (key) {
      state.key = key;
      return decryptBuffer(bytesFromBase64(verify.check).buffer);
    }).then(function (buf) {
      if (new TextDecoder().decode(buf) !== VERIFY_TEXT) { throw new Error('verifier mismatch'); }
      return true;
    }).catch(function () { state.key = null; return false; });
  }
  function showLoginError(text) { $('login-error').textContent = text; }
  function attemptLogin(user, password, remember) {
    var button = $('login-submit');
    button.disabled = true; button.textContent = 'Checking…';
    showLoginError('');
    return rawFetch(VERIFY_URL).then(function (r) { return r.json(); }).then(function (verify) {
      return deriveKeyBits(user, password, verify.salt_hex, verify.iterations).then(function (bits) {
        return verifyKey(bits, verify).then(function (ok) {
          if (!ok) { showLoginError('Wrong user name or password.'); return; }
          if (remember) { try { sessionStorage.setItem(SESSION_KEY, base64FromBytes(new Uint8Array(bits))); } catch (e) { /* storage unavailable */ } }
          unlock();
        });
      });
    }).catch(function (err) {
      showLoginError('Cannot reach the encrypted data (' + err.message + '). Check the connection and try again.');
    }).then(function () { button.disabled = false; button.textContent = 'Sign in'; });
  }
  function setupLogin() {
    var form = $('login-form');
    $('login-toggle').addEventListener('click', function () {
      var field = $('login-password');
      var show = field.type === 'password';
      field.type = show ? 'text' : 'password';
      this.textContent = show ? 'Hide' : 'Show';
      this.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    });
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      if (!cryptoAvailable()) { showLoginError('This browser cannot decrypt the page (Web Crypto needs HTTPS).'); return; }
      var user = $('login-user').value.trim();
      var password = $('login-password').value;
      if (!user || !password) { showLoginError('Enter the user name and the password.'); return; }
      attemptLogin(user, password, $('login-remember').checked);
    });
    $('logout').addEventListener('click', lock);
    // resume a session kept on this tab
    var saved = null;
    try { saved = sessionStorage.getItem(SESSION_KEY); } catch (e) { saved = null; }
    if (saved && cryptoAvailable()) {
      rawFetch(VERIFY_URL).then(function (r) { return r.json(); }).then(function (verify) {
        return verifyKey(bytesFromBase64(saved).buffer, verify);
      }).then(function (ok) { if (ok) { unlock(); } else { try { sessionStorage.removeItem(SESSION_KEY); } catch (e) { /* ignore */ } } }).catch(function () { /* stay on the login form */ });
    }
    $('login-user').focus();
  }

  document.addEventListener('DOMContentLoaded', function () {
    setupTheme();
    setupLogin();
  });
})();
