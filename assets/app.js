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
        else { node.setAttribute(key, attrs[key]); }
      });
    }
    (children || []).forEach(function (child) {
      if (child === null || child === undefined) { return; }
      node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
    });
    return node;
  }
  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } return node; }
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
      var url = URL.createObjectURL(new Blob([text], { type: 'text/csv' }));
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
  function makeChart(id, config) {
    var canvas = $(id);
    if (!canvas || !window.Chart) { return null; }
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
        scales: {
          x: { stacked: !!opts.stacked, grid: { display: false } },
          y: { stacked: !!opts.stacked, beginAtZero: true, title: { display: !!opts.yTitle, text: opts.yTitle || '' } }
        }
      }
    });
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
    if (opts.download) {
      tools.appendChild(el('a', { href: '#', class: 'small', onclick: function (e) { e.preventDefault(); downloadDecrypted(opts.download); } }, ['Download CSV']));
    }
    wrapper.appendChild(tools);
    var wrap = el('div', { class: 'table-wrap' });
    var table = el('table', { class: 'data' });
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
          var cell = el('td', { class: numeric[col] ? 'num' : ((opts.wrap || []).indexOf(col) >= 0 ? 'wrap' : '') });
          if (opts.render && opts.render[col]) { cell.appendChild(opts.render[col](value, row)); }
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
    var best = (tr.runs || []).reduce(function (acc, r) { return (r.best_map50_95 !== null && r.best_map50_95 > acc) ? r.best_map50_95 : acc; }, 0);
    var exps = (m.experiments && m.experiments.experiments) || [];
    var expDone = exps.filter(function (e) { return e.status === 'results'; }).length;

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
    var trainingSub = runningRuns ? runningRuns + ' running now' : (doneRuns ? 'best mAP50-95 so far ' + best.toFixed(3) : 'not started');
    cards.appendChild(card('Training runs (S1)', doneRuns + ' / ' + (tr.planned_runs || 12), 'done', trainingSub,
      el('div', { class: 'bar ok' }, [el('span', { style: 'width:' + (tr.planned_runs ? Math.round(100 * doneRuns / tr.planned_runs) : 0) + '%' })])));
    cards.appendChild(card('Experiments with results', expDone + ' / ' + exps.length, '', 'EXP-A to EXP-J, pre-registered'));

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
    if (plan.status) {
      statusCard.appendChild(el('p', { class: 'small muted', style: 'margin-top:0.8rem' }, ['Plan status line: ' + plan.status]));
    }
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
      var details = el('details', { class: 'phase', open: index === 0 ? '' : null });
      if (index !== 0) { details.removeAttribute('open'); }
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
    if (ds.class_counts) {
      var classNames = ds.classes || {};
      var classIds = Object.keys(classNames);
      var splitNames = Object.keys(ds.class_counts);
      showCanvas('chart-classes');
      barChart('chart-classes', splitNames, classIds.map(function (cid, i) {
        return { label: classNames[cid], data: splitNames.map(function (sp) { return (ds.class_counts[sp].per_class || {})[cid] || 0; }), backgroundColor: PALETTE[i % PALETTE.length] };
      }), { stacked: true, legend: true, yTitle: 'boxes' });
    } else { emptyChart('chart-classes', 'No label statistics yet.'); }

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

  function renderTraining(m) {
    var tr = m.training || { runs: [] };
    var cards = clear($('training-cards'));
    var runs = tr.runs || [];
    var byStatus = groupSum(runs, 'status');
    var plan = tr.plan || {};
    cards.appendChild(el('div', { class: 'card' }, [el('h3', { text: 'Recipe' }), el('dl', { class: 'kv' }, [
      el('dt', { text: 'Architectures' }), el('dd', { text: (plan.archs || []).join(', ') }),
      el('dt', { text: 'Seeds' }), el('dd', { text: (plan.seeds || []).join(', ') }),
      el('dt', { text: 'Epochs' }), el('dd', { text: plan.epochs + ' max, early stop patience ' + plan.patience }),
      el('dt', { text: 'Image size' }), el('dd', { text: plan.image_size + ' px, backbone frozen, COCO weights' })
    ])]));
    var status = el('div', { class: 'card' }, [el('h3', { text: 'Runs' }), el('div', { class: 'big' }, [document.createTextNode((byStatus.done || 0) + ' / ' + tr.planned_runs), el('small', { text: 'finished' })])]);
    var parts = [];
    if (byStatus.running) { parts.push(byStatus.running + ' running'); }
    if (byStatus.stopped) { parts.push(byStatus.stopped + ' stopped early'); }
    status.appendChild(el('div', { class: 'sub', text: parts.length ? parts.join(', ') : (runs.length ? 'no run in progress' : 'nothing started yet') }));
    cards.appendChild(status);
    var archSummary = {};
    runs.forEach(function (r) { if (r.best_map50_95 !== null && r.best_map50_95 !== undefined) { (archSummary[r.arch] = archSummary[r.arch] || []).push(r.best_map50_95); } });
    var archs = Object.keys(archSummary);
    if (archs.length) {
      var dl = el('dl', { class: 'kv' });
      archs.forEach(function (a) { var ms = meanStd(archSummary[a]); dl.appendChild(el('dt', { text: a })); dl.appendChild(el('dd', { text: ms.mean.toFixed(3) + (archSummary[a].length > 1 ? ' ± ' + ms.std.toFixed(3) : '') + ' (n=' + archSummary[a].length + ')' })); });
      cards.appendChild(el('div', { class: 'card' }, [el('h3', { text: 'Best val mAP50-95 per architecture' }), dl]));
    }

    var runsBox = clear($('training-runs'));
    if (!runs.length) {
      runsBox.appendChild(el('div', { class: 'empty', text: 'No training run has started yet. The S1 matrix (4 architectures × 3 seeds, 12 runs) appears here epoch by epoch once experiments/train_matrix.sh is running and the collector republishes.' }));
      emptyChart('chart-training-curves', 'Curves appear with the first finished epoch.');
      emptyChart('chart-training-best', 'Nothing trained yet.');
      $('training-log-wrap').classList.add('hidden');
      populateMetricSelect([]);
      return;
    }
    var rows = runs.map(function (r) {
      return { run: r.name, arch: r.arch, seed: r.seed, status: r.status, epochs: r.epochs_done, best_epoch: r.best_epoch, best_map50_95: r.best_map50_95, last_map50_95: r.last_map50_95, minutes: r.record_elapsed_minutes || r.record_wall_time_min || null, size_mb: r.best_pt_mb || r.record_size_mb || null, updated: r.updated || '' };
    });
    runsBox.appendChild(makeTable(rows, ['run', 'arch', 'seed', 'status', 'epochs', 'best_epoch', 'best_map50_95', 'last_map50_95', 'minutes', 'size_mb', 'updated'], {
      sort: 'run', labels: { best_map50_95: 'best mAP50-95', last_map50_95: 'last mAP50-95', size_mb: 'best.pt MB' },
      render: {
        status: function (v) { return pill(String(v), v === 'done' ? 'ok' : (v === 'running' ? 'warn' : 'gray'), v === 'running'); },
        updated: function (v) { return document.createTextNode(fmtDate(v)); }
      }
    }));
    // best per run chart
    showCanvas('chart-training-best');
    var withBest = runs.filter(function (r) { return r.best_map50_95 !== null && r.best_map50_95 !== undefined; });
    barChart('chart-training-best', withBest.map(function (r) { return r.name; }), [{ label: 'best val mAP50-95', data: withBest.map(function (r) { return r.best_map50_95; }), backgroundColor: withBest.map(function (r) { return ARCH_COLORS[r.arch] || PALETTE[5]; }) }], { horizontal: true });
    // curves
    var withCsv = runs.filter(function (r) { return r.files && r.files.results; });
    Promise.all(withCsv.map(function (r) { return fetchCSV(r.files.results).then(function (rows) { return { run: r, rows: rows }; }).catch(function () { return null; }); })).then(function (loaded) {
      state.csv.training = loaded.filter(Boolean);
      var metrics = {};
      state.csv.training.forEach(function (item) { if (item.rows.length) { Object.keys(item.rows[0]).forEach(function (k) { if (k !== 'epoch' && typeof item.rows[0][k] === 'number') { metrics[k] = true; } }); } });
      populateMetricSelect(Object.keys(metrics));
      drawTrainingCurves();
    });
    var logWrap = $('training-log-wrap');
    if (tr.log_tail) {
      logWrap.classList.remove('hidden');
      fetchText(tr.log_tail).then(function (text) { $('training-log').textContent = text; }).catch(function () { logWrap.classList.add('hidden'); });
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
    var metric = $('training-metric').value;
    var items = state.csv.training || [];
    if (!items.length || !metric) { emptyChart('chart-training-curves', 'Curves appear with the first finished epoch.'); return; }
    showCanvas('chart-training-curves');
    var maxEpoch = 0;
    var datasets = items.map(function (item) {
      var pts = item.rows.map(function (row) { maxEpoch = Math.max(maxEpoch, Number(row.epoch) || 0); return { x: Number(row.epoch), y: typeof row[metric] === 'number' ? row[metric] : null }; });
      var seed = item.run.seed;
      return { label: item.run.name, data: pts, borderColor: ARCH_COLORS[item.run.arch] || PALETTE[5], backgroundColor: 'transparent', borderDash: seed === 1 ? [6, 3] : (seed === 2 ? [2, 3] : []), pointRadius: 0, borderWidth: 1.8, tension: 0.15, spanGaps: true };
    });
    makeChart('chart-training-curves', { type: 'line', data: { datasets: datasets }, options: { responsive: true, parsing: false, interaction: { mode: 'nearest', intersect: false }, plugins: { legend: { position: 'bottom' } }, scales: { x: { type: 'linear', title: { display: true, text: 'epoch' }, min: 1, max: Math.max(maxEpoch, 2) }, y: { title: { display: true, text: metric } } } } });
  }

  function renderExperiments(m) {
    var ex = m.experiments || { experiments: [], files: [] };
    var box = clear($('experiment-table'));
    if (ex.experiments.length) {
      box.appendChild(makeTable(ex.experiments, ['id', 'name', 'purpose', 'data_source', 'metrics', 'status', 'rows'], {
        wrap: ['purpose', 'metrics', 'name', 'data_source'], labels: { rows: 'result rows' },
        render: { status: function (v) { return pill(v === 'results' ? 'results' : 'planned', v === 'results' ? 'ok' : 'gray'); } }
      }));
    }
    var filesBox = clear($('result-files'));
    if (!ex.files.length) { filesBox.appendChild(el('div', { class: 'empty', text: 'No result files yet.' })); return; }
    ex.files.forEach(function (file, index) {
      var card = el('div', { class: 'card', style: 'margin-bottom:0.9rem' });
      card.appendChild(el('h3', null, [el('code', { text: file.name }), el('span', { class: 'muted small', text: ' · ' + (file.rows !== undefined ? file.rows + ' rows · ' : '') + file.size_kb + ' kB · ' + fmtDate(file.updated) })]));
      if (file.description) { card.appendChild(el('p', { class: 'small muted', text: file.description })); }
      filesBox.appendChild(card);
      if (file.name.indexOf('kt_matrix_manifest') === 0) { card.appendChild(el('p', { class: 'small muted', text: 'Shown in the Data section above.' })); return; }
      if (/\.csv$/.test(file.name)) {
        fetchCSV(file.path).then(function (rows) {
          if (!rows.length) { card.appendChild(el('div', { class: 'empty small', text: 'Empty file.' })); return; }
          var cols = Object.keys(rows[0]).filter(function (c) { return rows.some(function (r) { return r[c] !== '' && r[c] !== null && r[c] !== undefined; }); });
          var numericCols = cols.filter(function (c) { return rows.every(function (r) { return r[c] === '' || r[c] === null || r[c] === undefined || typeof r[c] === 'number'; }) && rows.some(function (r) { return typeof r[c] === 'number'; }); });
          var catCols = cols.filter(function (c) { return numericCols.indexOf(c) < 0; }).filter(function (c) { var u = {}; rows.forEach(function (r) { u[r[c]] = 1; }); var n = Object.keys(u).length; return n > 1 && n <= 30; });
          if (numericCols.length && catCols.length) {
            var controls = el('div', { class: 'table-tools' });
            var xSel = el('select', { class: 'metric' }); catCols.forEach(function (c) { xSel.appendChild(el('option', { value: c, text: c })); });
            var ySel = el('select', { class: 'metric' }); numericCols.forEach(function (c) { ySel.appendChild(el('option', { value: c, text: c })); });
            var preferY = ['f1_score', 'map_score', 'precision', 'recall', 'parking_accuracy'].filter(function (p) { return numericCols.indexOf(p) >= 0; })[0];
            if (preferY) { ySel.value = preferY; }
            var preferX = ['model_name', 'experiment_id', 'scenario_name', 'run'].filter(function (p) { return catCols.indexOf(p) >= 0; })[0];
            if (preferX) { xSel.value = preferX; }
            controls.appendChild(el('span', { class: 'small muted', text: 'Chart: group by' }));
            controls.appendChild(xSel);
            controls.appendChild(el('span', { class: 'small muted', text: 'value' }));
            controls.appendChild(ySel);
            card.appendChild(controls);
            var canvasId = 'result-chart-' + index;
            card.appendChild(el('div', { class: 'chart short' }, [el('canvas', { id: canvasId })]));
            var draw = function () {
              var groups = {};
              rows.forEach(function (r) { if (typeof r[ySel.value] === 'number') { (groups[r[xSel.value]] = groups[r[xSel.value]] || []).push(r[ySel.value]); } });
              var labels = Object.keys(groups);
              barChart(canvasId, labels, [{ label: 'mean ' + ySel.value, data: labels.map(function (k) { return meanStd(groups[k]).mean; }), backgroundColor: labels.map(function (_, i) { return PALETTE[i % PALETTE.length]; }) }], { yTitle: ySel.value });
            };
            xSel.onchange = draw; ySel.onchange = draw; draw();
          }
          card.appendChild(makeTable(rows, cols, { download: file.path, wrap: ['notes'] }));
        }).catch(function (err) { card.appendChild(el('div', { class: 'empty small', text: 'Could not load: ' + err.message })); });
      } else {
        fetchJSON(file.path).then(function (obj) {
          card.appendChild(el('pre', { text: JSON.stringify(obj, null, 2) }));
        }).catch(function (err) { card.appendChild(el('div', { class: 'empty small', text: 'Could not load: ' + err.message })); });
      }
    });
  }

  function renderModels(m) {
    var models = m.models || {};
    var box = clear($('model-cards'));
    function weightsCard(title, list, emptyText) {
      var card = el('div', { class: 'card' }, [el('h3', { text: title })]);
      if (!list || !list.length) { card.appendChild(el('div', { class: 'empty small', text: emptyText })); }
      else { card.appendChild(makeTable(list, ['name', 'size_mb', 'date'], { labels: { size_mb: 'MB' } })); }
      return card;
    }
    box.appendChild(weightsCard('Pretrained weights (COCO)', models.pretrained, 'No pretrained weights found.'));
    box.appendChild(weightsCard('Fine-tuned weights (KIVI_Twin)', models.fine_tuned, 'No fine-tuned model yet; S1 training has not produced a best.pt.'));
    var app = models.app || {};
    var appCard = el('div', { class: 'card' }, [el('h3', { text: 'Model in the smartphone app' })]);
    if (Object.keys(app).length) {
      var dl = el('dl', { class: 'kv' });
      Object.keys(app).forEach(function (k) { dl.appendChild(el('dt', { text: k })); dl.appendChild(el('dd', { text: app[k] })); });
      appCard.appendChild(dl);
    } else { appCard.appendChild(el('div', { class: 'empty small', text: 'MODEL_VERSION not found.' })); }
    box.appendChild(appCard);
  }

  function renderFigures(m) {
    var box = clear($('figure-groups'));
    var groups = {};
    (m.figures || []).forEach(function (f) { (groups[f.group] = groups[f.group] || []).push(f); });
    var order = ['Digital twin', 'Parking regions', 'Capture and labels', 'Training', 'Results', 'Data protection', 'Other'];
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
