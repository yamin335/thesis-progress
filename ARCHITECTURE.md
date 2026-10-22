# Dashboard architecture

State of the progress dashboard as of 2026-10-21 (page version `v=20261022c`, collector 1.5.1).
Read this before changing `index.html`, `assets/app.js`, `assets/style.css` or the collector
`experiments/publish_progress.py` in the thesis repository, and update it in the same commit as
any change it describes. The README covers what a reader sees; this file covers how it is built.

## 1. Data flow

```
thesis repository (private)                      dashboard repository (public, this one)
───────────────────────────────                  ─────────────────────────────────────────
docs/thesis_plan.md        ─┐                    .plain/            plaintext staging, git-ignored
docs/progress_notes.md      │                    ├─ data/manifest.json
docs/experiment_plan.md     │  publish_progress  ├─ data/results/*.csv|json
docs/figures/*.png + captions.json ──────────►   ├─ data/training/<run>/results.csv, log tail
experiments/results/*       │  (collect, write   ├─ data/progress_notes.md, dataset card
models/fine_tuned/<run>/*   │   plaintext, then  └─ figures/*.png
models/pretrained/*, app MODEL_VERSION           encrypt_site()  ──►  vault/<path>.enc  (committed)
git log of both repositories ─┘                                      vault/verify.json, vault/index.json
                                                 index.html + assets/  (hand-written page, committed)
```

* The collector runs in the thesis repository: `venv-cv/bin/python experiments/publish_progress.py
  [--push] [--every 600]`. It writes plaintext into `.plain/`, encrypts every file under `data/`
  and `figures/` into `vault/<same path>.enc`, and with `--push` commits and pushes only when
  something changed (`vault/index.json` keeps a SHA-256 per plaintext file; unchanged files are not
  re-encrypted, vanished files are removed from the vault).
* Encryption: AES-256-GCM, file layout `nonce(12) || ciphertext || tag(16)`. Key = PBKDF2-HMAC-SHA256
  over `user:password` with the salt and iteration count from `vault/verify.json`, which also holds
  a verifier (`"thesis-progress ok"` encrypted under the key). Credentials:
  `~/.config/thesis-progress/credentials.json` on the author's machine only.
* The page fetches `vault/<path>.enc` for every plaintext path named in the manifest and decrypts
  in the browser (Web Crypto). Nothing is sent anywhere; GitHub Pages serves ciphertext.
* Refresh: the page re-fetches the manifest every 5 minutes and re-renders only when
  `generated_at` changed. Open/closed state of the experiment groups survives a re-render.

## 2. Manifest schema (`data/manifest.json`)

Top level: `generated_at`, `generator_version`, `thesis_title`, `repo` and `app_repo`
(`{short, dirty, branch}`), then one key per section.

| Key | Written by | Shape (what the page relies on) |
|---|---|---|
| `plan` | `parse_plan` | `status`, `deadline`, `technical_cutoff`, `phases[]` = `{title, done, total, items[]{done, text}}`. The writing phase is dropped (`WRITING_RE`). |
| `notes_status` | `parse_notes` | `[{key, value}]` from the "Current status" list of `progress_notes.md`. |
| `timeline` | `build` | `[{date, text, source}]` newest first: notes log + plan hand-off history, writing entries dropped. |
| `dataset` | `dataset_info` | `splits[]{split, frames, boxes, runs}` incl. `total`; `classes{id: name}`; `class_counts{split: {per_class}}`; `manifest_md` path. |
| `matrix` | `matrix_info` | `present`, `csv` path, `runs`, `by_status{}`, `frames_on_disk`. |
| `training` | `training_info`, `training_stages` | `runs[]{name, arch, seed, status, epochs_done, best_epoch, best_map50_95, last_map50_95, files{results, record, log}, ...}`, `planned_runs`, `plan{archs, seeds, epochs, patience, image_size}`, `log_tail` path, `running`; `ladder{stages[]{stage, data, purpose, status, detail}, note}` from `docs/training_plan.md` §2 (S0 done with EXP-A rows, S1 by run count, S2/S3 by plan item 7.6). |
| `experiments` | `experiments_info` | see §3. |
| `models` | `models_info` | `pretrained[]{name, format, size_mb, date}`; `fine_tuned[]{name, arch, dataset, seed, image_size, best_epoch, best_val_map50_95, best_val_map50, minutes, size_mb, date}` (from `finetune_record.json`); `app_models[]{id, family, arch, size_mb, classes, verified, nms_free_mb, nms_free_verified, nms_free_agreement, val_map50_95, trained_px}` from the app's `models.json`; `app_meta{generated_at, thesis_commit, input_size, models, files, total_mb, header{}}`. |
| `figures` | `figures_info` | `[{file, name, group, caption, date}]`; files whose name marks real or anonymised footage are never published. |
| `commits`, `app_commits` | `git_log` | `[{hash, date, subject}]`, writing-related subjects dropped. |

### 3. Experiments (`manifest.experiments`)

```
{ "experiments": [ { id, name, purpose, data_source, method, output, metrics,   ← docs/experiment_plan.md table
                     status,            "done" | "running" | "results" | "planned"
                     plan_item,         text of the plan checklist item naming the experiment earliest
                     rows, columns,     rows of all_results.csv whose experiment_id is <id> or starts with "<id>-",
                                        plus derived columns parsed from the id when present: input_px,
                                        t_parked_s, max_range_m (35 for untagged EXP-B rows), seed
                     rows_file,         data/results/<id>_rows.csv          (only when rows > 0)
                     details, details_file,   count and bundle data/results/<id>_details.json = {folder: result.json}
                     summary_file,      data/results/<id>_summary.json      (copy of experiments/results/exp_<x>_summary.json)
                     figures[],         names of docs/figures/exp_<x>_*.png (served through manifest.figures)
                     log_tail[],        last lines of experiments/results/exp_<x>.log
                     updated } ],
  "files": [ { name, path, description, updated, size_kb, rows?, columns? } ],   ← result files of no experiment
  "columns": [...33 schema columns...], "total_rows": n }
```

Status rules: `done` when the plan item is ticked; `running` when the last `--- ` line of the
sweep log is a `start`; `results` when rows exist; else `planned`. Files produced for an earlier
run that no longer exist are deleted from `data/results/` so the vault drops them too.

Conventions every experiment script must follow (also in the thesis repository's
`experiments/README.md`): result folders `experiments/results/<EXP-X>-*/result.json`, aggregate
`exp_<x>_summary.json`, figures `docs/figures/exp_<x>_*.png`, sweep log `exp_<x>.log`.

The summary "cells" shape that gets pivot tables and charts:
`{ cells: [ { <group>, <row>, <col>, runs, <metric>: {mean, std, ci95_runs: [lo, hi]}, ... } ],
axes: {group, row, col, col_unit, cell_note}   (default group "view", row "model", col "size", unit " px"),
best_by_<x>{group: {field: value}}, description, settings, ci }`. EXP-A uses the default axes,
EXP-B `{group: "view", row: "run", col: "t_parked", col_unit: " s"}`. Every `best_by_*` object is
printed as a line under the tables. Any other JSON summary is shown as a tree.

## 4. Page structure (`index.html` ids ↔ renderers in `assets/app.js`)

| Section id | Elements the script fills | Renderer |
|---|---|---|
| `login` | `login-form`, `login-user`, `login-password`, `login-toggle`, `login-remember`, `login-submit`, `login-error` | `setupLogin`, `attemptLogin`, `verifyKey`, `unlock`, `lock` |
| `topbar` | `stamp`, `thesis-title`, `theme-toggle`, `logout`, `tabs` | `renderHeader`, `setupTheme`, `setupNav` |
| `main` → `error` | error banner for manifest failures | `load` |
| `overview` | `overview-cards`, `status-card` | `renderOverview` |
| `timeline` | `timeline-list` | `renderTimeline` |
| `plan` | `phase-list` | `renderPlan` |
| `data` | `data-cards`, `chart-splits`, `chart-classes`, `chart-weather`, `chart-views`, `matrix-table`, `dataset-card` | `renderData` |
| `training` | `training-stages` (ladder table), `training-cards`, `training-runs`, `training-metric`, `chart-training-curves`, `chart-training-best`, `training-log-wrap`, `training-log` | `renderTraining`, `populateMetricSelect`, `drawTrainingCurves` |
| `experiments` | `experiment-cards`, `experiment-groups`, `other-results` | `renderExperiments`, `renderExperimentGroup`, `renderCellSummary`, `csvChartControls`, `figureStrip`, `jsonRoot` |
| `models` | `model-cards` (`.stack`: a `.grid.wide` row with the pretrained and fine-tuned tables, then the full-width app-bundle table) | `renderModels` |
| `figures` | `figure-groups` | `renderFigures`, `openLightbox` |
| `activity` | `commits-thesis`, `commits-app` | `renderActivity` |

`renderAll` calls every renderer in that order; `load(first)` fetches the manifest and calls it.
Everything is built with `el(tag, attrs, children)`; there is no templating and no inline script
(the CSP in `index.html` allows scripts from `self` and cdnjs only, styles inline, images from
`self`, `blob:` and `data:`).

### Experiments section, top to bottom

1. **Cards strip** (`experiment-cards`): one `a.exp-card` per experiment, status pill, row and
   record counts; clicking opens and scrolls to the group.
2. **Groups** (`experiment-groups`): one `details.exp#exp-<id>` per experiment whose status is not
   `planned`, built by `renderExperimentGroup`. Body cards in order: plan description (`dl.kv`),
   sweep log tail (running only), **Summary** (pivot table + grouped bar chart per view, metric
   selector; `renderCellSummary`), **Figures** (`figureStrip`), **Result rows** (chart with
   metric/grouping selectors from `csvChartControls`, then `makeTable` with the 12 `SHORT_COLUMNS`
   or all columns), **Per-row result records** (`details.exp-details`, loads the details bundle on
   first open, one `details.json` per record, searchable, each record rendered by `jsonRoot` on
   its first open).
   A `details.exp.planned` block lists the planned experiments as a compact table.
3. **Other result files** (`other-results`): one `details.exp.file` per file; CSV → chart controls
   + table with download link; JSON → download link + `jsonRoot` tree.

### Helpers worth knowing

* `el()`: `class`, `html`, `text`, `on<event>` handlers; attribute values `null`, `undefined` and
  `false` are **omitted**, `true` becomes a bare attribute. Always pass booleans for `open`.
* `clear(node)`: empties and returns the node; returns a detached `div` when the node is missing so
  a stale cached script cannot crash the whole render.
* `makeChart(target, config)`: `target` is a canvas element or an id; charts are registered in
  `state.charts` by canvas id and destroyed before a canvas is reused. `barChart`, `emptyChart`,
  `showCanvas` wrap it. **A chart must be created on a canvas that is in the document or appended
  to it in the same tick**; `renderCellSummary` and `csvChartControls` therefore take a `mount`
  element, append their markup to it, and only then draw.
* `makeTable(rows, columns, opts)`: filter box, click-to-sort headers, numeric right-alignment,
  `opts.download` (decrypted download), `opts.render{col: fn}`, `opts.wrap[]`, `opts.labels{}`,
  `opts.limit` (1000).
* `jsonView` / `jsonRoot`: JSON tree. Objects and arrays become `details.json` (collapsed below the
  first level), arrays of uniform flat objects become a table, scalars and short arrays stay inline.
* `lazyDetails(det, loader)`: runs `loader` once, the first time the `<details>` is open, and records
  the open state in `openGroups[det.id]` so re-renders keep the reader's choices.
* `fetchText` / `fetchJSON` / `fetchCSV` / `vaultImage` all go through `vaultFetch` (decrypt).
  `vaultImage` caches blob URLs in `state.blobUrls`; `lock()` revokes them.

## 5. Styling

`assets/style.css`: CSS variables on `:root` with a dark set under
`@media (prefers-color-scheme: dark) :root:not([data-theme="light"])` and `:root[data-theme="dark"]`;
the theme button stores the choice in `localStorage` (`progress-theme`) and re-renders so the
charts pick up the new colours (`chartDefaults`). Layout: `.grid` (230 px cards), `.grid.wide`
(380 px), `.card`, `.kv`; pills `.pill.ok|warn|bad|gray|accent` (+`.live` pulses); tables
`.table-tools`, `.table-wrap`, `table.data`; charts `.chart`, `.chart.tall`, `.chart.short`;
experiments `.exp-cards`, `a.exp-card`, `details.exp` (+`.planned`, `.file`), `.exp-body`,
`details.exp-details`, JSON tree `.json-root`, `details.json`, `.json-leaf`, `.json-key`,
`.json-val`. Every `<details>` used as a block hides the native marker and draws its own
`▸` / `▾` through `::before`, so a new block type must add that rule or it has no indicator.
Phone width (≤ 640 px): single-column grids, two-column experiment cards.

## 6. Rules that are easy to break

1. **Bump the asset version** (`?v=YYYYMMDDx` on both `app.js` and `style.css` in `index.html`)
   whenever either file changes; `tools/check_page.py` fails if the two differ.
2. **Nothing about the manuscript** on the page: the collector filters plan phases, timeline
   entries and commit subjects with `WRITING_RE`; progress notes must not mention the thesis text.
3. **Privacy**: synthetic imagery and aggregate numbers only; no real frames, no personal data,
   no third-person names (the supervisor is referred to by the unit). Figure names starting with
   `real` or containing `real_`/`anon` are refused by the collector.
4. **CSP**: no inline scripts, no new script hosts; libraries only from cdnjs with pinned versions
   (Chart.js 4.4.1, PapaParse 5.4.1, marked 12.0.0).
5. **Charts in collapsed blocks**: draw after the block is open and mounted; `lazyDetails` exists
   for that. Do not call chart builders on detached subtrees.
6. **The fixed 33-column result schema** is not the page's business, but the per-experiment row
   file is a verbatim subset of `all_results.csv`; new columns appear automatically, new
   experiments need no page change as long as the file conventions in §3 are followed.
7. **A running collector loop is stale after an edit**: `--every` loops now re-execute themselves
   when `publish_progress.py` changes on disk (collector 1.4.1); before that, an edited collector
   had to be restarted by hand or the old process overwrote the new manifest on its next cycle.
8. **Ids are the contract**: every id the script looks up must exist in `index.html`; the check
   script cross-references them.

## 7. Checks before publishing

```bash
cd ~/Documents/thesis-progress
~/Documents/thesis-parked-vehicles/venv-cv/bin/python tools/check_page.py    # parse, ids, versions, CSP, open: usage
```

Then, from the thesis repository, publish once and verify that the vault decrypts with the
credentials (the collector's own round trip, or the snippet in HOW_TO_RUN.md Step 7). No browser
exists on the build machine; after a page change, open the live page, sign in, and check the
browser console once. The expected first paint: overview cards, timeline, plan phases (first open),
data charts, training curves, experiment cards and the first experiment group open with its two
summary charts drawn, models, figures, commits.

## 8. Change log

* 2026-10-19: first version (plain data, no login).
* 2026-10-20: encrypted vault and login; writing progress removed; versioned asset URLs.
* 2026-10-20: experiments section rebuilt as per-experiment groups; JSON tree view; summary charts.
* 2026-10-21: `el()` omits null/false attributes (closed `<details>` by default), charts mount
  before drawing (summary charts visible on first load), lazy loading with preserved open state,
  marker on the records block, `tools/check_page.py`, this document.
* 2026-10-21 (later): Models section as three stacked tables (pretrained, fine-tuned with training
  record, app bundle from the app's `models.json`); collector 1.4. Then: the two weight tables side
  by side, the app bundle full width underneath (`v=20261021c`). The stale loop republished the
  old manifest once (empty app table); the loop now restarts itself on source changes (1.4.1).
* 2026-10-21 (EXP-B): summary renderer reads `axes` so other row/column keys work (`v=20261021d`).
* 2026-10-22: training ladder table (S0 to S3 with status) above the S1 cards; plan header explains
  the phase numbering (`v=20261022a`, collector 1.5).
* 2026-10-22 (later): derived row columns (input size, t_parked, range rule, seed) in the rows CSV;
  the rows chart can group by them and the short table shows them (`v=20261022b`, collector 1.5.1).
* 2026-10-22 (EXP-F): summary columns may be text (weather names); numeric columns still sort by
  value (`v=20261022c`).
