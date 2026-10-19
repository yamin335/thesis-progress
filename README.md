# Thesis progress dashboard

Live progress of the master's thesis **Computer Vision Approach to Identify Parked Vehicles Based on
Smartphone Camera Data** (Technische Hochschule Ingolstadt, Faculty of Electrical Engineering and
Information Technology, AImotion institute): https://yamin335.github.io/thesis-progress/

The page is static. `index.html` plus `assets/` render whatever is in `data/` and `figures/`; those two
folders are written by `experiments/publish_progress.py` in the (private) thesis repository and
committed here. Nothing on this page is typed by hand except `docs/progress_notes.md` in the thesis
repository, which supplies the "Current status" box and the dated timeline entries.

What is shown:

| Section | Source in the thesis repository |
|---|---|
| Overview, Plan | `docs/thesis_plan.md` (status line, phase checklists, deadlines) and `docs/progress_notes.md` |
| Data | `experiments/results/kt_matrix_manifest.csv`, `datasets/kt_v1/MANIFEST.md`, label statistics |
| Training | `models/fine_tuned/<run>/results.csv`, `finetune_record.json`, `train_matrix.log` |
| Experiments | `docs/experiment_plan.md` (EXP-A to EXP-J) and every file in `experiments/results/` |
| Models | `models/pretrained/`, `models/fine_tuned/*/best.pt`, the app's `MODEL_VERSION` |
| Figures | `docs/figures/*.png` with captions from `docs/figures/captions.json` |
| Activity | `git log` of the thesis and app repositories (messages only) |

Updating: in the thesis repository run

```bash
venv-cv/bin/python experiments/publish_progress.py --push            # once
venv-cv/bin/python experiments/publish_progress.py --push --every 600  # while training runs
```

Privacy: the dashboard contains synthetic imagery and aggregate numbers only. No real recording,
frame or personal data is ever copied here; the collector does not read `datasets/real_v1` and
refuses figure files whose name marks them as real or anonymised footage. Names of third persons
are not published; the supervisor is referred to by the organisational unit.

Libraries (loaded from cdnjs): Chart.js 4.4.1, PapaParse 5.4.1, marked 12.0.0. No cookies, no
analytics; the light/dark choice is kept in the browser's local storage only.
