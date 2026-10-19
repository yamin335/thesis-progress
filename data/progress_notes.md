# Progress notes

Short, dated notes for the public progress dashboard (https://yamin335.github.io/thesis-progress/).
`experiments/publish_progress.py` reads the **Current status** list as key/value pairs and the
**Log** as dated entries (newest first). Keep entries to one or two sentences; no personal data, no
real images. Everything else on the dashboard is collected automatically from the repository.

## Current status

- **Phase:** Phase 3 complete (53-run synthetic capture matrix, dataset `kt_v1` with 14 910 frames). Next: training stage S1 and the Phase 4 pipeline work.
- **Training S1:** running since 2026-10-20 00:52 (first run yolov8n seed 0, about 1.6 min per epoch); 12 runs (YOLOv8n, YOLO11n, YOLO26n, YOLO26s × seeds 0, 1, 2) on `kt_v1`, fixed recipe in `docs/training_plan.md`.
- **Real data / GDPR:** data-protection package v0.2 sent to the supervisor (week of 2026-10-12); the supervisor answers the DPO's questions (organisational unit, confirmation of measures M1 to M16). Recording waits for the DPO's release. Public privacy notice: https://yamin335.github.io/parked-vehicles-dsi/
- **App:** Kotlin Multiplatform demonstrator builds on Android and passes 27 shared tests; carries the placeholder COCO `yolov8n.onnx`; not yet measured on a device.
- **Writing:** chapter skeleton pending (thesis template decision D11); Method chapter draft lives in `docs/thesis_plan.md` §3.
- **Deadlines:** technical cut-off 2026-11-15 (moved from 2026-10-31 on 2026-10-20); submission 2027-01-15.

## Log

- **2026-10-20** S1 training matrix started (smoke run passed: 1.8 min per epoch, mAP50-95 0.70 after one epoch). Phase 4 item 4.1 done: the pipeline refuses a run captured on a different map than the region file. Item 5.1 done: a Python parity test replays the 790-step decision-rule vectors the smartphone app also tests against (all pass), the evaluation self-check passes, and one complete result row with confidence intervals was produced on a kt_v1 test run.
- **2026-10-20** Technical cut-off moved to 2026-11-15; four technical weeks from today: S1 training (Oct 20 to 23), pipeline and harness items 4.1 to 5.1 (by Oct 25), synthetic experiments (by Nov 1), real recording if released (target Nov 6), S2/S3 and results freeze (Nov 15).
- **2026-10-19** Progress dashboard created: `experiments/publish_progress.py` collects plan, dataset, matrix, training, results, models, figures and commits into the public site.
- **2026-10-12** Answered the DPO's second reply with data-protection package v0.2: German project description, privacy-notice texts, two VVT entries, one 110 m recording zone on Goethestraße (B 16a) from no. 12 a (Sparkasse) to the end of no. 14, one recording day, raw-footage window 72 h. Public privacy notice page published (DE/EN). Submission deadline set to 2027-01-15.
- **2026-10-11** Full 53-run capture matrix on `KIVI_Twin` captured and checked (frame counts, label statistics, overlays); three stalled windshield runs diagnosed (angled bay R25-1249) and recaptured; dataset `kt_v1` exported and verified (no split leakage, road 2 test-only). Plan v2 written; Town10 pilot artefacts archived under tag `town10-stand-in-final`.
- **2026-10-06** 40 parking spots populated on `KIVI_Twin` from the OpenDRIVE parking spaces and the measured Sparkasse lot.
- **2026-10-01** CARLA server, geometry and evaluation self-checks, and GPU PyTorch confirmed on the rebuilt machine.
- **2026-09-17** Machine reinstalled (Ubuntu 26.04); `KIVI_Twin` CARLA 0.9.14 build installed; Python environments rebuilt.
- **2026-07-29** Plan v1 on the Town10 stand-in map: pipeline, evaluation harness, EXP-A to EXP-F, failure analysis.
