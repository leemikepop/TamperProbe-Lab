# Experiments

Every experiment run on this repository is preregistered and auditable. The rules below follow
the follow-up experiments of the TamperProbe thesis.

## Rules

1. **Register first, capture second.** Copy [`PREREGISTRATION_TEMPLATE.md`](PREREGISTRATION_TEMPLATE.md)
   to `<experiment>/README.md`, fill in the question, cells, predictions and decision rules, and
   commit it **before** capturing the first cell. After that commit the registration is frozen:
   changes go only at the end of the file as `## Amendment <YYYY-MM-DD>`, saying what changed and
   why. The commit time is the evidence that the prediction came before the data.
2. **Change one thing at a time.** Neighbouring cells differ in exactly one factor, and each cell's
   `cell.md` names it. A comparison that changes more than one thing (for example a kernel swap) is
   marked "not a single factor; no attribution".
3. **Read conditions from the device, not from memory.** Module state, settings and whether a hook
   actually loaded are read from the device at capture time and pasted into `cell.md`.
4. **Every check must be able to fail.** Capture steps stop when a file count is wrong, the build
   differs from the registered one, or a control did not load; "I enabled it" is not evidence.
5. **Numbers come from tool output only.** Results files paste the raw output of
   `tools/compare_cells.py` or `../scripts/analyze_scan_durations.py`, then interpret it. The paper
   quotes only results files.
6. **Raw data is immutable.** Files under `<experiment>/raw/` are never edited, reformatted or
   re-encoded (keep their line endings).
7. **No device identity.** Never write a device serial, IMEI, account or personal app list into any
   record. Use `adb -s <serial>` with the serial held in an environment variable only. Before
   publishing, check raw exports for anything identifying.
8. **No rates.** A few phones in fixed configurations do not give detection or false-positive rates.
   Fixtures show representation, builds show toolchain compatibility, repeated captures show the
   stability of one configuration; none of them is a rate.

## Development and evaluation

Detectors are revised whenever a new concealment configuration reveals a gap. That is expected, and
it is kept apart from the data the paper reports:

1. **Development.** Any configuration may be tried and any detector changed. Development scans are
   kept outside this directory (or under `<experiment>/dev/`, marked as such) and are never quoted
   as results.
2. **Evaluation.** The repository is tagged, the preregistration names that tag and is committed,
   and every cell is captured from scratch with that build. No development scan is reused.
3. **A fix during evaluation** is an amendment: it names the new tag, and every cell is captured
   again with it, not only the cells that exposed the problem.
4. **Held-out configurations.** Each preregistration lists the configurations that were not used
   during development (for example a device or a module version never installed while detectors
   were being changed). Results on them are reported separately, so a reader can see whether a
   detector only works on what it was tuned on.

## Layout

```
experiments/
  README.md                       this file
  PREREGISTRATION_TEMPLATE.md     copy for each new experiment
  tools/compare_cells.py          provenance check and cross-cell outcome matrix (from the thesis)
  <experiment>/README.md          preregistration, procedure, amendments, results (at the end)
  <experiment>/raw/<cell>/        exports, cell.md, condition notes
```

`tools/compare_cells.py` reads the probe app's export documents. It was written for the thesis,
where exports came from a full and a default selection; in the Lab the probe app exports the full
selection (`--selection full`) and the retrofit hosts export `rootbeer` and `ruru`.

## Experiments

| ID | Experiment | Status |
| --- | --- | --- |
| E1 | Concealment ladders on this code (Pixel P0–P7, P3b, T1, T2; Redmi R0–R4) | done, [`E1-E3/`](E1-E3/), tag `eval-2026-10-v1` |
| E2 | RootBeer contract retrofit (see `../retrofit/`) | done, same cells |
| E3 | Black-box detectors (Duck-Detector 521 and 1023, Native Root Detector, Key Attestation, Ruru) | done, same cells |
| E3′ | Ruru contract retrofit (see `../retrofit/`) | done, same cells |
| E7 | Adaptive attacker: the `xposed-control` positive control | done, cell P7 |
| E4 | Clean-device baseline (Xiaomi 12, cell X0) | done, [`E4/`](E4/), tag `eval-2026-10-v1` |
| E5 | RASP deployability on open-source F-Droid apps | deferred |
| E6 | Full-catalog scan cost | deferred; E1 exports already record scan durations |
