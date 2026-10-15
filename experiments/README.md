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
where exports came from a full and a default selection; the Lab has only the full selection
(`--selection full`).

## Planned

| ID | Experiment | Status |
| --- | --- | --- |
| A | Re-run of the module ablation on this code | not registered |
| B | RootBeer contract retrofit (see `../retrofit/`) | not registered |
| D | RASP deployability on open-source F-Droid apps | not registered; optional |
