"""Summarise and compare captured cells of the 2026 follow-up experiments.

Reads the export documents that capture_cell.ps1 pulled into ``<experiment>/raw/<cell>/``.

  python compare_cells.py --provenance <cell dir>
      Checks one cell: every export must come from one Sample App build (version, commit,
      dirty flag, build type) and one device. Exits 1 if they do not. Also reports whether
      the repetitions of each selection agree on every detector's outcome and strength.

  python compare_cells.py <cell dir> <cell dir> ... [--selection full|default]
                          [--attr DETECTOR:attributeKey ...]
      Prints an outcome matrix across cells, listing only detectors that are not
      NOT_OBSERVED in every cell (O:S / O:M / O:W observed with strength, ? inconclusive,
      F failed, . not observed), the number observed, and the reference score (WEAK 1,
      MODERATE 2, STRONG 4, INCONCLUSIVE 1; the default threshold is 4). With --attr, also
      prints record attribute values from the first export of each cell, for example
      --attr ZYGISK_SMAPS:singlePageDirtyRegionCount

  python compare_cells.py --keys DETECTOR <cell dir>
      Lists every record attribute key the detector published in that cell, with its value,
      so the right --attr names can be chosen.

Always run with the TamperProbe venv interpreter.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SYMBOL = {"NOT_OBSERVED": ".", "INCONCLUSIVE": "?", "FAILED": "F"}
WEIGHT = {"WEAK": 1, "MODERATE": 2, "STRONG": 4}
INCONCLUSIVE_WEIGHT = 1


def load(cell: Path, selection: str | None = None) -> list[dict]:
    pattern = f"*-{selection}.json" if selection else "*.json"
    files = sorted(cell.glob(pattern))
    if not files:
        sys.exit(f"{cell}: no exports matching {pattern}")
    return [json.loads(f.read_text(encoding="utf-8")) | {"__file": f.name} for f in files]


def outcomes(document: dict) -> dict[str, str]:
    table = {}
    for result in document["scan"]["report"]["results"]:
        outcome = result["outcome"]
        table[result["descriptor"]["id"]] = (
            f"O:{result['strength'][0]}" if outcome == "OBSERVED" else SYMBOL.get(outcome, outcome)
        )
    return table


def reference_score(document: dict) -> int:
    score = 0
    for result in document["scan"]["report"]["results"]:
        if result["outcome"] == "OBSERVED":
            score += WEIGHT.get(result["strength"], 0)
        elif result["outcome"] == "INCONCLUSIVE":
            score += INCONCLUSIVE_WEIGHT
    return score


def provenance(cell: Path) -> int:
    documents = load(cell)
    builds = {json.dumps(d["provenance"]["sampleApp"], sort_keys=True) for d in documents}
    devices = {d["provenance"]["device"]["buildFingerprint"] for d in documents}
    for build in builds:
        print(f"sampleApp: {build}")
    for device in devices:
        print(f"device:    {device}")
    status = 0
    if len(builds) != 1 or len(devices) != 1:
        print("STOP: exports in this cell come from more than one build or device")
        status = 1
    if any(json.loads(b).get("gitDirty") for b in builds):
        print("WARNING: gitDirty is true; the build does not map to an exact commit")
    for selection in ("default", "full"):
        runs = [outcomes(d) for d in load(cell, selection)]
        disagreements = sorted(k for k in runs[0] if len({r.get(k) for r in runs}) > 1)
        print(f"{selection}: {len(runs)} runs, repetition disagreements: "
              f"{disagreements if disagreements else 'none'}")
    return status


def records(document: dict, detector: str):
    for result in document["scan"]["report"]["results"]:
        if result["descriptor"]["id"] != detector:
            continue
        for unit in result.get("unitResults", []):
            for record in unit.get("records", []):
                yield unit, record


def attribute(document: dict, detector: str, key: str) -> str:
    for _, record in records(document, detector):
        attributes = record.get("attributes") or {}
        if key in attributes:
            return str(attributes[key])
    return "-"


def keys(detector: str, cell: Path) -> int:
    document = load(cell, "full")[0]
    found = False
    for unit, record in records(document, detector):
        found = True
        print(f"[{unit['descriptor']['id']}] status={unit.get('collectionStatus')} "
              f"record={record['code']} kind={record['kind']}")
        for key, value in sorted((record.get("attributes") or {}).items()):
            print(f"    {key} = {value}")
    if not found:
        print(f"{detector}: no records in {cell}")
        return 1
    return 0


def compare(cells: list[Path], selection: str, attrs: list[str]) -> int:
    first = {cell: load(cell, selection) for cell in cells}
    tables = {cell: outcomes(docs[0]) for cell, docs in first.items()}
    ids = sorted(next(iter(tables.values())))
    width = max(len(i) for i in ids) + 2
    print(f"selection={selection}")
    print("detector".ljust(width) + "".join(c.name.rjust(12) for c in cells))
    for detector in ids:
        row = [tables[c].get(detector, "-") for c in cells]
        if all(value == "." for value in row):
            continue
        print(detector.ljust(width) + "".join(value.rjust(12) for value in row))
    silent = sum(all(tables[c].get(d) == "." for c in cells) for d in ids)
    print(f"({silent} detectors NOT_OBSERVED in every listed cell are omitted)")
    observed = {c: sum(v.startswith("O") for v in tables[c].values()) for c in cells}
    print("observed".ljust(width) + "".join(str(observed[c]).rjust(12) for c in cells))
    print("reference score".ljust(width) + "".join(str(reference_score(first[c][0])).rjust(12) for c in cells))
    for spec in attrs:
        detector, _, key = spec.partition(":")
        print(spec.ljust(width) + "".join(attribute(first[c][0], detector, key).rjust(12) for c in cells))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("cells", nargs="*", type=Path)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--keys", metavar="DETECTOR")
    parser.add_argument("--selection", choices=("full", "default"), default="full")
    parser.add_argument("--attr", action="append", default=[])
    args = parser.parse_args()
    if args.provenance:
        return provenance(args.provenance)
    if args.keys:
        if len(args.cells) != 1:
            parser.error("--keys takes exactly one cell directory")
        return keys(args.keys, args.cells[0])
    if not args.cells:
        parser.error("give --provenance <cell>, --keys DETECTOR <cell>, or cell directories")
    return compare(args.cells, args.selection, args.attr)


if __name__ == "__main__":
    raise SystemExit(main())
