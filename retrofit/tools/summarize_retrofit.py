"""Summarise retrofit exports: what each upstream "clean" rests on.

Reads export documents written by the retrofit hosts (retrofit-<time>-<selection>.json). For every
check whose upstream verdict was not a positive, it classifies each evidence unit:

  no_answer      the channel answered for no target (unit UNAVAILABLE), so the upstream "clean"
                 came from a channel that did not answer (Rule 1/2)
  concealable    the channel answered "absent", but the unit declares that concealment can
                 manufacture that absence (Rule 3)
  trusted        the channel answered "absent" and no concealment is declared for it

and the check as a whole: no_answer if no unit answered, concealable or trusted if every answered
unit is, mixed otherwise. Checks with an upstream positive are "positive"; checks whose upstream
code threw are "failed". `partial` marks a unit that answered for only some of its targets.

    python retrofit/tools/summarize_retrofit.py <export.json | cell dir> ...
    python retrofit/tools/summarize_retrofit.py --json <export.json | cell dir> ...

These are counts over fixed configurations, not detection or false-positive rates.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

CHECK_CLASSES = ("positive", "failed", "no_answer", "concealable", "mixed", "trusted")


def load(paths: list[Path]) -> list[tuple[Path, dict]]:
    files: list[Path] = []
    for path in paths:
        files.extend(sorted(path.glob("retrofit-*.json")) if path.is_dir() else [path])
    if not files:
        sys.exit("no retrofit exports found")
    documents = []
    for file in files:
        document = json.loads(file.read_text(encoding="utf-8"))
        if "retrofit" not in document:
            sys.exit(f"{file}: not a retrofit export (no 'retrofit' block)")
        documents.append((file, document))
    return documents


def record(unit: dict, suffix: str) -> dict | None:
    return next((r for r in unit["records"] if r["code"].endswith(suffix)), None)


def classify_unit(unit: dict) -> dict:
    coverage = record(unit, ".coverage")
    issues = unit["issues"]
    reasons = sorted({issue["attributes"].get("reason", issue["code"]) for issue in issues})
    if unit["collectionStatus"] == "UNAVAILABLE" or coverage is None:
        unit_class = "no_answer"
        attempted = sum(int(i["attributes"].get("count", "0")) for i in issues)
        answered = 0
    else:
        attributes = coverage["attributes"]
        unit_class = "concealable" if attributes.get("concealable") == "true" else "trusted"
        attempted = int(attributes["attemptedCount"])
        answered = int(attributes["answeredCount"])
    return {
        "unit": unit["descriptor"]["id"],
        "class": unit_class,
        "partial": unit["collectionStatus"] == "PARTIAL",
        "answered": answered,
        "attempted": attempted,
        "reasons": reasons,
    }


def classify_check(check: dict, result: dict) -> dict:
    summary = {
        "detector": check["detectorId"],
        "upstreamVerdict": check["upstreamVerdict"],
        "outcome": result["outcome"],
        "units": [],
    }
    if check.get("upstreamFailed"):
        return summary | {"class": "failed"}
    if check["upstreamPositive"]:
        return summary | {"class": "positive"}
    units = [classify_unit(unit) for unit in result["unitResults"]]
    answered = {u["class"] for u in units if u["class"] != "no_answer"}
    if not answered:
        check_class = "no_answer"
    elif len(answered) == 1:
        check_class = answered.pop()
    else:
        check_class = "mixed"
    return summary | {"class": check_class, "units": units}


def summarize(document: dict) -> dict:
    results = {r["descriptor"]["id"]: r for r in document["scan"]["report"]["results"]}
    checks = [classify_check(c, results[c["detectorId"]]) for c in document["retrofit"]["checks"]]
    clean = [c for c in checks if c["class"] not in ("positive", "failed")]
    return {
        "selection": document["retrofit"]["selection"],
        "upstream": document["retrofit"]["upstream"],
        "aggregate": document["retrofit"]["aggregate"],
        "device": document["provenance"]["device"]["buildFingerprint"],
        "host": document["provenance"]["host"],
        "checks": checks,
        "counts": dict(Counter(c["class"] for c in checks)),
        "upstreamCleanChecks": len(clean),
        "upstreamCleanResting": {
            cls: sum(1 for c in clean if c["class"] == cls) for cls in ("no_answer", "concealable", "mixed", "trusted")
        },
    }


def render(file: Path, summary: dict) -> str:
    lines = [
        f"== {file.name}",
        f"upstream: {summary['upstream']['name']} {summary['upstream']['revision'][:12]}; "
        f"{summary['aggregate']['method']} = {summary['aggregate']['verdict']}",
        f"host: targetSdk {summary['host']['targetSdk']}, package visibility {summary['host']['packageVisibility']}",
        "",
    ]
    for check in summary["checks"]:
        lines.append(f"{check['detector']:<32} upstream {check['upstreamVerdict']:<18} -> {check['class']}")
        for unit in check["units"]:
            partial = " partial" if unit["partial"] else ""
            reasons = f"  [{', '.join(unit['reasons'])}]" if unit["reasons"] else ""
            lines.append(
                f"    {unit['unit']:<48} {unit['class']}{partial} "
                f"{unit['answered']}/{unit['attempted']} answered{reasons}"
            )
    resting = summary["upstreamCleanResting"]
    lines += [
        "",
        f"upstream clean checks: {summary['upstreamCleanChecks']}; resting on: "
        + ", ".join(f"{name} {resting[name]}" for name in ("no_answer", "concealable", "mixed", "trusted")),
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--json", action="store_true", help="print the summaries as JSON")
    args = parser.parse_args()
    summaries = [(file, summarize(document)) for file, document in load(args.paths)]
    if args.json:
        print(json.dumps([{"file": file.name} | s for file, s in summaries], indent=2))
    else:
        for file, summary in summaries:
            print(render(file, summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
