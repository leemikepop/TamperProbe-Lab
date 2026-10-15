"""Aggregate per-detector timing from Sample App scan exports.

Reads export documents produced by ``FullScanExportTest`` (export schema 2 or later,
which is where ``durationMicros`` first appears) and reports, per detector, the median,
interquartile range and p95 across repetitions, together with each detector's share of
the scan.

Every run passed in must come from the same device, the same selection and the same
TamperProbe commit. Mixing them silently would produce a table that looks fine and means
nothing, so the script refuses rather than warns.

Usage::

    venv\\Scripts\\python.exe scripts/analyze_scan_durations.py <file-or-directory>...
    venv\\Scripts\\python.exe scripts/analyze_scan_durations.py runs/ --format markdown
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

MINIMUM_EXPORT_SCHEMA = 2


class InconsistentRunsError(RuntimeError):
    """Raised when the supplied runs are not comparable with one another."""


def load_runs(paths: Sequence[Path]) -> List[Dict[str, Any]]:
    """Load every export document under the given files or directories."""
    files: List[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(path.glob("*.json")))
        elif path.is_file():
            files.append(path)
        else:
            raise FileNotFoundError(f"No such file or directory: {path}")
    if not files:
        raise FileNotFoundError("No export documents found in the given paths")

    runs: List[Dict[str, Any]] = []
    for file in files:
        document = json.loads(file.read_text(encoding="utf-8"))
        schema = document.get("exportSchemaVersion", 0)
        if schema < MINIMUM_EXPORT_SCHEMA:
            raise InconsistentRunsError(
                f"{file.name}: export schema {schema} carries no per-detector timing; "
                f"schema {MINIMUM_EXPORT_SCHEMA} or later is required"
            )
        document["__file"] = file
        runs.append(document)
    return runs


def comparability_key(run: Dict[str, Any]) -> Tuple[str, str, int, str, str]:
    """The facts that must match for two runs to belong in the same table.

    The Sample App's build type is part of it: a debug build compiles the native engine
    without optimisation, so a debug and a release run of the same commit measure
    different code and must never be averaged together.
    """
    provenance = run["provenance"]
    device = provenance["device"]
    return (
        device["buildFingerprint"],
        provenance["sampleApp"]["gitCommit"],
        len(run["scan"]["requestedDetectorIds"]),
        provenance["coreBuild"]["catalogVersion"],
        provenance["sampleApp"].get("buildType", "unknown"),
    )


def assert_comparable(runs: Sequence[Dict[str, Any]]) -> None:
    keys = {comparability_key(run) for run in runs}
    if len(keys) != 1:
        lines = [
            f"  {run['__file'].name}: fingerprint={comparability_key(run)[0]} "
            f"commit={comparability_key(run)[1]} detectors={comparability_key(run)[2]} "
            f"buildType={comparability_key(run)[4]}"
            for run in runs
        ]
        raise InconsistentRunsError(
            "Runs differ in device, commit, selection size or catalog version:\n"
            + "\n".join(lines)
        )


def summarise(values: Sequence[float]) -> Dict[str, float]:
    ordered = sorted(values)
    median = statistics.median(ordered)
    if len(ordered) >= 4:
        quartiles = statistics.quantiles(ordered, n=4, method="inclusive")
        iqr = quartiles[2] - quartiles[0]
    else:
        # Too few points for a quartile to mean anything; report the full spread and say so.
        iqr = ordered[-1] - ordered[0]
    index = min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1))))
    return {"median": median, "iqr": iqr, "p95": ordered[index], "n": len(ordered)}


def collect(runs: Sequence[Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, float]], Dict[str, float], Dict[str, float]]:
    per_detector: Dict[str, List[float]] = {}
    scan_totals: List[float] = []
    detector_sums: List[float] = []

    for run in runs:
        report = run["scan"]["report"]
        total = 0.0
        for result in report["results"]:
            micros = float(result.get("durationMicros", 0))
            per_detector.setdefault(result["descriptor"]["id"], []).append(micros)
            total += micros
        detector_sums.append(total)
        # durationMillis is the client-side span, which includes the JNI hop and the
        # Kotlin-side work around it. The gap against the detector sum is SDK overhead.
        scan_totals.append(float(report["durationMillis"]) * 1000.0)

    summaries = {name: summarise(values) for name, values in per_detector.items()}
    return summaries, summarise(scan_totals), summarise(detector_sums)


def render(
    runs: Sequence[Dict[str, Any]],
    summaries: Dict[str, Dict[str, float]],
    scan_total: Dict[str, float],
    detector_sum: Dict[str, float],
    markdown: bool,
) -> str:
    provenance = runs[0]["provenance"]
    device = provenance["device"]
    lines: List[str] = []
    lines.append(
        f"Device: {device['model']} (Android {device['androidRelease']}, API {device['apiLevel']})"
    )
    lines.append(
        f"Commit: {provenance['sampleApp']['gitCommit']}"
        f"{' (dirty tree)' if provenance['sampleApp']['gitDirty'] else ''}"
        f"  build={provenance['sampleApp']['buildType']}"
    )
    lines.append(
        f"Selection: {len(runs[0]['scan']['requestedDetectorIds'])} detectors"
        f"   Repetitions: {int(scan_total['n'])}"
    )
    lines.append("")

    median_sum = detector_sum["median"]
    header = ("detector", "median ms", "IQR ms", "p95 ms", "share")
    rows = []
    for name, values in sorted(summaries.items(), key=lambda item: -item[1]["median"]):
        share = (values["median"] / median_sum * 100.0) if median_sum else 0.0
        rows.append(
            (
                name,
                f"{values['median'] / 1000.0:.2f}",
                f"{values['iqr'] / 1000.0:.2f}",
                f"{values['p95'] / 1000.0:.2f}",
                f"{share:.1f}%",
            )
        )

    if markdown:
        lines.append("| " + " | ".join(header) + " |")
        lines.append("| --- | ---: | ---: | ---: | ---: |")
        for row in rows:
            lines.append("| " + " | ".join(row) + " |")
    else:
        width = max(len(row[0]) for row in rows) if rows else 8
        lines.append(f"{header[0]:<{width}} {header[1]:>10} {header[2]:>9} {header[3]:>9} {header[4]:>7}")
        for row in rows:
            lines.append(f"{row[0]:<{width}} {row[1]:>10} {row[2]:>9} {row[3]:>9} {row[4]:>7}")

    lines.append("")
    lines.append(f"Sum of detector medians : {median_sum / 1000.0:.1f} ms")
    lines.append(f"Client-observed scan    : {scan_total['median'] / 1000.0:.1f} ms (median)")
    overhead = scan_total["median"] - median_sum
    lines.append(
        f"SDK overhead outside detectors: {overhead / 1000.0:.1f} ms "
        f"({overhead / scan_total['median'] * 100.0:.1f}% of the scan)"
        if scan_total["median"]
        else "SDK overhead outside detectors: unavailable"
    )

    zero = [name for name, values in summaries.items() if values["median"] == 0]
    if zero:
        lines.append("")
        lines.append(
            "WARNING: these detectors reported a zero median duration, which usually means "
            "the timing is not wired up rather than that they are free:"
        )
        for name in sorted(zero):
            lines.append(f"  - {name}")
    return "\n".join(lines)


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path, help="Export documents or directories")
    parser.add_argument(
        "--format",
        choices=("text", "markdown"),
        default="text",
        help="Output format; markdown is ready to paste into a thesis record",
    )
    arguments = parser.parse_args(list(argv))

    try:
        runs = load_runs(arguments.paths)
        assert_comparable(runs)
    except (FileNotFoundError, InconsistentRunsError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    summaries, scan_total, detector_sum = collect(runs)
    print(render(runs, summaries, scan_total, detector_sum, arguments.format == "markdown"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
