"""Per-unit collection status and concealable-negative records for the units that declare one.

    python declared_units.py <cell dir> [<cell dir> ...]

For every probe-app export (`*-full.json`) in each cell, prints one line per evidence unit of the
detectors whose adapters declare a concealable negative, as `<unit>=<collectionStatus>/<n>`, where
`n` counts the unit's records whose code ends in `.concealable-negative`. Also prints, per run, the
detectors that are NOT_OBSERVED with no such record in any unit (trusted negatives).

Always run with the TamperProbe venv interpreter.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

DECLARING = ("DANGEROUS_PACKAGES", "KERNEL_CHECK", "LSPOSED_SEPOLICY", "NATIVE_ROOT_SEPOLICY",
             "TEE_ATTESTATION")
SUFFIX = ".concealable-negative"


def cneg_count(unit: dict) -> int:
    return sum(1 for record in unit.get("records", []) if record["code"].endswith(SUFFIX))


def main(paths: list[str]) -> int:
    if not paths:
        print(__doc__)
        return 2
    for cell in map(Path, paths):
        exports = sorted(cell.glob("tamperprobe-scan-*-full.json"))
        if not exports:
            print(f"{cell}: no exports")
            return 1
        for export in exports:
            results = json.loads(export.read_text(encoding="utf-8"))["scan"]["report"]["results"]
            units = [f"{u['descriptor']['id']}={u['collectionStatus']}/{cneg_count(u)}"
                     for r in results if r["descriptor"]["id"] in DECLARING
                     for u in r["unitResults"]]
            trusted = sorted(r["descriptor"]["id"] for r in results
                             if r["outcome"] == "NOT_OBSERVED"
                             and not any(cneg_count(u) for u in r["unitResults"]))
            print(f"{cell.name} {export.name}")
            print("  declared units: " + " ".join(units))
            print(f"  NOT_OBSERVED without any concealable-negative record: {len(trusted)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
