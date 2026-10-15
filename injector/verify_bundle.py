#!/usr/bin/env python3

import hashlib
import json
import sys
from pathlib import Path


REQUIRED_FILES = {
    "rasp-adapter.jar",
    "detections_manifest.json",
    "queries.xml",
    "manifest-fragment.xml",
    "attestation_status.json",
    "attestation_roots.json",
    "package_indicators.txt",
    "package_intent_actions.txt",
    "bundle-metadata.json",
}
SUPPORTED_ABIS = {"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_bundle.py <bundle_directory>", file=sys.stderr)
        return 2

    root = Path(sys.argv[1]).resolve()
    missing = sorted(name for name in REQUIRED_FILES if not (root / name).is_file())
    if missing:
        raise ValueError(f"RASP bundle is missing required files: {missing}")

    metadata = json.loads((root / "bundle-metadata.json").read_text(encoding="utf-8"))
    if metadata.get("bundleSchemaVersion") != 1 or metadata.get("edition") != "lab":
        raise ValueError("Not a TamperProbe-Lab RASP bundle (schema 1, edition lab)")
    if metadata.get("minSdkVersion") != 29:
        raise ValueError("RASP bundle metadata must declare minSdkVersion 29")
    if metadata.get("wireSchemaVersion") != 1:
        raise ValueError("RASP bundle metadata must declare wire schema version 1")
    manifest = json.loads((root / "detections_manifest.json").read_text(encoding="utf-8"))
    if (
        manifest.get("schemaVersion") != 1
        or manifest.get("catalogVersion") != "1.0"
        or manifest.get("evidenceContractVersion") != 1
        or not isinstance(manifest.get("detections"), list)
        or not isinstance(manifest.get("evidenceDomains"), list)
    ):
        raise ValueError("RASP bundle must contain a v1 detector catalog")
    # Counts are declared in bundle-metadata.json by the build that staged this manifest, so the
    # check follows the catalog instead of a number written here by hand.
    declared = metadata.get("catalogCounts")
    actual = {
        "evidenceDomains": len(manifest["evidenceDomains"]),
        "detectors": len(manifest["detections"]),
        "evidenceUnits": sum(
            len(item.get("evidenceUnits", [])) for item in manifest["detections"]
        ),
    }
    if not isinstance(declared, dict) or declared != actual:
        raise ValueError(
            f"RASP bundle catalog counts do not match bundle metadata: "
            f"declared={declared}, actual={actual}"
        )
    if metadata.get("catalogVersion") != manifest.get("catalogVersion"):
        raise ValueError("RASP bundle catalog version does not match its manifest")
    if metadata.get("catalogSchemaVersion") != manifest.get("schemaVersion"):
        raise ValueError("RASP bundle catalog schema does not match its manifest")
    if metadata.get("evidenceContractVersion") != manifest.get("evidenceContractVersion"):
        raise ValueError("RASP bundle evidence model version does not match its manifest")

    entries = metadata.get("files")
    if not isinstance(entries, list):
        raise ValueError("RASP bundle metadata files must be a list")

    metadata_paths = [item.get("path") for item in entries if isinstance(item, dict)]
    if len(metadata_paths) != len(entries) or any(not isinstance(path, str) for path in metadata_paths):
        raise ValueError("RASP bundle metadata contains an invalid file entry")
    if len(metadata_paths) != len(set(metadata_paths)):
        raise ValueError("RASP bundle metadata contains duplicate file entries")

    actual_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "bundle-metadata.json"
    }
    if set(metadata_paths) != actual_paths:
        missing_hashes = sorted(actual_paths - set(metadata_paths))
        missing_files = sorted(set(metadata_paths) - actual_paths)
        raise ValueError(
            f"RASP bundle checksum coverage mismatch: "
            f"unhashed={missing_hashes}, missing={missing_files}"
        )

    for item in entries:
        relative = item["path"]
        candidate = (root / relative).resolve()
        if root not in candidate.parents or not candidate.is_file():
            raise ValueError(f"Invalid or missing bundle entry: {relative}")
        if sha256(candidate) != item["sha256"]:
            raise ValueError(f"Checksum mismatch for bundle entry: {relative}")

    native_abis = {
        path.parent.name
        for path in (root / "jni").glob("*/libtamperprobe_native.so")
        if path.is_file()
    }
    if native_abis != SUPPORTED_ABIS:
        raise ValueError(
            f"RASP bundle native ABI set mismatch: "
            f"expected={sorted(SUPPORTED_ABIS)}, actual={sorted(native_abis)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
