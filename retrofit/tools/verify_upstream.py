"""Check that the vendored upstream code in retrofit/*/upstream is unmodified.

Each upstream directory has a BLOBS file listing the git blob ID of every vendored file, which
equals the blob in the upstream repository at the pinned revision (see UPSTREAM.md there). This
script recomputes the IDs from the working tree, so it needs no git and no network:

    python retrofit/tools/verify_upstream.py

It exits 1 if a file differs, is missing, or is present but not listed.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

RETROFIT = Path(__file__).resolve().parent.parent
UNLISTED = {"BLOBS", "UPSTREAM.md"}


def blob_id(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def read_manifest(path: Path) -> dict[str, str]:
    entries = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        entries[name.strip()] = digest
    return entries


def verify(upstream: Path) -> list[str]:
    problems = []
    expected = read_manifest(upstream / "BLOBS")
    present = {
        path.relative_to(upstream).as_posix()
        for path in upstream.rglob("*")
        if path.is_file() and path.name not in UNLISTED
    }
    for name in sorted(present - expected.keys()):
        problems.append(f"{upstream}/{name}: not listed in BLOBS")
    for name, digest in sorted(expected.items()):
        path = upstream / name
        if not path.is_file():
            problems.append(f"{upstream}/{name}: missing")
        elif blob_id(path.read_bytes()) != digest:
            problems.append(f"{upstream}/{name}: blob {blob_id(path.read_bytes())} != {digest}")
    return problems


def main() -> int:
    upstreams = sorted(p.parent for p in RETROFIT.glob("*/upstream/BLOBS"))
    if not upstreams:
        print("no retrofit/*/upstream/BLOBS found")
        return 1
    problems = [problem for upstream in upstreams for problem in verify(upstream)]
    for upstream in upstreams:
        print(f"checked {upstream.relative_to(RETROFIT.parent).as_posix()}")
    for problem in problems:
        print(f"MODIFIED {problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
