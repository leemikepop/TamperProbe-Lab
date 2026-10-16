import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import summarize_retrofit  # noqa: E402
import verify_upstream  # noqa: E402


def unit(unit_id, status, concealable=None, answered=0, attempted=0, issues=()):
    records = []
    if status != "UNAVAILABLE":
        records.append({
            "code": f"X.{unit_id}.coverage",
            "kind": "OBSERVATION",
            "attributes": {
                "attemptedCount": str(attempted),
                "answeredCount": str(answered),
                "concealable": "true" if concealable else "false",
            },
        })
    return {
        "descriptor": {"id": unit_id},
        "collectionStatus": status,
        "records": records,
        "issues": [
            {"code": "channel-no-answer", "attributes": {"reason": reason, "count": str(count)}}
            for reason, count in issues
        ],
    }


def document(checks):
    return {
        "retrofit": {
            "selection": "rootbeer",
            "upstream": {"name": "RootBeer", "repository": "r", "revision": "de7bc7b4b09c"},
            "aggregate": {"method": "isRooted()", "verdict": "false"},
            "checks": [
                {
                    "detectorId": detector,
                    "upstreamMethod": "m()",
                    "upstreamVerdict": verdict,
                    "upstreamPositive": verdict == "true",
                    "upstreamFailed": verdict == "threw",
                    "outcome": outcome,
                }
                for detector, verdict, outcome, _ in checks
            ],
        },
        "scan": {
            "report": {
                "results": [
                    {"descriptor": {"id": detector}, "outcome": outcome, "unitResults": units}
                    for detector, _, outcome, units in checks
                ]
            }
        },
        "provenance": {
            "device": {"buildFingerprint": "fp"},
            "host": {"targetSdk": 36, "packageVisibility": "manifest_queries:39"},
        },
    }


class SummarizeRetrofitTest(unittest.TestCase):
    def setUp(self):
        self.summary = summarize_retrofit.summarize(document([
            ("A", "false", "INCONCLUSIVE", [unit("a.props", "UNAVAILABLE", issues=[("property_not_listed", 2)])]),
            ("B", "false", "NOT_OBSERVED", [unit("b.paths", "PARTIAL", True, 21, 22, [("EACCES", 1)])]),
            ("C", "false", "NOT_OBSERVED", [
                unit("c.profile", "COMPLETE", False, 1, 1),
                unit("c.files", "COMPLETE", True, 7, 7),
            ]),
            ("D", "true", "OBSERVED", []),
            ("E", "threw", "FAILED", []),
            ("F", "false", "NOT_OBSERVED", [
                unit("f.hooks", "UNAVAILABLE", issues=[("SIGSYS", 1)]),
                unit("f.profile", "COMPLETE", False, 1, 1),
            ]),
        ]))

    def test_classifies_each_check(self):
        classes = {c["detector"]: c["class"] for c in self.summary["checks"]}
        self.assertEqual(
            {"A": "no_answer", "B": "concealable", "C": "mixed", "D": "positive", "E": "failed", "F": "trusted"},
            classes,
        )

    def test_counts_what_upstream_clean_checks_rest_on(self):
        self.assertEqual(4, self.summary["upstreamCleanChecks"])
        self.assertEqual(
            {"no_answer": 1, "concealable": 1, "mixed": 1, "trusted": 1},
            self.summary["upstreamCleanResting"],
        )

    def test_keeps_unit_coverage_and_reasons(self):
        b = next(c for c in self.summary["checks"] if c["detector"] == "B")["units"][0]
        self.assertEqual((21, 22, True, ["EACCES"]), (b["answered"], b["attempted"], b["partial"], b["reasons"]))
        a = next(c for c in self.summary["checks"] if c["detector"] == "A")["units"][0]
        self.assertEqual((0, 2), (a["answered"], a["attempted"]))

    def test_reads_a_cell_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "retrofit-20261016T000000Z-rootbeer.json"
            path.write_text(json.dumps(document([("A", "false", "INCONCLUSIVE", [])])), encoding="utf-8")
            output = subprocess.run(
                [sys.executable, str(TOOLS / "summarize_retrofit.py"), tmp],
                capture_output=True, text=True, check=True,
            ).stdout
        self.assertIn("upstream clean checks: 1", output)


class VerifyUpstreamTest(unittest.TestCase):
    def test_blob_id_matches_git(self):
        # `printf 'hello\n' | git hash-object --stdin`
        self.assertEqual("ce013625030ba8dba906f756967f9e9ca394464a", verify_upstream.blob_id(b"hello\n"))

    def test_reports_modified_missing_and_unlisted_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            upstream = Path(tmp)
            (upstream / "kept.txt").write_bytes(b"same\n")
            (upstream / "changed.txt").write_bytes(b"edited\n")
            (upstream / "extra.txt").write_bytes(b"x\n")
            (upstream / "UPSTREAM.md").write_text("doc", encoding="utf-8")
            manifest = {
                "kept.txt": verify_upstream.blob_id(b"same\n"),
                "changed.txt": verify_upstream.blob_id(b"original\n"),
                "gone.txt": hashlib.sha1(b"").hexdigest(),
            }
            (upstream / "BLOBS").write_text(
                "".join(f"{digest}  {name}\n" for name, digest in manifest.items()), encoding="utf-8"
            )
            problems = verify_upstream.verify(upstream)
        self.assertEqual(3, len(problems))
        self.assertTrue(any("changed.txt: blob" in p for p in problems))
        self.assertTrue(any("gone.txt: missing" in p for p in problems))
        self.assertTrue(any("extra.txt: not listed" in p for p in problems))

    def test_the_vendored_code_is_unmodified(self):
        for blobs in sorted(TOOLS.parent.glob("*/upstream/BLOBS")):
            self.assertEqual([], verify_upstream.verify(blobs.parent), blobs)


if __name__ == "__main__":
    unittest.main()
