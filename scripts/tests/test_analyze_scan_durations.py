import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analyze_scan_durations import InconsistentRunsError, assert_comparable  # noqa: E402


def run(build_type, name):
    return {
        "__file": Path(name),
        "provenance": {
            "device": {"buildFingerprint": "vendor/device:13/build:user/release-keys"},
            "sampleApp": {"gitCommit": "ef56fd7", "buildType": build_type},
            "coreBuild": {"catalogVersion": "1.0"},
        },
        "scan": {"requestedDetectorIds": ["SU_BINARY", "BUSYBOX"]},
    }


class ComparabilityTest(unittest.TestCase):
    def test_accepts_runs_of_one_build_type(self):
        assert_comparable([run("release", "a.json"), run("release", "b.json")])

    def test_rejects_debug_and_release_runs_of_the_same_commit(self):
        # A debug build compiles the native engine without optimisation, so averaging it
        # with a release run of the same commit would mix two different programs.
        with self.assertRaisesRegex(InconsistentRunsError, "buildType"):
            assert_comparable([run("debug", "a.json"), run("release", "b.json")])


if __name__ == "__main__":
    unittest.main()
