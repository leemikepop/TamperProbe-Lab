import json
import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1]
PROJECT_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from generate_detections_manifest import (  # noqa: E402
    SIDE_CAR_FIELDS,
    REQUIRED_UNIT_STRING_FIELDS,
    extract_detector_id,
    get_active_detection_sources,
    load_evidence_domains,
    load_package_indicators,
    scan_and_validate_catalog,
    validate_detector_sidecar,
)


class EvidenceSidecarValidationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cpp_dir = PROJECT_DIR / "src" / "main" / "cpp"
        cls.domains_doc = load_evidence_domains(PROJECT_DIR / "evidence_domains.json")

    def validate(self):
        return scan_and_validate_catalog(self.cpp_dir, self.domains_doc, expected_contract_version=1)

    def test_current_v1_contract_is_consistent(self):
        # Counts are not pinned here: the Lab catalog is expected to change after the experiments.
        domains, detections = self.validate()
        self.assertTrue(domains)
        self.assertTrue(detections)
        self.assertTrue(all(item["evidenceUnits"] for item in detections))
        self.assertTrue(all(item["payloadSchemaVersion"] == 1 for item in detections))
        # The research edition has no maturity tiers or default selection: every detector runs.
        for item in detections:
            self.assertNotIn("maturity", item)
            self.assertNotIn("enabledByDefault", item)

    def test_sidecars_contain_only_v1_fields(self):
        for cpp_file in get_active_detection_sources(self.cpp_dir):
            detector_id = extract_detector_id(cpp_file)
            if detector_id is None:
                continue
            sidecar = json.loads(cpp_file.with_suffix(".evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(SIDE_CAR_FIELDS, set(sidecar), detector_id)
            for unit in sidecar["evidenceUnits"]:
                self.assertEqual(set(REQUIRED_UNIT_STRING_FIELDS), set(unit), unit["id"])
                for forbidden in (
                    "provenance",
                    "dependentEvidenceFamilyIds",
                    "evidenceCodeSelectors",
                    "primaryEvidenceFamilyId",
                ):
                    self.assertNotIn(forbidden, unit)

    def test_source_directory_mismatch_is_rejected(self):
        cpp_file = self.cpp_dir / "detections" / "binary-artifact" / "busybox.cpp"
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_detector_sidecar(
                cpp_file,
                "BUSYBOX",
                "kernel-interface",
                {domain["id"] for domain in self.domains_doc["evidenceDomains"]},
                set(),
            )

    def test_id_mismatch_is_rejected(self):
        cpp_file = self.cpp_dir / "detections" / "binary-artifact" / "busybox.cpp"
        with self.assertRaisesRegex(ValueError, "Detector ID mismatch"):
            validate_detector_sidecar(
                cpp_file,
                "WRONG_ID",
                "binary-artifact",
                {domain["id"] for domain in self.domains_doc["evidenceDomains"]},
                set(),
            )

    def test_package_intent_rules_use_canonical_kotlin_list(self):
        package_list = (
            PROJECT_DIR / "src" / "main" / "java" / "io" / "leemikepop" /
            "tamperprobe" / "lab" / "lib" / "detections" / "appvisibility" / "DangerousPackageList.kt"
        )
        packages, intent_rules = load_package_indicators(package_list)
        self.assertIn("com.topjohnwu.magisk", packages)
        self.assertIn(
            ("com.topjohnwu.magisk", "com.topjohnwu.magisk.REQUEST_INSTALL"),
            intent_rules,
        )
        self.assertTrue({package for package, _ in intent_rules}.issubset(set(packages)))

    def test_each_detector_has_a_dedicated_adapter_file(self):
        adapter_dir = (
            PROJECT_DIR / "src" / "main" / "java" / "io" / "leemikepop" /
            "tamperprobe" / "lab" / "internal" / "evidence" / "adapters"
        )
        adapter_files = list(adapter_dir.glob("*EvidenceAdapter.kt"))
        published = sum(
            1 for source in get_active_detection_sources(PROJECT_DIR / "src" / "main" / "cpp")
            if extract_detector_id(source) is not None
        )
        self.assertEqual(published, len(adapter_files))
        self.assertEqual(published, len({path.stem for path in adapter_files}))

    def test_each_detector_has_a_distinct_top_level_payload_type(self):
        registry = (
            PROJECT_DIR / "src" / "main" / "java" / "io" / "leemikepop" /
            "tamperprobe" / "lab" / "internal" / "EvidenceAdapterRegistry.kt"
        ).read_text(encoding="utf-8")
        import re
        bindings = re.findall(
            r'"([A-Z][A-Z0-9_]+)"\s+to\s+(?:configuredBinding|typedBinding)\s*\(\s*'
            r'([A-Za-z][A-Za-z0-9]+Payload)\.serializer',
            registry,
            re.MULTILINE,
        )
        published = sum(
            1 for source in get_active_detection_sources(PROJECT_DIR / "src" / "main" / "cpp")
            if extract_detector_id(source) is not None
        )
        self.assertEqual(published, len(bindings))
        self.assertEqual(published, len({payload_type for _, payload_type in bindings}))


if __name__ == "__main__":
    unittest.main()
