import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SCRIPTS_DIR.parent
GENERATED_MANIFEST = REPO_ROOT / "tamperprobe" / "scripts" / "generated" / "detections_manifest.json"
ANDROID_NAME = "{http://schemas.android.com/apk/res/android}name"
ANDROID_VALUE = "{http://schemas.android.com/apk/res/android}value"
ANDROID_MIN_SDK = "{http://schemas.android.com/apk/res/android}minSdkVersion"
ANDROID_ZYGOTE_PRELOAD = "{http://schemas.android.com/apk/res/android}zygotePreloadName"
POLICY_ORACLE_PRELOAD = (
    "io.leemikepop.tamperprobe.lab.internal.policyoracle.TamperProbeAppZygotePreload"
)
POLICY_ORACLE_SERVICE = (
    "io.leemikepop.tamperprobe.lab.internal.policyoracle.SelinuxPolicyOracleCarrierService"
)


class BundleToolTest(unittest.TestCase):
    def test_generated_catalog_has_no_maturity_tiers(self):
        manifest = json.loads(GENERATED_MANIFEST.read_text(encoding="utf-8"))
        entries = manifest["detections"]

        self.assertEqual(1, manifest["schemaVersion"])
        self.assertEqual("1.0", manifest["catalogVersion"])
        self.assertEqual(1, manifest["evidenceContractVersion"])
        self.assertTrue(entries)
        self.assertTrue(all(item["evidenceUnits"] for item in entries))
        for item in entries:
            self.assertNotIn("maturity", item)
            self.assertNotIn("enabledByDefault", item)

    def test_default_selection_configures_the_policy_oracle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "AndroidManifest.xml"
            fragment = root / "manifest-fragment.xml"
            queries = root / "queries.xml"
            manifest.write_text(
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="com.example.host"><application /></manifest>',
                encoding="utf-8",
            )
            fragment.write_text(
                '<tamperprobe-manifest xmlns:android="http://schemas.android.com/apk/res/android">'
                '<provider android:name="io.leemikepop.tamperprobe.lab.rasp.TamperProbeInitializer" />'
                f'<service android:name="{POLICY_ORACLE_SERVICE}" />'
                '</tamperprobe-manifest>',
                encoding="utf-8",
            )
            queries.write_text('<queries />', encoding="utf-8")
            subprocess.run(
                [
                    sys.executable, str(SCRIPTS_DIR / "merge_manifest.py"),
                    "--manifest", str(manifest), "--fragment", str(fragment),
                    "--queries", str(queries),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            application = ET.parse(manifest).getroot().find("application")
            self.assertEqual(POLICY_ORACLE_PRELOAD, application.get(ANDROID_ZYGOTE_PRELOAD))
            provider = application.find("provider")
            self.assertEqual(
                "com.example.host.tamperprobe.lab.initializer",
                provider.get("{http://schemas.android.com/apk/res/android}authorities"),
            )
            metadata_names = {element.get(ANDROID_NAME) for element in application.findall("meta-data")}
            self.assertFalse(any("AUTO_BLOCK" in name or "THRESHOLD" in name for name in metadata_names))

    def test_manifest_merge_is_idempotent_and_enabled_list_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "AndroidManifest.xml"
            fragment = root / "manifest-fragment.xml"
            queries = root / "queries.xml"
            manifest.write_text(
                '<?xml version="1.0"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="com.example.host"><application>'
                '</application></manifest>',
                encoding="utf-8",
            )
            fragment.write_text(
                '<tamperprobe-manifest xmlns:android="http://schemas.android.com/apk/res/android">'
                '<provider android:name="io.leemikepop.tamperprobe.lab.rasp.TamperProbeInitializer" '
                'android:exported="false" android:initOrder="100" />'
                '</tamperprobe-manifest>',
                encoding="utf-8",
            )
            queries.write_text(
                '<queries xmlns:android="http://schemas.android.com/apk/res/android">'
                '<package android:name="com.topjohnwu.magisk" /></queries>',
                encoding="utf-8",
            )

            command = [
                sys.executable,
                str(SCRIPTS_DIR / "merge_manifest.py"),
                "--manifest", str(manifest),
                "--fragment", str(fragment),
                "--queries", str(queries),
                "--enabled-detections", "BUSYBOX,SU_BINARY",
                "--disabled-detections", "RUNTIME_INSTRUMENTATION",
            ]
            subprocess.run(command, check=True, capture_output=True, text=True)
            subprocess.run(command, check=True, capture_output=True, text=True)

            parsed = ET.parse(manifest).getroot()
            application = parsed.find("application")
            self.assertIsNotNone(application)
            providers = application.findall("provider")
            self.assertEqual(1, len(providers))
            self.assertEqual(
                "io.leemikepop.tamperprobe.lab.rasp.TamperProbeInitializer",
                providers[0].get(ANDROID_NAME),
            )
            metadata = {
                element.get(ANDROID_NAME): element.get(ANDROID_VALUE)
                for element in application.findall("meta-data")
            }
            self.assertEqual("BUSYBOX,SU_BINARY", metadata["io.leemikepop.tamperprobe.lab.ENABLED_DETECTIONS"])
            self.assertNotIn("io.leemikepop.tamperprobe.lab.DISABLED_DETECTIONS", metadata)
            self.assertEqual(1, len(parsed.find("queries").findall("package")))
            self.assertEqual("29", parsed.find("uses-sdk").get(ANDROID_MIN_SDK))
            self.assertIsNone(application.get(ANDROID_ZYGOTE_PRELOAD))
            self.assertFalse(any(
                item.get(ANDROID_NAME) == POLICY_ORACLE_SERVICE
                for item in application.findall("service")
            ))

    def test_policy_oracle_merge_is_conditional_and_reports_min_sdk_raise(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "AndroidManifest.xml"
            fragment = root / "manifest-fragment.xml"
            queries = root / "queries.xml"
            report = root / "report.json"
            manifest.write_text(
                '<?xml version="1.0"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="com.example.host"><uses-sdk android:minSdkVersion="24" />'
                '<application /></manifest>',
                encoding="utf-8",
            )
            fragment.write_text(
                '<tamperprobe-manifest xmlns:android="http://schemas.android.com/apk/res/android">'
                '<provider android:name="io.leemikepop.tamperprobe.lab.rasp.TamperProbeInitializer" '
                'android:exported="false" android:initOrder="100" />'
                f'<service android:name="{POLICY_ORACLE_SERVICE}" android:exported="false" '
                'android:isolatedProcess="true" android:useAppZygote="true" />'
                '</tamperprobe-manifest>',
                encoding="utf-8",
            )
            queries.write_text('<queries />', encoding="utf-8")
            command = [
                sys.executable,
                str(SCRIPTS_DIR / "merge_manifest.py"),
                "--manifest", str(manifest),
                "--fragment", str(fragment),
                "--queries", str(queries),
                "--enabled-detections", "NATIVE_ROOT_SEPOLICY",
                "--report", str(report),
            ]
            subprocess.run(command, check=True, capture_output=True, text=True)
            command[command.index("--enabled-detections") + 1] = (
                "LSPOSED_SEPOLICY,NATIVE_ROOT_SEPOLICY"
            )
            subprocess.run(command, check=True, capture_output=True, text=True)

            parsed = ET.parse(manifest).getroot()
            application = parsed.find("application")
            self.assertEqual(POLICY_ORACLE_PRELOAD, application.get(ANDROID_ZYGOTE_PRELOAD))
            services = [
                item for item in application.findall("service")
                if item.get(ANDROID_NAME) == POLICY_ORACLE_SERVICE
            ]
            self.assertEqual(1, len(services))
            self.assertEqual("29", parsed.find("uses-sdk").get(ANDROID_MIN_SDK))
            result = json.loads(report.read_text(encoding="utf-8"))
            # The second idempotent pass observes the already-raised value.
            self.assertEqual(29, result["originalMinSdkVersion"])
            self.assertEqual(29, result["outputMinSdkVersion"])
            self.assertFalse(result["minSdkCompatibilityChanged"])
            self.assertTrue(result["policyOraclePreloadConfigured"])

    def test_manifest_merge_reports_original_low_min_sdk_on_first_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "AndroidManifest.xml"
            fragment = root / "fragment.xml"
            queries = root / "queries.xml"
            report = root / "report.json"
            manifest.write_text(
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="com.example.low"><uses-sdk android:minSdkVersion="23" '
                'android:targetSdkVersion="36" />'
                '<application /></manifest>',
                encoding="utf-8",
            )
            fragment.write_text(
                '<tamperprobe-manifest xmlns:android="http://schemas.android.com/apk/res/android">'
                '<provider android:name="io.leemikepop.tamperprobe.lab.rasp.TamperProbeInitializer" />'
                '</tamperprobe-manifest>',
                encoding="utf-8",
            )
            queries.write_text('<queries />', encoding="utf-8")
            subprocess.run(
                [
                    sys.executable, str(SCRIPTS_DIR / "merge_manifest.py"),
                    "--manifest", str(manifest), "--fragment", str(fragment),
                    "--queries", str(queries),
                    # minSdk handling only; avoid the Policy Oracle carrier these fragments omit.
                    "--enabled-detections", "BUSYBOX",
                    "--report", str(report),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            result = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(23, result["originalMinSdkVersion"])
            self.assertEqual(29, result["outputMinSdkVersion"])
            self.assertTrue(result["minSdkCompatibilityChanged"])
            self.assertEqual(1, len(result["compatibilityWarnings"]))
            parsed = ET.parse(manifest).getroot().find("uses-sdk")
            self.assertEqual("36", parsed.get("{http://schemas.android.com/apk/res/android}targetSdkVersion"))

    def test_manifest_merge_preserves_higher_numeric_min_sdk(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "AndroidManifest.xml"
            fragment = root / "fragment.xml"
            queries = root / "queries.xml"
            report = root / "report.json"
            manifest.write_text(
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="com.example.high"><uses-sdk android:minSdkVersion="31" />'
                '<application /></manifest>',
                encoding="utf-8",
            )
            fragment.write_text(
                '<tamperprobe-manifest xmlns:android="http://schemas.android.com/apk/res/android">'
                '<provider android:name="io.leemikepop.tamperprobe.lab.rasp.TamperProbeInitializer" />'
                '</tamperprobe-manifest>',
                encoding="utf-8",
            )
            queries.write_text('<queries />', encoding="utf-8")
            subprocess.run(
                [
                    sys.executable, str(SCRIPTS_DIR / "merge_manifest.py"),
                    "--manifest", str(manifest), "--fragment", str(fragment),
                    "--queries", str(queries),
                    # minSdk handling only; avoid the Policy Oracle carrier these fragments omit.
                    "--enabled-detections", "BUSYBOX",
                    "--report", str(report),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            result = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(31, result["originalMinSdkVersion"])
            self.assertEqual(31, result["outputMinSdkVersion"])
            self.assertFalse(result["minSdkCompatibilityChanged"])
            self.assertEqual([], result["compatibilityWarnings"])

    def test_injector_runs_d8_at_api_29(self):
        script = (SCRIPTS_DIR / "inject.sh").read_text(encoding="utf-8")
        self.assertIn('$D8 --min-api 29 ', script)

    def test_manifest_merge_rejects_codename_min_sdk_and_preload_conflicts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fragment = root / "fragment.xml"
            queries = root / "queries.xml"
            fragment.write_text(
                '<tamperprobe-manifest xmlns:android="http://schemas.android.com/apk/res/android">'
                '<provider android:name="io.leemikepop.tamperprobe.lab.rasp.TamperProbeInitializer" />'
                f'<service android:name="{POLICY_ORACLE_SERVICE}" />'
                '</tamperprobe-manifest>',
                encoding="utf-8",
            )
            queries.write_text('<queries />', encoding="utf-8")

            codename = root / "codename.xml"
            codename.write_text(
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="com.example.codename"><uses-sdk android:minSdkVersion="Q" />'
                '<application /></manifest>',
                encoding="utf-8",
            )
            common = [
                sys.executable, str(SCRIPTS_DIR / "merge_manifest.py"),
                "--fragment", str(fragment), "--queries", str(queries),
            ]
            invalid_sdk = subprocess.run(
                [*common, "--manifest", str(codename)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, invalid_sdk.returncode)

            conflict = root / "conflict.xml"
            conflict.write_text(
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="com.example.conflict"><application '
                'android:zygotePreloadName="com.example.OtherPreload" /></manifest>',
                encoding="utf-8",
            )
            preload_conflict = subprocess.run(
                [
                    *common, "--manifest", str(conflict),
                    "--enabled-detections", "LSPOSED_SEPOLICY",
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, preload_conflict.returncode)

    def test_bundle_verifier_checks_all_four_abis_and_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                "rasp-adapter.jar": b"jar",
                "detections_manifest.json": (
                    GENERATED_MANIFEST
                ).read_bytes(),
                "queries.xml": b"<queries />",
                "manifest-fragment.xml": b"<tamperprobe-manifest />",
                "attestation_status.json": b"{}",
                "attestation_roots.json": b'{"schemaVersion":1,"certificates":[]}',
                "package_indicators.txt": b"com.topjohnwu.magisk\n",
                "package_intent_actions.txt": (
                    b"com.topjohnwu.magisk\tcom.topjohnwu.magisk.SHOW\n"
                ),
            }
            for abi in ("arm64-v8a", "armeabi-v7a", "x86", "x86_64"):
                files[f"jni/{abi}/libtamperprobe_native.so"] = abi.encode()

            entries = []
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                entries.append({"path": relative, "sha256": hashlib.sha256(content).hexdigest()})
            metadata_file = root / "bundle-metadata.json"
            catalog = json.loads(files["detections_manifest.json"])
            catalog_counts = {
                "evidenceDomains": len(catalog["evidenceDomains"]),
                "detectors": len(catalog["detections"]),
                "evidenceUnits": sum(
                    len(item["evidenceUnits"]) for item in catalog["detections"]
                ),
            }

            def write_metadata(metadata_entries, counts=catalog_counts):
                metadata_file.write_text(
                    json.dumps({
                        "bundleSchemaVersion": 1,
                        "edition": "lab",
                        "minSdkVersion": 29,
                        "catalogVersion": "1.0",
                        "catalogSchemaVersion": 1,
                        "evidenceContractVersion": 1,
                        "wireSchemaVersion": 1,
                        "catalogCounts": counts,
                        "files": metadata_entries,
                    }),
                    encoding="utf-8",
                )

            write_metadata(entries)

            subprocess.run(
                [sys.executable, str(SCRIPTS_DIR / "verify_bundle.py"), str(root)],
                check=True,
            )

            # A manifest that disagrees with the counts its build declared is rejected.
            write_metadata(entries, {**catalog_counts, "detectors": catalog_counts["detectors"] + 1})
            count_mismatch = subprocess.run(
                [sys.executable, str(SCRIPTS_DIR / "verify_bundle.py"), str(root)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, count_mismatch.returncode)
            self.assertIn("catalog counts do not match", count_mismatch.stderr)

            write_metadata(entries, None)
            undeclared_counts = subprocess.run(
                [sys.executable, str(SCRIPTS_DIR / "verify_bundle.py"), str(root)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, undeclared_counts.returncode)

            write_metadata([
                entry for entry in entries if entry["path"] != "rasp-adapter.jar"
            ])
            missing_checksum = subprocess.run(
                [sys.executable, str(SCRIPTS_DIR / "verify_bundle.py"), str(root)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, missing_checksum.returncode)

            old_native = root / "jni/x86_64/libtamperprobe_native.so"
            new_native = root / "jni/riscv64/libtamperprobe_native.so"
            new_native.parent.mkdir(parents=True)
            old_native.replace(new_native)
            wrong_abi_entries = []
            for entry in entries:
                if entry["path"] == "jni/x86_64/libtamperprobe_native.so":
                    wrong_abi_entries.append({
                        "path": "jni/riscv64/libtamperprobe_native.so",
                        "sha256": entry["sha256"],
                    })
                else:
                    wrong_abi_entries.append(entry)
            write_metadata(wrong_abi_entries)
            wrong_abi = subprocess.run(
                [sys.executable, str(SCRIPTS_DIR / "verify_bundle.py"), str(root)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, wrong_abi.returncode)


if __name__ == "__main__":
    unittest.main()
