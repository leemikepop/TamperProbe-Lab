#!/usr/bin/env python3

import argparse
import copy
import json
import xml.etree.ElementTree as ET
from pathlib import Path


ANDROID_NS = "http://schemas.android.com/apk/res/android"
POLICY_ORACLE_DETECTOR_IDS = frozenset((
    "LSPOSED_SEPOLICY",
    "NATIVE_ROOT_SEPOLICY",
))
POLICY_ORACLE_PRELOAD = (
    "io.leemikepop.tamperprobe.lab.internal.policyoracle.TamperProbeAppZygotePreload"
)
POLICY_ORACLE_SERVICE = (
    "io.leemikepop.tamperprobe.lab.internal.policyoracle.SelinuxPolicyOracleCarrierService"
)
MIN_SDK_VERSION = 29
ET.register_namespace("android", ANDROID_NS)


def android_attr(name: str) -> str:
    return f"{{{ANDROID_NS}}}{name}"


def remove_named_children(parent: ET.Element, tag: str, name: str) -> None:
    for child in list(parent.findall(tag)):
        if child.get(android_attr("name")) == name:
            parent.remove(child)


def set_metadata(application: ET.Element, name: str, value: str | None) -> None:
    remove_named_children(application, "meta-data", name)
    if value is None or not value.strip():
        return
    element = ET.SubElement(application, "meta-data")
    element.set(android_attr("name"), name)
    element.set(android_attr("value"), value)


def merge_queries(manifest: ET.Element, source: ET.Element) -> None:
    target = manifest.find("queries")
    if target is None:
        target = ET.Element("queries")
        application = manifest.find("application")
        insert_at = list(manifest).index(application) if application is not None else len(manifest)
        manifest.insert(insert_at, target)

    existing_packages = {
        element.get(android_attr("name")) for element in target.findall("package")
    }
    for element in source.findall("package"):
        package_name = element.get(android_attr("name"))
        if package_name and package_name not in existing_packages:
            target.append(copy.deepcopy(element))
            existing_packages.add(package_name)

    def intent_key(element: ET.Element) -> tuple[str, tuple[str, ...]]:
        action = element.find("action")
        action_name = action.get(android_attr("name"), "") if action is not None else ""
        categories = tuple(sorted(
            category.get(android_attr("name"), "") for category in element.findall("category")
        ))
        return action_name, categories

    existing_intents = {intent_key(element) for element in target.findall("intent")}
    for element in source.findall("intent"):
        key = intent_key(element)
        if key not in existing_intents:
            target.append(copy.deepcopy(element))
            existing_intents.add(key)


def parse_detection_ids(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


def enforce_min_sdk(manifest: ET.Element) -> tuple[int | None, int, bool]:
    uses_sdk = manifest.find("uses-sdk")
    if uses_sdk is None:
        uses_sdk = ET.Element("uses-sdk")
        application = manifest.find("application")
        insert_at = list(manifest).index(application) if application is not None else len(manifest)
        manifest.insert(insert_at, uses_sdk)

    raw_value = uses_sdk.get(android_attr("minSdkVersion"))
    original = None
    if raw_value is not None:
        stripped = raw_value.strip()
        if not stripped.isascii() or not stripped.isdigit():
            raise ValueError(
                f"Target minSdkVersion must be numeric; found {raw_value!r}"
            )
        original = int(stripped)

    output = max(original or 0, MIN_SDK_VERSION)
    changed = original != output
    uses_sdk.set(android_attr("minSdkVersion"), str(output))
    return original, output, changed


def configure_policy_oracle(
    application: ET.Element,
    fragment: ET.Element,
    selected: bool,
) -> None:
    existing_preload = application.get(android_attr("zygotePreloadName"))
    remove_named_children(application, "service", POLICY_ORACLE_SERVICE)

    if not selected:
        if existing_preload == POLICY_ORACLE_PRELOAD:
            application.attrib.pop(android_attr("zygotePreloadName"), None)
        return

    if existing_preload and existing_preload != POLICY_ORACLE_PRELOAD:
        raise ValueError(
            "Target application already declares a different android:zygotePreloadName"
        )

    service_template = next(
        (
            element for element in fragment.findall("service")
            if element.get(android_attr("name")) == POLICY_ORACLE_SERVICE
        ),
        None,
    )
    if service_template is None:
        raise ValueError("RASP manifest fragment does not contain the policy-oracle service")
    application.set(android_attr("zygotePreloadName"), POLICY_ORACLE_PRELOAD)
    application.append(copy.deepcopy(service_template))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--fragment", required=True)
    parser.add_argument("--queries", required=True)
    parser.add_argument("--enabled-detections", default="")
    parser.add_argument("--disabled-detections", default="")
    parser.add_argument("--report")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    tree = ET.parse(manifest_path)
    manifest = tree.getroot()
    package_name = manifest.get("package", "").strip()
    if not package_name:
        raise ValueError("Target manifest does not declare a package name")

    application = manifest.find("application")
    if application is None:
        raise ValueError("Target manifest does not contain an application element")

    fragment = ET.parse(args.fragment).getroot()
    provider_template = fragment.find("provider")
    if provider_template is None:
        raise ValueError("RASP manifest fragment does not contain a provider")
    provider_name = provider_template.get(android_attr("name"), "")
    if not provider_name:
        raise ValueError("RASP provider class name is missing")

    remove_named_children(application, "provider", provider_name)
    provider = copy.deepcopy(provider_template)
    provider.set(android_attr("authorities"), f"{package_name}.tamperprobe.lab.initializer")
    application.insert(0, provider)

    enabled = args.enabled_detections.strip()
    disabled = args.disabled_detections.strip() if not enabled else ""
    set_metadata(application, "io.leemikepop.tamperprobe.lab.ENABLED_DETECTIONS", enabled or None)
    set_metadata(application, "io.leemikepop.tamperprobe.lab.DISABLED_DETECTIONS", disabled or None)

    # Every detector runs unless the selection narrows it, so the Policy Oracle carrier is
    # needed unless the selection leaves out both SEPOLICY detectors.
    if enabled:
        policy_oracle_selected = bool(
            POLICY_ORACLE_DETECTOR_IDS.intersection(parse_detection_ids(enabled))
        )
    else:
        policy_oracle_selected = bool(POLICY_ORACLE_DETECTOR_IDS - parse_detection_ids(disabled))
    configure_policy_oracle(application, fragment, policy_oracle_selected)
    original_min_sdk, output_min_sdk, min_sdk_changed = enforce_min_sdk(manifest)

    merge_queries(manifest, ET.parse(args.queries).getroot())
    ET.indent(tree, space="    ")
    tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
    report = {
        "packageName": package_name,
        "originalMinSdkVersion": original_min_sdk,
        "outputMinSdkVersion": output_min_sdk,
        "minSdkCompatibilityChanged": min_sdk_changed,
        "policyOracleSelected": policy_oracle_selected,
        "policyOraclePreloadConfigured": policy_oracle_selected,
        "compatibilityWarnings": (
            [
                "The injected APK now requires Android API 29 or newer "
                f"(original minSdkVersion: {original_min_sdk if original_min_sdk is not None else 'absent'})."
            ]
            if min_sdk_changed
            else []
        ),
    }
    if args.report:
        Path(args.report).write_text(
            json.dumps(report, indent=2) + "\n",
            encoding="utf-8",
        )
    print(package_name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
