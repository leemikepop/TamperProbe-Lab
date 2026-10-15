#!/usr/bin/env python3
"""
TamperProbe Detection Manifest Generator

掃描 C++ 檢測項目與同目錄的 .evidence.json 規格檔，嚴格校驗並生成 JSON manifest
用於 SDK、Sample App、RASP Web Server 與論文 Traceability
"""

import os
import re
import json
import sys
import io
from xml.sax.saxutils import escape
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


REQUIRED_UNIT_STRING_FIELDS = (
    "id",
    "title",
    "domainId",
    "observedObject",
    "proposition",
    "observationChannel",
    "availability",
    "trustBoundary",
    "inferenceLimit",
)
SIDE_CAR_FIELDS = {
    "id",
    "name",
    "description",
    "payloadSchemaVersion",
    "primaryEvidenceDomainId",
    "evidenceUnits",
}


def extract_detector_id(file_path: Path) -> Optional[str]:
    """Extract only the native registration identity; catalog metadata belongs to the sidecar."""
    try:
        content = file_path.read_text(encoding='utf-8')
        if not re.search(r'^\s*REGISTER_DETECTION\s*\(', content, re.MULTILINE):
            return None

        id_method = re.search(
            r'(?:const\s+char\s*\*|std::string(?:_view)?)\s+getId\s*\(\s*\)\s*const\s+override\s*\{\s*return\s+"([^"]+)"\s*;\s*\}',
            content,
            re.DOTALL,
        )
        if id_method:
            return id_method.group(1)

        # Transitional fallback keeps the generator usable until all native metadata is removed.
        metadata = re.search(
            r'DetectionMetadata\s+getMetadata\s*\(\s*\)\s*const\s+override\s*\{(.*?)\}',
            content,
            re.DOTALL,
        )
        if metadata:
            detector_id = re.search(r'\.id\s*=\s*"([^"]+)"', metadata.group(1))
            if detector_id:
                return detector_id.group(1)
        return None
    except Exception as e:
        raise RuntimeError(f"解析 {file_path} 失敗: {e}") from e


def get_active_detection_sources(cpp_dir: Path) -> List[Path]:
    cmake_file = cpp_dir / "CMakeLists.txt"
    if not cmake_file.exists():
        raise FileNotFoundError(f"找不到 CMakeLists.txt: {cmake_file}")

    content = cmake_file.read_text(encoding="utf-8")
    matches = re.findall(r'^\s*(?!#)(detections/[^\s#]+\.cpp)\s*$', content, re.MULTILINE)
    return [cpp_dir / relative_path for relative_path in matches]


def load_properties(path: Path) -> Dict[str, str]:
    properties = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        properties[key.strip()] = value.strip()
    return properties


def load_evidence_domains(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as error:
        raise ValueError(f"Unable to load evidence domains {path}: {error}") from error


def validate_detector_sidecar(
    cpp_file: Path,
    detector_id: str,
    source_domain: str,
    known_domains: Set[str],
    global_unit_ids: Set[str],
) -> Dict[str, Any]:
    """
    載入並嚴格驗證檢測器同目錄的 .evidence.json 規格檔
    """
    sidecar_path = cpp_file.with_name(f"{cpp_file.stem}.evidence.json")
    if not sidecar_path.exists():
        raise FileNotFoundError(
            f"Missing mandatory evidence sidecar for detector {detector_id} at {cpp_file}: "
            f"expected {sidecar_path}"
        )

    try:
        doc = json.loads(sidecar_path.read_text(encoding="utf-8-sig"))
    except Exception as e:
        raise ValueError(f"Invalid JSON in sidecar {sidecar_path}: {e}") from e

    if not isinstance(doc, dict):
        raise ValueError(f"Sidecar {sidecar_path} root must be a JSON object")

    unknown_fields = set(doc) - SIDE_CAR_FIELDS
    missing_fields = SIDE_CAR_FIELDS - set(doc)
    if unknown_fields or missing_fields:
        raise ValueError(
            f"Detector sidecar {sidecar_path} has unknown fields {sorted(unknown_fields)} "
            f"or missing fields {sorted(missing_fields)}"
        )

    sidecar_id = doc.get("id")
    if sidecar_id != detector_id:
        raise ValueError(
            f"Detector ID mismatch in {sidecar_path}: C++ declares '{detector_id}' but sidecar has '{sidecar_id}'"
        )

    for field in ("name", "description"):
        if not isinstance(doc[field], str) or not doc[field].strip():
            raise ValueError(f"Detector {detector_id} has an empty {field} in {sidecar_path}")
    if not isinstance(doc["payloadSchemaVersion"], int) or doc["payloadSchemaVersion"] < 1:
        raise ValueError(f"Detector {detector_id} has invalid payloadSchemaVersion")

    sidecar_primary = doc.get("primaryEvidenceDomainId")
    if not isinstance(sidecar_primary, str) or sidecar_primary not in known_domains:
        raise ValueError(f"Detector {detector_id} has unknown primary Evidence Domain: {sidecar_primary}")
    if sidecar_primary != source_domain:
        raise ValueError(
            f"Detector {detector_id} source domain '{source_domain}' does not match "
            f"primary domain '{sidecar_primary}' in {sidecar_path}"
        )

    units = doc.get("evidenceUnits")
    if not isinstance(units, list) or not units:
        raise ValueError(f"Detector {detector_id} must define at least one evidence unit in {sidecar_path}")

    normalized_units = []
    for unit in units:
        if not isinstance(unit, dict):
            raise ValueError(f"Detector {detector_id} evidence units must be objects in {sidecar_path}")
        if set(unit) != set(REQUIRED_UNIT_STRING_FIELDS):
            raise ValueError(
                f"Evidence unit in {sidecar_path} must contain exactly {REQUIRED_UNIT_STRING_FIELDS}"
            )

        for field in REQUIRED_UNIT_STRING_FIELDS:
            value = unit.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Detector {detector_id} evidence unit missing or empty required field '{field}' in {sidecar_path}"
                )

        unit_id = unit["id"]
        if unit_id in global_unit_ids:
            raise ValueError(f"Evidence unit ID '{unit_id}' is duplicated across the catalog (seen in {sidecar_path})")
        global_unit_ids.add(unit_id)

        if unit["domainId"] not in known_domains:
            raise ValueError(f"Evidence unit '{unit_id}' references unknown domain '{unit['domainId']}'")
        normalized_units.append({field: unit[field] for field in REQUIRED_UNIT_STRING_FIELDS})

    direct_domains = {unit["domainId"] for unit in normalized_units}
    if sidecar_primary not in direct_domains:
        raise ValueError(
            f"Detector {detector_id} primary Evidence Domain '{sidecar_primary}' "
            f"is not represented by any direct evidence unit in {sidecar_path}"
        )

    return {
        "id": detector_id,
        "name": doc["name"],
        "description": doc["description"],
        "payloadSchemaVersion": doc["payloadSchemaVersion"],
        "primaryEvidenceDomainId": sidecar_primary,
        "evidenceUnits": normalized_units,
    }


def scan_and_validate_catalog(
    cpp_dir: Path,
    domains_model: Dict[str, Any],
    expected_contract_version: int,
) -> Tuple[List[dict], List[dict]]:
    """Validate active detectors, co-located sidecars, and the canonical domain registry."""
    if domains_model.get("schemaVersion") != expected_contract_version:
        raise ValueError(
            f"Evidence Domain schemaVersion ({domains_model.get('schemaVersion')}) "
            f"does not match expected version ({expected_contract_version})"
        )

    domains = domains_model.get("evidenceDomains")
    if not isinstance(domains, list) or not domains:
        raise ValueError("Evidence Domain registry must define evidenceDomains")
    normalized_domains = []
    domain_ids = []
    for domain in domains:
        if not isinstance(domain, dict) or set(domain) != {"id", "title", "shortTitle", "description"}:
            raise ValueError("Evidence Domain entries require id, title, shortTitle, and description")
        if any(not isinstance(domain[field], str) or not domain[field].strip() for field in domain):
            raise ValueError(f"Evidence Domain fields must be non-empty strings: {domain}")
        domain_ids.append(domain["id"])
        normalized_domains.append(dict(domain))
    if len(set(domain_ids)) != len(domain_ids):
        raise ValueError("Evidence Domain IDs must be unique")
    known_domains = set(domain_ids)

    # 取得 active C++ sources
    active_sources = get_active_detection_sources(cpp_dir)
    detected_items: List[Tuple[Path, str, str]] = []
    for cpp_file in active_sources:
        detector_id = extract_detector_id(cpp_file)
        if not detector_id:
            continue
        relative_parts = cpp_file.relative_to(cpp_dir).parts
        if len(relative_parts) < 3 or relative_parts[0] != "detections":
            raise ValueError(f"Detector source is outside the Evidence Domain layout: {cpp_file}")
        detected_items.append((cpp_file, detector_id, relative_parts[1]))

    published_ids = {detector_id for _, detector_id, _ in detected_items}
    if len(published_ids) != len(detected_items):
        raise ValueError("Published detector IDs must be unique across C++ sources")

    # 驗證每個檢測器的同目錄 sidecar
    global_unit_ids: Set[str] = set()
    validated_detections: List[dict] = []

    for cpp_file, detector_id, source_domain in detected_items:
        validated = validate_detector_sidecar(
            cpp_file,
            detector_id,
            source_domain,
            known_domains,
            global_unit_ids,
        )
        validated_detections.append(validated)
        print(f"找到檢測項目: {detector_id} ({source_domain})")

    flat_detections = sorted(validated_detections, key=lambda item: item["id"])
    unit_count = sum(len(item["evidenceUnits"]) for item in flat_detections)
    # The Lab catalog is expected to change after the experiments, so counts are not pinned
    # here; consumers check against counts derived from this manifest instead.
    if not normalized_domains or not flat_detections or unit_count < len(flat_detections):
        raise ValueError(
            f"Catalog is incomplete: {len(normalized_domains)} domains, "
            f"{len(flat_detections)} detectors, {unit_count} units"
        )
    if any(item["payloadSchemaVersion"] != 1 for item in flat_detections):
        raise ValueError("TamperProbe v1 requires payloadSchemaVersion 1 for every detector")
    return normalized_domains, flat_detections


def validate_runtime_bindings(project_dir: Path, published_ids: Set[str]) -> None:
    """Keep the catalog and the typed payload/adapter runtime bindings one-to-one."""
    binding_source = project_dir / "src" / "main" / "java" / "io" / "leemikepop" / \
        "tamperprobe" / "lab" / "internal" / "EvidenceAdapterRegistry.kt"
    binding_text = binding_source.read_text(encoding="utf-8")
    binding_rows = re.findall(
        r'"([A-Z][A-Z0-9_]+)"\s+to\s+(?:configuredBinding|typedBinding)\s*\(\s*'
        r'([A-Za-z][A-Za-z0-9]+Payload)\.serializer\(\),\s*'
        r'([A-Za-z][A-Za-z0-9]+EvidenceAdapter)',
        binding_text,
        re.MULTILINE,
    )
    registered_ids = {detector_id for detector_id, _, _ in binding_rows}
    if registered_ids != published_ids or len(binding_rows) != len(published_ids):
        missing = sorted(published_ids - registered_ids)
        extra = sorted(registered_ids - published_ids)
        raise ValueError(f"runtime binding mismatch: missing={missing}, extra={extra}")

    adapter_bindings = {detector_id: adapter for detector_id, _, adapter in binding_rows}
    payload_bindings = {detector_id: payload for detector_id, payload, _ in binding_rows}
    adapter_dir = binding_source.parent / "evidence" / "adapters"
    adapter_files = {path.stem: path for path in adapter_dir.glob("*EvidenceAdapter.kt")}
    if set(adapter_bindings) != published_ids:
        raise ValueError("runtime registry must bind every published detector to a named adapter")
    if set(adapter_bindings.values()) != set(adapter_files):
        raise ValueError(
            "adapter files must be one-to-one with registry bindings: "
            f"registered={sorted(adapter_bindings.values())}, files={sorted(adapter_files)}"
        )
    for adapter_name, adapter_path in adapter_files.items():
        content = adapter_path.read_text(encoding="utf-8")
        declarations = re.findall(
            r'^internal object ([A-Za-z][A-Za-z0-9]+EvidenceAdapter)\b',
            content,
            re.MULTILINE,
        )
        if declarations != [adapter_name]:
            raise ValueError(f"{adapter_path}: expected exactly one adapter object named {adapter_name}")

    if set(payload_bindings) != published_ids or len(set(payload_bindings.values())) != len(published_ids):
        raise ValueError("every detector must own a distinct top-level payload type")
    payload_root = project_dir / "src" / "main" / "java" / "io" / "leemikepop" / \
        "tamperprobe" / "lab" / "lib" / "detections"
    payload_declarations: Dict[str, List[Path]] = {}
    for payload_file in payload_root.rglob("*Payload.kt"):
        if "shared" in payload_file.parts:
            continue
        content = payload_file.read_text(encoding="utf-8")
        for declaration in re.findall(
            r'^internal data class ([A-Za-z][A-Za-z0-9]+Payload)\(',
            content,
            re.MULTILINE,
        ):
            payload_declarations.setdefault(declaration, []).append(payload_file)
    for detector_id, payload_type in payload_bindings.items():
        owners = payload_declarations.get(payload_type, [])
        if len(owners) != 1 or owners[0].stem != payload_type:
            raise ValueError(
                f"{detector_id}: top-level payload {payload_type} must have one detector-specific file"
            )


def generate_manifest(
    cpp_dir: Path,
    output_file: Path,
    schema_version: int,
    catalog_version: str,
    evidence_domains_path: Path,
    evidence_contract_version: int,
):
    """
    生成 JSON manifest
    """
    print("=" * 60)
    print("TamperProbe v1 Detection Catalog Generator")
    print("=" * 60)

    evidence_domains_doc = load_evidence_domains(evidence_domains_path)
    evidence_domains, flat_detections = scan_and_validate_catalog(
        cpp_dir,
        evidence_domains_doc,
        evidence_contract_version,
    )
    validate_runtime_bindings(cpp_dir.parents[2], {item["id"] for item in flat_detections})
    # Every detector must ship its developer documentation (.docs.md beside its .cpp).
    load_detector_docs(cpp_dir, flat_detections)

    total_count = len(flat_detections)
    total_units = sum(len(item["evidenceUnits"]) for item in flat_detections)

    manifest = {
        "schemaVersion": schema_version,
        "catalogVersion": catalog_version,
        "evidenceContractVersion": evidence_contract_version,
        "evidenceDomains": evidence_domains,
        "detections": flat_detections
    }

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open('w', encoding='utf-8', newline='\n') as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"\n生成 manifest: {output_file}")
    print(f"   總計: {total_count} 個檢測項目, {total_units} 個 Atomic Evidence Units")
    print(f"   Evidence Domains: {', '.join(domain['id'] for domain in evidence_domains)}")

    print("\n各分類統計:")
    for domain in evidence_domains:
        domain_id = domain["id"]
        ids = [item["id"] for item in flat_detections if item["primaryEvidenceDomainId"] == domain_id]
        print(f"   • {domain_id:24s}: {len(ids):2d} 項 ({', '.join(ids)})")

    print("\nManifest 生成完成！")
    print("=" * 60)


# 開發者文件的固定章節。順序即為網頁呈現順序；缺任何一節都會讓 build 失敗，
# 這是刻意的：文件與程式碼放在一起才不會像先前的計數那樣各自漂移。
DOC_SECTIONS: List[Tuple[str, str]] = [
    ("whatLooksAt", "這個檢測在看什麼"),
    ("whatItMeans", "觸發代表什麼"),
    ("falsePositives", "已知偽陽性來源"),
    ("blindSpots", "看不到什麼"),
    ("handling", "建議處置"),
    ("cost", "成本"),
]

UNITS_HEADING = "Evidence units"


def _split_markdown_sections(text: str, level: int) -> List[Tuple[str, str]]:
    """把 markdown 依指定標題層級切成 (標題, 內文) 序列。"""
    marker = "#" * level + " "
    sections: List[Tuple[str, str]] = []
    heading: Optional[str] = None
    body: List[str] = []
    for line in text.split("\n"):
        if line.startswith(marker):
            if heading is not None:
                sections.append((heading, "\n".join(body).strip()))
            heading = line[len(marker):].strip()
            body = []
        elif heading is not None:
            body.append(line)
    if heading is not None:
        sections.append((heading, "\n".join(body).strip()))
    return sections


def validate_detector_docs(
    cpp_file: Path,
    detector_id: str,
    unit_ids: List[str],
) -> Dict[str, Any]:
    """載入並嚴格驗證檢測器同目錄的 .docs.md 開發者說明。"""
    docs_path = cpp_file.with_name(f"{cpp_file.stem}.docs.md")
    if not docs_path.exists():
        raise FileNotFoundError(
            f"Missing mandatory developer documentation for detector {detector_id}: "
            f"expected {docs_path}"
        )
    raw = docs_path.read_text(encoding="utf-8")

    title_lines = [line for line in raw.split("\n") if line.startswith("# ")]
    if not title_lines:
        raise ValueError(f"{docs_path}: developer documentation requires a '# <name>' title")

    top_level = _split_markdown_sections(raw, 1)
    summary = top_level[0][1].split("\n##")[0].strip() if top_level else ""
    if not summary:
        raise ValueError(
            f"{docs_path}: a one-paragraph summary must follow the title before the first section"
        )

    sections = dict(_split_markdown_sections(raw, 2))
    expected_headings = [heading for _, heading in DOC_SECTIONS] + [UNITS_HEADING]
    unknown = set(sections) - set(expected_headings)
    if unknown:
        raise ValueError(
            f"{docs_path}: unexpected section(s) {sorted(unknown)}; "
            f"allowed sections are {expected_headings}"
        )

    resolved: Dict[str, Any] = {}
    for key, heading in DOC_SECTIONS:
        body = sections.get(heading, "").strip()
        if not body:
            raise ValueError(f"{docs_path}: section '## {heading}' is missing or empty")
        resolved[key] = body

    if UNITS_HEADING not in sections:
        raise ValueError(f"{docs_path}: section '## {UNITS_HEADING}' is required")
    unit_bodies = dict(_split_markdown_sections(sections[UNITS_HEADING], 3))
    documented = list(unit_bodies)
    if documented != unit_ids:
        raise ValueError(
            f"{docs_path}: '## {UNITS_HEADING}' must document exactly the declared units "
            f"in order. Expected {unit_ids}, found {documented}"
        )
    for unit_id, body in unit_bodies.items():
        if not body.strip():
            raise ValueError(f"{docs_path}: unit '### {unit_id}' has no description")

    resolved["summary"] = summary
    resolved["units"] = {unit_id: body.strip() for unit_id, body in unit_bodies.items()}
    return resolved


def load_detector_docs(cpp_dir: Path, flat_detections: List[dict]) -> Dict[str, Dict[str, Any]]:
    """為每個已發佈的 detector 載入並驗證其開發者文件。"""
    units_by_id = {
        item["id"]: [unit["id"] for unit in item["evidenceUnits"]] for item in flat_detections
    }
    docs: Dict[str, Dict[str, Any]] = {}
    for cpp_file in get_active_detection_sources(cpp_dir):
        detector_id = extract_detector_id(cpp_file)
        if not detector_id or detector_id not in units_by_id:
            continue
        docs[detector_id] = validate_detector_docs(cpp_file, detector_id, units_by_id[detector_id])
    missing = sorted(set(units_by_id) - set(docs))
    if missing:
        raise ValueError(f"Published detectors without developer documentation: {missing}")
    return docs


def load_package_indicators(package_list_file: Path) -> Tuple[List[str], List[Tuple[str, str]]]:
    content = package_list_file.read_text(encoding="utf-8")
    package_block_match = re.search(
        r'val\s+PACKAGES\s*=\s*listOf\((.*?)\n\s*\)',
        content,
        re.DOTALL,
    )
    if not package_block_match:
        raise ValueError(f"Unable to locate PACKAGES list in {package_list_file}")

    packages = sorted(set(re.findall(r'"([A-Za-z0-9_.]+)"', package_block_match.group(1))))
    intent_block_match = re.search(
        r'val\s+KNOWN_INTENT_ACTIONS\s*=\s*mapOf\((.*?)\n\s*\)\s*\n\}',
        content,
        re.DOTALL,
    )
    if not intent_block_match:
        raise ValueError(f"Unable to locate KNOWN_INTENT_ACTIONS map in {package_list_file}")

    intent_rules = []
    for entry in re.finditer(
        r'"([A-Za-z0-9_.]+)"\s+to\s+listOf\((.*?)\)',
        intent_block_match.group(1),
        re.DOTALL,
    ):
        package_name = entry.group(1)
        actions = re.findall(r'"([A-Za-z0-9_.]+)"', entry.group(2))
        intent_rules.extend((package_name, action) for action in actions)

    intent_rules = sorted(set(intent_rules))
    unknown_packages = sorted({package for package, _ in intent_rules} - set(packages))
    if unknown_packages:
        raise ValueError(f"Intent rules reference unknown packages: {unknown_packages}")
    return packages, intent_rules


def generate_queries(
    package_list_file: Path,
    output_file: Path,
    indent: str = "    ",
) -> Tuple[List[str], List[Tuple[str, str]]]:
    packages, intent_rules = load_package_indicators(package_list_file)
    lines = [
        '<queries xmlns:android="http://schemas.android.com/apk/res/android">',
        f'{indent}<intent>',
        f'{indent}    <action android:name="android.intent.action.MAIN" />',
        f'{indent}    <category android:name="android.intent.category.LAUNCHER" />',
        f'{indent}</intent>',
    ]
    for _, action in intent_rules:
        lines.extend([
            f'{indent}<intent>',
            f'{indent}    <action android:name="{escape(action)}" />',
            f'{indent}</intent>',
        ])
    lines.extend(f'{indent}<package android:name="{escape(package)}" />' for package in packages)
    lines.append('</queries>')

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(
        f"生成 package queries: {output_file} "
        f"({len(packages)} packages, {len(intent_rules)} intent rules)"
    )
    return packages, intent_rules


def generate_core_manifest(
    packages: List[str],
    intent_rules: List[Tuple[str, str]],
    output_file: Path,
):
    lines = [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">',
        '    <queries>',
        '        <intent>',
        '            <action android:name="android.intent.action.MAIN" />',
        '            <category android:name="android.intent.category.LAUNCHER" />',
        '        </intent>',
    ]
    for _, action in intent_rules:
        lines.extend([
            '        <intent>',
            f'            <action android:name="{escape(action)}" />',
            '        </intent>',
        ])
    lines.extend(f'        <package android:name="{escape(package)}" />' for package in packages)
    lines.extend([
        '    </queries>',
        '    <application>',
        '        <service',
        '            android:name="io.leemikepop.tamperprobe.lab.internal.fdforensics.ZygiskFdForensicsCarrierService"',
        '            android:exported="false"',
        '            android:process=":tamperprobe_fd_forensics" />',
        '        <service',
        '            android:name="io.leemikepop.tamperprobe.lab.internal.policyoracle.SelinuxPolicyOracleCarrierService"',
        '            android:exported="false"',
        '            android:isolatedProcess="true"',
        '            android:useAppZygote="true" />',
        '    </application>',
        '</manifest>',
    ])
    output_file.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"生成 core manifest: {output_file}")


def main():
    """主程式"""
    if sys.platform.startswith('win'):
        try:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
        except Exception:
            pass

    script_dir = Path(__file__).parent
    project_root = script_dir.parent  # tamperprobe/
    cpp_dir = project_root / "src" / "main" / "cpp"

    output_file = script_dir / "generated" / "detections_manifest.json"
    queries_file = script_dir / "generated" / "queries.xml"
    package_indicators_file = script_dir / "generated" / "package_indicators.txt"
    package_intent_actions_file = script_dir / "generated" / "package_intent_actions.txt"
    core_manifest_file = project_root / "src" / "main" / "AndroidManifest.xml"
    package_list_file = (
        project_root / "src" / "main" / "java" / "io" / "leemikepop" / "tamperprobe" / "lab" /
        "lib" / "detections" / "appvisibility" / "DangerousPackageList.kt"
    )
    evidence_domains_file = project_root / "evidence_domains.json"
    versions = load_properties(project_root / "version.properties")

    if not cpp_dir.exists():
        print(f"錯誤: 找不到 C++ 目錄: {cpp_dir}")
        return 1

    try:
        generate_manifest(
            cpp_dir,
            output_file,
            int(versions["catalogSchemaVersion"]),
            versions["catalogVersion"],
            evidence_domains_file,
            int(versions["evidenceContractVersion"]),
        )
        packages, intent_rules = generate_queries(package_list_file, queries_file)
        package_indicators_file.write_text("\n".join(packages) + "\n", encoding="utf-8", newline="\n")
        package_intent_actions_file.write_text(
            "\n".join(f"{package}\t{action}" for package, action in intent_rules) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        generate_core_manifest(packages, intent_rules, core_manifest_file)
        return 0
    except Exception as e:
        print(f"錯誤: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
