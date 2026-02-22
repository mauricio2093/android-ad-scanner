from __future__ import annotations

import datetime
import uuid


def _new_id(stix_type: str) -> str:
    return f"{stix_type}--{uuid.uuid4()}"


def _normalize_time(value: str) -> str:
    if value.endswith("Z"):
        return value
    if "+00:00" in value:
        return value.replace("+00:00", "Z")
    return value


def build_stix_lite_bundle(scan_records: list[dict], source_name: str = "android-ad-scanner") -> dict:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )

    bundle_objects: list[dict] = []

    identity_id = _new_id("identity")
    bundle_objects.append(
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": source_name,
            "identity_class": "organization",
        }
    )

    attack_pattern_ids: dict[str, str] = {}

    for record in scan_records:
        scan_id = int(record["id"])
        created_at = _normalize_time(str(record["created_at"]))
        package_name = str(record.get("package_name", "unknown"))
        risk_level = str(record.get("risk_level", "UNKNOWN"))
        risk_score = float(record.get("risk_score", 0.0))
        device_id = str(record.get("device_id", "unknown"))
        features = dict(record.get("features", {}))
        reasons = list(record.get("reasons", []))
        ioc_matches = list(record.get("ioc_matches", []))
        attack_techniques = list(record.get("attack_techniques", []))

        observed_id = _new_id("observed-data")
        bundle_objects.append(
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": observed_id,
                "created_by_ref": identity_id,
                "created": created_at,
                "modified": created_at,
                "first_observed": created_at,
                "last_observed": created_at,
                "number_observed": 1,
                "x_scan_id": scan_id,
                "x_device_id": device_id,
                "x_package_name": package_name,
                "x_risk_level": risk_level,
                "x_risk_score": risk_score,
                "x_features": features,
            }
        )

        note_id = _new_id("note")
        bundle_objects.append(
            {
                "type": "note",
                "spec_version": "2.1",
                "id": note_id,
                "created_by_ref": identity_id,
                "created": created_at,
                "modified": created_at,
                "content": "\\n".join(reasons) if reasons else "Sin razones registradas",
                "object_refs": [observed_id],
            }
        )

        apk_sha256 = str(record.get("raw_snapshot", {}).get("apk_sha256", "")).strip().lower()
        if apk_sha256:
            indicator_id = _new_id("indicator")
            bundle_objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_id,
                    "created_by_ref": identity_id,
                    "created": created_at,
                    "modified": created_at,
                    "name": f"APK SHA-256 {package_name}",
                    "pattern_type": "stix",
                    "pattern": f"[file:hashes.'SHA-256' = '{apk_sha256}']",
                    "valid_from": created_at,
                    "labels": ["apk-hash", "android", risk_level.lower()],
                }
            )
            bundle_objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": _new_id("relationship"),
                    "created": created_at,
                    "modified": created_at,
                    "relationship_type": "based-on",
                    "source_ref": indicator_id,
                    "target_ref": observed_id,
                }
            )

        for ioc in ioc_matches:
            ioc_val = str(ioc)
            if ioc_val.startswith("sha256:"):
                continue
            indicator_id = _new_id("indicator")
            bundle_objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_id,
                    "created_by_ref": identity_id,
                    "created": created_at,
                    "modified": created_at,
                    "name": f"IOC match {package_name}",
                    "pattern_type": "stix",
                    "pattern": f"[software:name = '{package_name}']",
                    "valid_from": created_at,
                    "labels": ["ioc", "android"],
                    "description": f"Coincidencia IOC: {ioc_val}",
                }
            )
            bundle_objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": _new_id("relationship"),
                    "created": created_at,
                    "modified": created_at,
                    "relationship_type": "related-to",
                    "source_ref": indicator_id,
                    "target_ref": observed_id,
                }
            )

        for tech in attack_techniques:
            tech_id = str(tech.get("id", "")).strip()
            tech_name = str(tech.get("name", "")).strip() or "Unknown Technique"
            if not tech_id:
                continue

            if tech_id not in attack_pattern_ids:
                attack_pattern_id = _new_id("attack-pattern")
                attack_pattern_ids[tech_id] = attack_pattern_id
                bundle_objects.append(
                    {
                        "type": "attack-pattern",
                        "spec_version": "2.1",
                        "id": attack_pattern_id,
                        "created": now,
                        "modified": now,
                        "name": f"ATT&CK Mobile {tech_id} - {tech_name}",
                        "description": f"Tecnica inferida: {tech_id} ({tech_name})",
                        "x_attack_technique_id": tech_id,
                        "x_attack_tactic": str(tech.get("tactic", "unknown")),
                        "x_inference_confidence": str(tech.get("confidence", "low")),
                    }
                )

            bundle_objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": _new_id("relationship"),
                    "created": created_at,
                    "modified": created_at,
                    "relationship_type": "related-to",
                    "source_ref": observed_id,
                    "target_ref": attack_pattern_ids[tech_id],
                }
            )

    bundle = {
        "type": "bundle",
        "id": _new_id("bundle"),
        "spec_version": "2.1",
        "objects": bundle_objects,
    }
    return bundle
