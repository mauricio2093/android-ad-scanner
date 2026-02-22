from __future__ import annotations

from .models import FeatureVector


def infer_attack_techniques(features: FeatureVector, dumpsys_text: str) -> list[dict[str, str]]:
    """Infer ATT&CK Mobile techniques from observable app traits.

    Note: this is evidence-based inference (heuristic), not definitive attribution.
    """
    lowered = dumpsys_text.lower()
    techniques: list[dict[str, str]] = []

    if features.accessibility_binding_detected:
        techniques.append(
            {
                "id": "T1453",
                "name": "Abuse Accessibility Features",
                "tactic": "Privilege Escalation/Defense Evasion",
                "confidence": "high",
            }
        )

    if features.boot_receiver_detected:
        techniques.append(
            {
                "id": "T1624.001",
                "name": "Broadcast Receivers",
                "tactic": "Persistence",
                "confidence": "high",
            }
        )

    if features.overlay_permission_detected:
        techniques.append(
            {
                "id": "T1417.002",
                "name": "GUI Input Capture",
                "tactic": "Credential Access",
                "confidence": "medium",
            }
        )

    if features.suspicious_permissions_count > 0:
        techniques.append(
            {
                "id": "T1636",
                "name": "Protected User Data",
                "tactic": "Collection",
                "confidence": "medium",
            }
        )

    if "bind_notification_listener_service" in lowered:
        techniques.append(
            {
                "id": "T1517",
                "name": "Access Notifications",
                "tactic": "Collection",
                "confidence": "medium",
            }
        )

    if "bind_device_admin" in lowered or "device_admin" in lowered:
        techniques.append(
            {
                "id": "T1626",
                "name": "Abuse Elevation Control Mechanism",
                "tactic": "Privilege Escalation",
                "confidence": "low",
            }
        )

    deduped: dict[str, dict[str, str]] = {}
    for technique in techniques:
        deduped[technique["id"]] = technique
    return list(deduped.values())
