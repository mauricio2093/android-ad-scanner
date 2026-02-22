from __future__ import annotations

import datetime
import hashlib
import json
from collections import defaultdict


def _parse_ts(value: str) -> datetime.datetime | None:
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


def _score_to_level(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 55:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _trend_label(timestamps: list[datetime.datetime]) -> tuple[str, int, int]:
    if not timestamps:
        return ("unknown", 0, 0)

    now = max(timestamps)
    window_last = now - datetime.timedelta(hours=24)
    window_prev = now - datetime.timedelta(hours=48)

    last_count = sum(1 for value in timestamps if value >= window_last)
    prev_count = sum(1 for value in timestamps if window_prev <= value < window_last)

    if prev_count == 0 and last_count > 0:
        return ("emerging", last_count, prev_count)

    ratio = (last_count - prev_count) / max(1, prev_count)
    if ratio > 0.4:
        trend = "growing"
    elif ratio < -0.4:
        trend = "declining"
    else:
        trend = "stable"

    return (trend, last_count, prev_count)


def _campaign_id(seed: str) -> str:
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:12]
    return f"camp-{digest}"


def summarize_campaigns(scan_records: list[dict], min_cluster_size: int = 2) -> dict:
    groups: dict[str, list[dict]] = defaultdict(list)

    for record in scan_records:
        raw = dict(record.get("raw_snapshot", {}))
        package_name = str(record.get("package_name", "unknown"))
        apk_sha256 = str(raw.get("apk_sha256", "")).strip().lower()
        component_fp = str(raw.get("component_fingerprint", "")).strip().lower()

        if apk_sha256:
            key = f"sha256:{apk_sha256}"
        elif component_fp:
            key = f"fingerprint:{component_fp}"
        else:
            key = f"package:{package_name.lower()}"

        groups[key].append(record)

    clusters: list[dict] = []
    for key, items in groups.items():
        if len(items) < max(1, min_cluster_size):
            continue

        devices = sorted({str(item.get("device_id", "unknown")) for item in items})
        packages = sorted({str(item.get("package_name", "unknown")) for item in items})
        scores = [float(item.get("risk_score", 0.0)) for item in items]
        labels = [item.get("label") for item in items]
        label_malicious = sum(1 for label in labels if label == 1)
        ioc_count = sum(len(list(item.get("ioc_matches", []))) for item in items)
        attack_ids = sorted(
            {
                str(tech.get("id", ""))
                for item in items
                for tech in list(item.get("attack_techniques", []))
                if str(tech.get("id", "")).strip()
            }
        )

        timestamps = [
            parsed
            for parsed in (_parse_ts(str(item.get("created_at", ""))) for item in items)
            if parsed is not None
        ]

        if timestamps:
            first_seen = min(timestamps).isoformat()
            last_seen = max(timestamps).isoformat()
        else:
            first_seen = ""
            last_seen = ""

        trend, scans_24h, scans_prev_24h = _trend_label(timestamps)

        avg_risk = sum(scores) / max(1, len(scores))
        max_risk = max(scores) if scores else 0.0
        ioc_density = ioc_count / max(1, len(items))
        malicious_ratio = label_malicious / max(1, len(items))

        campaign_score = (
            (avg_risk * 0.55)
            + (max_risk * 0.2)
            + (min(100.0, len(devices) * 12.0) * 0.1)
            + (min(100.0, len(items) * 8.0) * 0.05)
            + (min(100.0, len(attack_ids) * 15.0) * 0.05)
            + (min(100.0, ioc_density * 40.0) * 0.03)
            + (min(100.0, malicious_ratio * 100.0) * 0.02)
        )

        if trend == "growing":
            campaign_score += 5.0
        elif trend == "emerging":
            campaign_score += 3.0

        campaign_score = round(min(100.0, campaign_score), 2)

        cluster_seed = f"{key}|{','.join(devices)}|{','.join(packages)}"
        clusters.append(
            {
                "campaign_id": _campaign_id(cluster_seed),
                "cluster_key": key,
                "campaign_score": campaign_score,
                "campaign_level": _score_to_level(campaign_score),
                "scan_count": len(items),
                "device_count": len(devices),
                "package_count": len(packages),
                "devices": devices,
                "packages": packages,
                "avg_risk": round(avg_risk, 2),
                "max_risk": round(max_risk, 2),
                "ioc_density": round(ioc_density, 3),
                "ioc_matches_total": ioc_count,
                "attack_techniques": attack_ids,
                "malicious_label_ratio": round(malicious_ratio, 3),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "trend": trend,
                "scans_last_24h": scans_24h,
                "scans_prev_24h": scans_prev_24h,
                "scan_ids": sorted(int(item.get("id", 0)) for item in items if int(item.get("id", 0)) > 0),
            }
        )

    clusters.sort(key=lambda value: (value["campaign_score"], value["scan_count"]), reverse=True)

    high_risk_scans = sum(1 for item in scan_records if float(item.get("risk_score", 0.0)) >= 55.0)
    global_devices = sorted({str(item.get("device_id", "unknown")) for item in scan_records})
    global_packages = sorted({str(item.get("package_name", "unknown")) for item in scan_records})

    return {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "total_scans": len(scan_records),
        "high_risk_scans": high_risk_scans,
        "global_device_count": len(global_devices),
        "global_package_count": len(global_packages),
        "clusters": clusters,
    }


def build_campaign_dashboard_markdown(summary: dict, top_n: int = 20) -> str:
    lines: list[str] = []
    lines.append("# Campaign Correlation Dashboard")
    lines.append("")
    lines.append(f"Generated at (UTC): {summary.get('generated_at', '')}")
    lines.append(f"Total scans: {summary.get('total_scans', 0)}")
    lines.append(f"High risk scans: {summary.get('high_risk_scans', 0)}")
    lines.append(f"Devices observed: {summary.get('global_device_count', 0)}")
    lines.append(f"Packages observed: {summary.get('global_package_count', 0)}")
    lines.append("")

    clusters = list(summary.get("clusters", []))[: max(1, top_n)]
    if not clusters:
        lines.append("No campaign clusters found with current filters.")
        return "\n".join(lines) + "\n"

    lines.append("## Top Campaigns")
    lines.append("")
    lines.append("| Campaign | Score | Level | Scans | Devices | Packages | Trend |")
    lines.append("|---|---:|---|---:|---:|---:|---|")
    for cluster in clusters:
        lines.append(
            "| {cid} | {score} | {level} | {scans} | {devices} | {packages} | {trend} |".format(
                cid=cluster.get("campaign_id"),
                score=cluster.get("campaign_score"),
                level=cluster.get("campaign_level"),
                scans=cluster.get("scan_count"),
                devices=cluster.get("device_count"),
                packages=cluster.get("package_count"),
                trend=cluster.get("trend"),
            )
        )
    lines.append("")

    for cluster in clusters:
        lines.append(f"### {cluster.get('campaign_id')} ({cluster.get('campaign_level')})")
        lines.append(f"- Cluster key: `{cluster.get('cluster_key')}`")
        lines.append(f"- Campaign score: {cluster.get('campaign_score')}")
        lines.append(f"- Avg risk / Max risk: {cluster.get('avg_risk')} / {cluster.get('max_risk')}")
        lines.append(f"- Trend: {cluster.get('trend')} (24h={cluster.get('scans_last_24h')}, prev24h={cluster.get('scans_prev_24h')})")
        lines.append(f"- Devices: {', '.join(cluster.get('devices', []))}")
        lines.append(f"- Packages: {', '.join(cluster.get('packages', []))}")
        lines.append(
            f"- ATT&CK techniques: {', '.join(cluster.get('attack_techniques', [])) if cluster.get('attack_techniques') else 'none'}"
        )
        lines.append(f"- IOC density: {cluster.get('ioc_density')} (total={cluster.get('ioc_matches_total')})")
        lines.append(f"- First seen: {cluster.get('first_seen')}")
        lines.append(f"- Last seen: {cluster.get('last_seen')}")
        lines.append(f"- Scan IDs: {', '.join(str(value) for value in cluster.get('scan_ids', []))}")
        lines.append("")

    return "\n".join(lines) + "\n"


def serialize_campaign_summary(summary: dict) -> str:
    return json.dumps(summary, indent=2, ensure_ascii=False)
