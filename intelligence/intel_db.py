from __future__ import annotations

import datetime
import json
import sqlite3
from pathlib import Path

from .anomaly import BaselineStats
from .models import IntelligentScanResult


class ThreatIntelDB:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    anomaly_score REAL,
                    anomaly_zmax REAL,
                    reasons_json TEXT NOT NULL,
                    ioc_matches_json TEXT NOT NULL,
                    features_json TEXT NOT NULL,
                    raw_snapshot_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_scan_sessions_package_created
                ON scan_sessions (package_name, created_at DESC);

                CREATE TABLE IF NOT EXISTS ioc_signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    confidence REAL NOT NULL,
                    source TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(ioc_type, value)
                );

                CREATE TABLE IF NOT EXISTS model_baseline (
                    feature_name TEXT PRIMARY KEY,
                    mean REAL NOT NULL,
                    std REAL NOT NULL,
                    sample_size INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_labels (
                    scan_id INTEGER PRIMARY KEY,
                    label INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scan_sessions(id)
                );

                CREATE TABLE IF NOT EXISTS ml_models (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    model_name TEXT NOT NULL,
                    model_version TEXT NOT NULL,
                    model_payload_json TEXT NOT NULL,
                    metrics_json TEXT NOT NULL,
                    trained_samples INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ml_models_name_created
                ON ml_models (model_name, created_at DESC);
                """
            )

    def upsert_iocs(self, rows: list[dict]) -> int:
        if not rows:
            return 0

        now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        upserted = 0

        with self._connect() as conn:
            for row in rows:
                ioc_type = str(row.get("ioc_type", "keyword")).strip().lower()
                value = str(row.get("value", "")).strip().lower()
                if not value:
                    continue

                severity = int(row.get("severity", 5))
                confidence = float(row.get("confidence", 0.7))
                source = str(row.get("source", "local")).strip() or "local"
                active = 1 if bool(row.get("active", True)) else 0

                conn.execute(
                    """
                    INSERT INTO ioc_signatures (
                        ioc_type, value, severity, confidence, source, active, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ioc_type, value)
                    DO UPDATE SET
                        severity=excluded.severity,
                        confidence=excluded.confidence,
                        source=excluded.source,
                        active=excluded.active,
                        updated_at=excluded.updated_at
                    """,
                    (ioc_type, value, severity, confidence, source, active, now, now),
                )
                upserted += 1

        return upserted

    def get_active_iocs(self) -> list[sqlite3.Row]:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT ioc_type, value, severity, confidence, source FROM ioc_signatures WHERE active=1"
            )
            return list(cur.fetchall())

    def store_scan(self, result: IntelligentScanResult, raw_snapshot: dict) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO scan_sessions (
                    created_at, device_id, package_name,
                    risk_score, risk_level, anomaly_score, anomaly_zmax,
                    reasons_json, ioc_matches_json, features_json, raw_snapshot_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.timestamp_utc,
                    result.device_id,
                    result.package_name,
                    result.risk_score,
                    result.risk_level,
                    result.anomaly_score,
                    result.anomaly_zmax,
                    json.dumps(result.reasons, ensure_ascii=False),
                    json.dumps(result.ioc_matches, ensure_ascii=False),
                    json.dumps(result.feature_vector.to_dict(), ensure_ascii=False),
                    json.dumps(raw_snapshot, ensure_ascii=False),
                ),
            )
            return int(cur.lastrowid)

    def get_latest_scan_id_for_package(self, package_name: str) -> int | None:
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT id
                FROM scan_sessions
                WHERE package_name=?
                ORDER BY created_at DESC, id DESC
                LIMIT 1
                """,
                (package_name,),
            )
            row = cur.fetchone()
            return None if row is None else int(row["id"])

    def get_recent_scans(self, limit: int = 20) -> list[sqlite3.Row]:
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT s.id, s.created_at, s.device_id, s.package_name,
                       s.risk_score, s.risk_level, l.label
                FROM scan_sessions s
                LEFT JOIN scan_labels l ON l.scan_id=s.id
                ORDER BY s.created_at DESC, s.id DESC
                LIMIT ?
                """,
                (int(limit),),
            )
            return list(cur.fetchall())

    def get_scan_records(self, limit: int = 100) -> list[dict]:
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT s.id, s.created_at, s.device_id, s.package_name,
                       s.risk_score, s.risk_level,
                       s.anomaly_score, s.anomaly_zmax,
                       s.reasons_json, s.ioc_matches_json, s.features_json, s.raw_snapshot_json,
                       l.label
                FROM scan_sessions s
                LEFT JOIN scan_labels l ON l.scan_id=s.id
                ORDER BY s.created_at DESC, s.id DESC
                LIMIT ?
                """,
                (int(limit),),
            )
            rows = list(cur.fetchall())
        return [self._row_to_scan_record(row) for row in rows]

    def get_scan_records_by_ids(self, scan_ids: list[int]) -> list[dict]:
        if not scan_ids:
            return []

        placeholders = ",".join("?" for _ in scan_ids)
        with self._connect() as conn:
            cur = conn.execute(
                f"""
                SELECT s.id, s.created_at, s.device_id, s.package_name,
                       s.risk_score, s.risk_level,
                       s.anomaly_score, s.anomaly_zmax,
                       s.reasons_json, s.ioc_matches_json, s.features_json, s.raw_snapshot_json,
                       l.label
                FROM scan_sessions s
                LEFT JOIN scan_labels l ON l.scan_id=s.id
                WHERE s.id IN ({placeholders})
                ORDER BY s.created_at DESC, s.id DESC
                """,
                tuple(int(value) for value in scan_ids),
            )
            rows = list(cur.fetchall())
        return [self._row_to_scan_record(row) for row in rows]

    def _row_to_scan_record(self, row: sqlite3.Row) -> dict:
        def _safe_json(payload: str, default):
            try:
                return json.loads(payload)
            except Exception:
                return default

        raw_snapshot = _safe_json(str(row["raw_snapshot_json"]), {})
        attack_techniques = raw_snapshot.get("attack_techniques", [])
        if not isinstance(attack_techniques, list):
            attack_techniques = []

        return {
            "id": int(row["id"]),
            "created_at": str(row["created_at"]),
            "device_id": str(row["device_id"]),
            "package_name": str(row["package_name"]),
            "risk_score": float(row["risk_score"]),
            "risk_level": str(row["risk_level"]),
            "anomaly_score": None if row["anomaly_score"] is None else float(row["anomaly_score"]),
            "anomaly_zmax": None if row["anomaly_zmax"] is None else float(row["anomaly_zmax"]),
            "label": None if row["label"] is None else int(row["label"]),
            "reasons": _safe_json(str(row["reasons_json"]), []),
            "ioc_matches": _safe_json(str(row["ioc_matches_json"]), []),
            "features": _safe_json(str(row["features_json"]), {}),
            "raw_snapshot": raw_snapshot,
            "attack_techniques": attack_techniques,
        }

    def set_scan_label(self, scan_id: int, label: int, source: str = "analyst") -> None:
        if label not in (0, 1):
            raise ValueError("label debe ser 0 (benigno) o 1 (malicioso)")
        now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_labels (scan_id, label, source, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(scan_id)
                DO UPDATE SET label=excluded.label, source=excluded.source, created_at=excluded.created_at
                """,
                (scan_id, label, source, now),
            )

    def get_labeled_feature_rows(self, max_rows: int = 5000) -> list[tuple[dict, int]]:
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT s.features_json, l.label
                FROM scan_sessions s
                INNER JOIN scan_labels l ON l.scan_id=s.id
                ORDER BY s.created_at DESC, s.id DESC
                LIMIT ?
                """,
                (int(max_rows),),
            )
            rows = list(cur.fetchall())

        dataset: list[tuple[dict, int]] = []
        for row in rows:
            try:
                features = json.loads(row["features_json"])
            except json.JSONDecodeError:
                continue
            dataset.append((features, int(row["label"])))
        return dataset

    def store_ml_model(
        self,
        model_name: str,
        model_version: str,
        model_payload: dict,
        metrics_payload: dict,
        trained_samples: int,
    ) -> int:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO ml_models (
                    model_name, model_version, model_payload_json, metrics_json, trained_samples, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    model_name,
                    model_version,
                    json.dumps(model_payload, ensure_ascii=False),
                    json.dumps(metrics_payload, ensure_ascii=False),
                    int(trained_samples),
                    now,
                ),
            )
            return int(cur.lastrowid)

    def get_latest_ml_model(self, model_name: str) -> sqlite3.Row | None:
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT id, model_name, model_version, model_payload_json, metrics_json, trained_samples, created_at
                FROM ml_models
                WHERE model_name=?
                ORDER BY created_at DESC, id DESC
                LIMIT 1
                """,
                (model_name,),
            )
            return cur.fetchone()

    def load_baseline(self) -> BaselineStats | None:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT feature_name, mean, std, sample_size FROM model_baseline"
            )
            rows = list(cur.fetchall())

        if not rows:
            return None

        means = {row["feature_name"]: float(row["mean"]) for row in rows}
        stds = {row["feature_name"]: float(row["std"]) for row in rows}
        sample_size = min(int(row["sample_size"]) for row in rows)
        return BaselineStats(means=means, stds=stds, sample_size=sample_size)

    def rebuild_baseline_from_history(self, max_rows: int = 500) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT features_json
                FROM scan_sessions
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (max_rows,),
            )
            rows = list(cur.fetchall())

        if not rows:
            return 0

        vectors: list[dict] = []
        for row in rows:
            try:
                vectors.append(json.loads(row["features_json"]))
            except json.JSONDecodeError:
                continue

        if not vectors:
            return 0

        numeric_keys = [
            "permissions_total",
            "suspicious_permissions_count",
            "dangerous_permissions_count",
            "ad_sdk_hits",
            "tracker_hits",
            "suspicious_keyword_hits",
        ]

        n = len(vectors)
        means: dict[str, float] = {}
        stds: dict[str, float] = {}

        for key in numeric_keys:
            values = [float(v.get(key, 0.0)) for v in vectors]
            mean = sum(values) / n
            variance = sum((value - mean) ** 2 for value in values) / max(1, (n - 1))
            std = variance ** 0.5
            means[key] = mean
            stds[key] = std

        now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        with self._connect() as conn:
            for key in numeric_keys:
                conn.execute(
                    """
                    INSERT INTO model_baseline (feature_name, mean, std, sample_size, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(feature_name)
                    DO UPDATE SET mean=excluded.mean, std=excluded.std,
                        sample_size=excluded.sample_size, updated_at=excluded.updated_at
                    """,
                    (key, means[key], stds[key], n, now),
                )

        return n
