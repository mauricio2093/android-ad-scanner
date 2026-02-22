from __future__ import annotations

import argparse
import json
from pathlib import Path

from intelligence import IntelligentScanPipeline


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Herramienta de operaciones para escaneo inteligente Android"
    )
    parser.add_argument(
        "--db",
        default="data/threat_intel.db",
        help="Ruta de base de datos SQLite (default: data/threat_intel.db)",
    )
    parser.add_argument(
        "--ioc-file",
        default="config/intel_iocs.json",
        help="Ruta de IOC feed local JSON",
    )

    parser.add_argument("--device", default="", help="ADB device id")
    parser.add_argument("--package", default="", help="Package name a analizar")
    parser.add_argument("--json-out", default="", help="Ruta opcional para guardar reporte JSON")
    parser.add_argument(
        "--rebuild-baseline",
        action="store_true",
        help="Recalcula baseline estadistico con historial",
    )

    parser.add_argument(
        "--list-scans",
        type=int,
        default=0,
        help="Lista ultimos N escaneos inteligentes",
    )
    parser.add_argument(
        "--label-scan-id",
        type=int,
        default=0,
        help="ID de scan para etiquetar",
    )
    parser.add_argument(
        "--label",
        type=int,
        choices=[0, 1],
        default=-1,
        help="Etiqueta supervisada: 0=benigno, 1=malicioso",
    )
    parser.add_argument(
        "--train-model",
        action="store_true",
        help="Entrena modelo supervisado con muestras etiquetadas",
    )
    parser.add_argument(
        "--min-samples",
        type=int,
        default=20,
        help="Minimo de muestras etiquetadas para entrenar",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=5000,
        help="Maximo de muestras historicas para entrenamiento",
    )
    parser.add_argument(
        "--export-stix",
        action="store_true",
        help="Exporta bundle STIX-lite desde scans almacenados",
    )
    parser.add_argument(
        "--stix-out",
        default="analisis/stix_lite_bundle.json",
        help="Ruta de salida para bundle STIX-lite",
    )
    parser.add_argument(
        "--stix-limit",
        type=int,
        default=100,
        help="Cantidad maxima de scans para export STIX-lite",
    )
    parser.add_argument(
        "--stix-scan-ids",
        default="",
        help="Lista de IDs de scan separada por comas para export STIX-lite",
    )
    parser.add_argument(
        "--campaign-dashboard",
        action="store_true",
        help="Genera dashboard de correlacion de campanas (multi-dispositivo)",
    )
    parser.add_argument(
        "--campaign-out",
        default="analisis/campaign_dashboard.md",
        help="Ruta de salida markdown para dashboard de campanas",
    )
    parser.add_argument(
        "--campaign-limit",
        type=int,
        default=2000,
        help="Cantidad maxima de scans para analisis de campanas",
    )
    parser.add_argument(
        "--campaign-min-cluster",
        type=int,
        default=2,
        help="Minimo de scans para considerar cluster de campana",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    pipeline = IntelligentScanPipeline(db_path=Path(args.db))
    upserted = pipeline.sync_iocs_from_file(Path(args.ioc_file))
    print(f"[ioc] upserted={upserted}")

    if args.rebuild_baseline:
        rebuilt = pipeline.rebuild_baseline(max_rows=max(100, args.max_rows))
        print(f"[baseline] muestras utilizadas: {rebuilt}")

    if args.list_scans > 0:
        scans = pipeline.get_recent_scans(limit=args.list_scans)
        print(json.dumps(scans, indent=2, ensure_ascii=False))
        return 0

    if args.label_scan_id > 0:
        if args.label not in (0, 1):
            raise SystemExit("--label es obligatorio con --label-scan-id (0 o 1)")
        pipeline.label_scan(scan_id=args.label_scan_id, label=args.label, source="cli")
        print(f"[ok] scan {args.label_scan_id} etiquetado con label={args.label}")
        return 0

    if args.train_model:
        summary = pipeline.train_supervised_model(
            min_samples=max(4, args.min_samples),
            max_rows=max(50, args.max_rows),
        )
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return 0

    if args.export_stix:
        scan_ids: list[int] = []
        if args.stix_scan_ids.strip():
            for part in args.stix_scan_ids.split(","):
                part = part.strip()
                if part:
                    scan_ids.append(int(part))
        out_path = Path(args.stix_out)
        bundle = pipeline.export_stix_lite(
            output_path=out_path,
            limit=max(1, args.stix_limit),
            scan_ids=scan_ids or None,
        )
        print(f"[ok] stix objects={len(bundle.get('objects', []))} output={out_path}")
        return 0

    if args.campaign_dashboard:
        out_path = Path(args.campaign_out)
        summary = pipeline.export_campaign_dashboard(
            output_path=out_path,
            limit=max(1, args.campaign_limit),
            min_cluster_size=max(1, args.campaign_min_cluster),
            top_n=30,
        )
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return 0

    if not args.device or not args.package:
        raise SystemExit(
            "Para escanear debes proveer --device y --package, o usar --list-scans / --label-scan-id / --train-model / --export-stix / --campaign-dashboard"
        )

    result = pipeline.scan_package(device_id=args.device, package_name=args.package)
    payload = result.to_dict()
    payload["ioc_upserted"] = upserted

    print(json.dumps(payload, indent=2, ensure_ascii=False))

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[ok] reporte guardado en {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
