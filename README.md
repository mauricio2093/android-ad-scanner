# ADB Automation Tool (Modernizado)

Herramienta desktop en Python para analisis de adware/sospecha en Android via ADB.

## Que cambio en esta modernizacion

- Seguridad reforzada: se elimino `shell=True` en ejecucion de comandos.
- Validaciones fuertes para paquetes y keywords antes de invocar ADB.
- UI mas estable: ejecucion asincrona en segundo plano y manejo thread-safe.
- Portabilidad mejorada: filtros y aperturas de carpetas con logica multiplataforma.
- Configuracion externa de reglas: `config/detection_rules.json`.
- Soporte opcional de UI moderna con `ttkbootstrap`.
- Base de proyecto profesional: `pyproject.toml`, tests y `.gitignore`.
- Capa inteligente nueva: base de datos local de threat intel, scoring de riesgo y deteccion de anomalias.

## Requisitos

- Python 3.10+
- Android Platform Tools (`adb`) en `PATH`
- Opcional: Gemini CLI en `PATH` para analisis con IA

## Instalacion

```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows PowerShell

pip install -r requirements.txt
```

## Ejecucion

```bash
python adb_automation_tool.py
```

Si `ttkbootstrap` esta instalado, se usa tema moderno automaticamente.
Puedes cambiar tema con la variable:

```bash
export ADB_TOOL_THEME=flatly
```

## Pruebas

```bash
python -m unittest discover -s tests -p "test_*.py"
```

## Escaneo Inteligente (nuevo)

El GUI ahora incluye:

- `Analisis Inteligente`: escaneo avanzado del paquete seleccionado.
- `Reentrenar Baseline`: recalcula baseline estadistico desde historial local.

Tambien puedes usar CLI:

```bash
python smart_intel_scan.py --device <DEVICE_ID> --package <PACKAGE_NAME> --rebuild-baseline --json-out analisis/intel.json
```

Operaciones avanzadas de Fase 8:

```bash
# listar ultimos 20 escaneos
python smart_intel_scan.py --list-scans 20

# etiquetar un scan (0=benigno, 1=malicioso)
python smart_intel_scan.py --label-scan-id 42 --label 1

# entrenar modelo supervisado con historico etiquetado
python smart_intel_scan.py --train-model --min-samples 20 --max-rows 5000

# exportar threat intel en formato STIX-lite
python smart_intel_scan.py --export-stix --stix-limit 200 --stix-out analisis/stix_lite_bundle.json

# generar dashboard de campañas multi-dispositivo
python smart_intel_scan.py --campaign-dashboard --campaign-limit 3000 --campaign-min-cluster 2 --campaign-out analisis/campaign_dashboard.md
```

Archivos clave:

- DB local: `data/threat_intel.db`
- IOC feed: `config/intel_iocs.json`
- Reportes JSON por escaneo: `analisis/intelligent_scan_*.json`
- Export STIX-lite: `analisis/stix_lite_bundle.json`
- Dashboard campañas: `analisis/campaign_dashboard.md` + `analisis/campaign_dashboard.json`

## Configuracion de reglas

Editar `config/detection_rules.json`:

- `suspicious_packages`: paquetes marcados como riesgo alto.
- `ambiguous_patterns`: patrones heurísticos (regex) para revisiones manuales.
- `suspicious_permissions`: permisos considerados de alto riesgo.

## Reportes de modernizacion

Se documentaron fases en `md/`:

- `md/fase-01-auditoria.md`
- `md/fase-02-soluciones-y-actualizaciones.md`
- `md/fase-03-implementacion-tecnica.md`
- `md/fase-04-roadmap-modernizacion-2026.md`
- `md/fase-05-estudio-estrategico-2026.md`
- `md/fase-06-implementacion-inteligente.md`
- `md/fase-07-proyectos-escalables.md`
- `md/fase-08-ml-supervisado-y-hash-ioc.md`
- `md/fase-09-fingerprint-attack-stix.md`
- `md/fase-10-campaign-correlation-dashboard.md`
