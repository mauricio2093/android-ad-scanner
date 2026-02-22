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

## Scripts de automatizacion

### 1) Release interactivo profesional (tag + changelog + push)

Bash:

```bash
./scripts/release-tag.sh
./scripts/release-tag.sh --repo /ruta/al/proyecto
./scripts/release-tag.sh v1.2.3 --yes-pull --yes-push --remote origin --branch main
```

PowerShell:

```powershell
.\scripts\release-tag.ps1
.\scripts\release-tag.ps1 -RepoPath D:\ruta\al\proyecto
.\scripts\release-tag.ps1 -Version v1.2.3 -YesPull -YesPush -Remote origin -Branch main
```

Incluye:

- preflight control center (estado, unstaging, reset local seguro)
- sync robusto con `fetch + rebase` (evita ambigüedad de pull)
- sugerencias automaticas de commit sin IA (heuristicas por archivos y tipo de cambio)
- staging guiado, commit, versionado semver, tag y push
- salida coloreada profesional
- si no existe repo: permite `git init`, bootstrap inicial (`README` + `first commit` + `main`) y configuracion de `origin`
- en bootstrap inicial: puedes elegir subir todo, solo README o carpetas/archivos especificos

### 2) Ejecutar programa sin `.exe`

```bash
./scripts/run-app.sh
./scripts/run-app.sh --intel -- --list-scans 20
```

```powershell
.\scripts\run-app.ps1
.\scripts\run-app.ps1 -Intel -- --list-scans 20
```

### 3) QA automatizado del flujo de release

```bash
./scripts/qa-release-tag.sh
```

Valida automaticamente en un repositorio temporal:

- preflight interactivo
- sync (`fetch + rebase`)
- commit + tag + push
- flujo con cambios sucios + auto-stash (tracked)
- limpieza final de stash

### 4) Compilar `.exe` moderno (PyInstaller)

Bash:

```bash
./scripts/build-exe.sh --clean --install-pyinstaller
./scripts/build-exe.sh --mode direct --name android-ad-scanner --console
```

PowerShell:

```powershell
.\scripts\build-exe.ps1 -Clean -InstallPyInstaller
.\scripts\build-exe.ps1 -Mode direct -Name android-ad-scanner -Console
```

Notas:

- `spec` usa `adb_automation_tool.spec`.
- `direct` compila desde `adb_automation_tool.py` con parametros.
- En Windows, el artefacto esperado queda en `dist\adb_automation_tool.exe` (o el `-Name` que indiques).

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
