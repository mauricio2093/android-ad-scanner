from __future__ import annotations

import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Pattern, Sequence

try:
    import ttkbootstrap as tb
except ImportError:
    tb = None

try:
    from intelligence import IntelligentScanPipeline
except Exception:
    IntelligentScanPipeline = None  # type: ignore[assignment]


PACKAGE_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z0-9_]+)+$")
SAFE_KEYWORD_RE = re.compile(r"^[a-zA-Z0-9._-]{2,80}$")

DEFAULT_DETECTION_RULES = {
    "suspicious_packages": [
        "com.example.adware",
        "com.malicious.app",
        "com.spyware.data",
    ],
    "ambiguous_patterns": [
        "ad",
        "track",
        "analytics",
    ],
    "suspicious_permissions": [
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.READ_LOGS",
        "android.permission.WRITE_SETTINGS",
        "android.permission.PACKAGE_USAGE_STATS",
    ],
}


def is_valid_package_name(value: str) -> bool:
    return bool(PACKAGE_NAME_RE.fullmatch(value.strip()))


def is_safe_keyword(value: str) -> bool:
    return bool(SAFE_KEYWORD_RE.fullmatch(value.strip()))


def extract_device_ids(adb_devices_output: str) -> list[str]:
    devices: list[str] = []
    for line in adb_devices_output.splitlines():
        parts = line.strip().split("\t")
        if len(parts) == 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


def filter_lines_with_pattern(content: str, pattern: str | Pattern[str]) -> str:
    regex = re.compile(pattern, re.IGNORECASE) if isinstance(pattern, str) else pattern
    lines = [line for line in content.splitlines() if regex.search(line)]
    return "\n".join(lines) + ("\n" if lines else "")


class ADBAutomationTool:
    def __init__(self, master: tk.Tk):
        self.master = master
        self.main_thread_id = threading.get_ident()
        self.command_timeout_seconds = 90

        self.master.title("ADB Automation Tool")
        self.master.geometry("980x760")
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.devices: list[str] = []
        self.analysis_files: list[Path] = []
        self.gemini_analysis_content: str | None = None

        self.logcat_process: subprocess.Popen[str] | None = None
        self.logcat_lock = threading.Lock()
        self.logcat_stop_event = threading.Event()
        self.logcat_buffer: list[str] = []

        if getattr(sys, "frozen", False):
            self.base_path = Path(sys.executable).resolve().parent
        else:
            self.base_path = Path(__file__).resolve().parent

        self.analysis_dir = self.base_path / "analisis"
        self.analysis_dir.mkdir(exist_ok=True)
        self.data_dir = self.base_path / "data"
        self.data_dir.mkdir(exist_ok=True)

        self.config_dir = self.base_path / "config"
        self.config_dir.mkdir(exist_ok=True)
        self.rules_file = self.config_dir / "detection_rules.json"
        self.intel_ioc_file = self.config_dir / "intel_iocs.json"
        self.intel_db_path = self.data_dir / "threat_intel.db"
        self.intel_pipeline = None
        self.last_intelligent_scan_id: int | None = None

        self.suspicious_packages: list[str] = []
        self.suspicious_packages_set: set[str] = set()
        self.ambiguous_patterns: list[str] = []
        self.ambiguous_regexes: list[Pattern[str]] = []
        self.suspicious_permissions: list[str] = []

        self._build_ui()
        self._load_detection_rules()
        self._init_intelligence_layer()
        self.check_adb_path()
        self.check_gemini_installed()

    def _build_ui(self) -> None:
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_columnconfigure(0, weight=1)

        self.main_frame = ttk.Frame(self.master, padding="10")
        self.main_frame.grid(row=0, column=0, sticky="nsew")
        self.main_frame.grid_rowconfigure(5, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        self.control_frame = ttk.LabelFrame(self.main_frame, text="Controles", padding="10")
        self.control_frame.grid(row=0, column=0, sticky="ew", pady=6)
        for col in range(4):
            self.control_frame.grid_columnconfigure(col, weight=1)

        self.initialize_button = ttk.Button(
            self.control_frame,
            text="Inicializar ADB y Dispositivos",
            command=self.initialize_adb,
        )
        self.initialize_button.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        self.device_label = ttk.Label(self.control_frame, text="Seleccionar Dispositivo:")
        self.device_label.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        self.selected_device = tk.StringVar()
        self.device_combobox = ttk.Combobox(
            self.control_frame,
            textvariable=self.selected_device,
            state="readonly",
        )
        self.device_combobox.grid(row=0, column=2, padx=5, pady=5, sticky="ew")
        self.device_combobox.bind("<<ComboboxSelected>>", self.on_device_selected)

        self.package_label = ttk.Label(self.control_frame, text="Paquete / Keyword:")
        self.package_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.package_entry = ttk.Entry(self.control_frame)
        self.package_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        self.package_entry.insert(0, "com.example.adware")

        self.command_buttons_frame = ttk.LabelFrame(
            self.main_frame,
            text="Comandos de Analisis",
            padding="10",
        )
        self.command_buttons_frame.grid(row=1, column=0, sticky="ew", pady=6)
        for col in range(4):
            self.command_buttons_frame.grid_columnconfigure(col, weight=1)

        ttk.Button(
            self.command_buttons_frame,
            text="Ver app en foco",
            command=self.get_current_focus,
        ).grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        self.logcat_button = ttk.Button(
            self.command_buttons_frame,
            text="Ver logs en tiempo real",
            command=self.search_ad_logs,
        )
        self.logcat_button.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        ttk.Button(
            self.command_buttons_frame,
            text='Ver procesos que tengan "ad"',
            command=self.search_ad_processes,
        ).grid(row=0, column=2, padx=5, pady=5, sticky="ew")

        ttk.Button(
            self.command_buttons_frame,
            text="Ver paquetes instalados por keyword",
            command=self.search_packages_by_keyword,
        ).grid(row=0, column=3, padx=5, pady=5, sticky="ew")

        ttk.Button(
            self.command_buttons_frame,
            text="Obtener info detallada de un paquete",
            command=self.investigate_package,
        ).grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        ttk.Button(
            self.command_buttons_frame,
            text="Listar paquetes de terceros",
            command=self.list_installed_packages_history,
        ).grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        ttk.Button(
            self.command_buttons_frame,
            text="Permisos sospechosos",
            command=self.list_apps_with_suspicious_permissions,
        ).grid(row=1, column=2, padx=5, pady=5, sticky="ew")

        ttk.Button(
            self.command_buttons_frame,
            text="Monitorear foco actual",
            command=self.monitor_current_focus,
        ).grid(row=1, column=3, padx=5, pady=5, sticky="ew")

        ttk.Button(
            self.command_buttons_frame,
            text="Extraer apps sospechosas",
            command=self.extract_suspicious_apps,
        ).grid(row=2, column=0, padx=5, pady=5, sticky="ew")

        ttk.Button(
            self.command_buttons_frame,
            text="Listar todas las apps",
            command=self.list_all_apps,
        ).grid(row=2, column=1, padx=5, pady=5, sticky="ew")

        ttk.Button(
            self.command_buttons_frame,
            text="Listar apps del sistema",
            command=self.list_system_apps,
        ).grid(row=2, column=2, padx=5, pady=5, sticky="ew")

        ttk.Button(
            self.command_buttons_frame,
            text="Apps con instalador",
            command=self.list_installer_apps,
        ).grid(row=2, column=3, padx=5, pady=5, sticky="ew")

        self.action_buttons_frame = ttk.LabelFrame(
            self.main_frame,
            text="Acciones de Mantenimiento",
            padding="10",
        )
        self.action_buttons_frame.grid(row=2, column=0, sticky="ew", pady=6)
        self.action_buttons_frame.grid_columnconfigure(0, weight=1)
        self.action_buttons_frame.grid_columnconfigure(1, weight=1)

        ttk.Button(
            self.action_buttons_frame,
            text="Desinstalar Paquete",
            command=self.uninstall_package,
        ).grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        ttk.Button(
            self.action_buttons_frame,
            text="Limpiar Salida",
            command=self.clear_output,
        ).grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.analysis_buttons_frame = ttk.LabelFrame(
            self.main_frame,
            text="Gestion de Analisis",
            padding="10",
        )
        self.analysis_buttons_frame.grid(row=3, column=0, sticky="ew", pady=6)
        self.analysis_buttons_frame.grid_columnconfigure(0, weight=1)
        self.analysis_buttons_frame.grid_columnconfigure(1, weight=1)

        ttk.Button(
            self.analysis_buttons_frame,
            text="Mostrar Analisis",
            command=self.show_analysis_folder,
        ).grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        ttk.Button(
            self.analysis_buttons_frame,
            text="Descargar Analisis",
            command=self.download_analysis,
        ).grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.analyze_gemini_button = ttk.Button(
            self.analysis_buttons_frame,
            text="Analizar con Gemini",
            command=self.analyze_with_gemini,
            state="disabled",
        )
        self.analyze_gemini_button.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        self.gemini_info_text = tk.StringVar(value="Gemini CLI no detectado.")
        ttk.Label(
            self.analysis_buttons_frame,
            textvariable=self.gemini_info_text,
            wraplength=360,
            justify="left",
        ).grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        self.intelligent_scan_button = ttk.Button(
            self.analysis_buttons_frame,
            text="Analisis Inteligente",
            command=self.run_intelligent_scan,
            state="disabled",
        )
        self.intelligent_scan_button.grid(row=2, column=0, padx=5, pady=5, sticky="ew")

        self.rebuild_baseline_button = ttk.Button(
            self.analysis_buttons_frame,
            text="Reentrenar Baseline",
            command=self.rebuild_intel_baseline,
            state="disabled",
        )
        self.rebuild_baseline_button.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

        self.label_malicious_button = ttk.Button(
            self.analysis_buttons_frame,
            text="Etiquetar Maliciosa",
            command=self.label_current_package_malicious,
            state="disabled",
        )
        self.label_malicious_button.grid(row=3, column=0, padx=5, pady=5, sticky="ew")

        self.label_benign_button = ttk.Button(
            self.analysis_buttons_frame,
            text="Etiquetar Benigna",
            command=self.label_current_package_benign,
            state="disabled",
        )
        self.label_benign_button.grid(row=3, column=1, padx=5, pady=5, sticky="ew")

        self.train_model_button = ttk.Button(
            self.analysis_buttons_frame,
            text="Entrenar Modelo ML",
            command=self.train_supervised_model,
            state="disabled",
        )
        self.train_model_button.grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

        self.export_stix_button = ttk.Button(
            self.analysis_buttons_frame,
            text="Exportar STIX-lite",
            command=self.export_stix_lite_bundle,
            state="disabled",
        )
        self.export_stix_button.grid(row=5, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

        self.campaign_dashboard_button = ttk.Button(
            self.analysis_buttons_frame,
            text="Dashboard Campanas",
            command=self.export_campaign_dashboard,
            state="disabled",
        )
        self.campaign_dashboard_button.grid(row=6, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

        self.intel_info_text = tk.StringVar(value="Intelligence layer no inicializada.")
        ttk.Label(
            self.analysis_buttons_frame,
            textvariable=self.intel_info_text,
            wraplength=360,
            justify="left",
        ).grid(row=7, column=0, columnspan=2, padx=5, pady=(2, 5), sticky="ew")

        ttk.Label(self.main_frame, text="Salida de Comandos:").grid(row=4, column=0, sticky="w")

        self.output_text = scrolledtext.ScrolledText(
            self.main_frame,
            wrap=tk.WORD,
            height=24,
            state="disabled",
        )
        self.output_text.grid(row=5, column=0, sticky="nsew", pady=(6, 0))
        self.output_text.tag_config("red", foreground="red")
        self.output_text.tag_config("yellow", foreground="orange")
        self.output_text.tag_config("green", foreground="green")

        self.status_text = tk.StringVar(value="Listo")
        ttk.Label(self.main_frame, textvariable=self.status_text, anchor="w").grid(
            row=6,
            column=0,
            sticky="ew",
            pady=(6, 0),
        )

    def _load_detection_rules(self) -> None:
        if not self.rules_file.exists():
            self.rules_file.write_text(
                json.dumps(DEFAULT_DETECTION_RULES, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            self.append_output(
                f"Se creo la configuracion base de reglas en: {self.rules_file.name}\n"
            )

        try:
            data = json.loads(self.rules_file.read_text(encoding="utf-8"))
        except Exception as exc:
            self.append_output(
                f"Error leyendo reglas personalizadas ({exc}). Se usan reglas por defecto.\n"
            )
            data = DEFAULT_DETECTION_RULES

        suspicious_packages = data.get("suspicious_packages", [])
        ambiguous_patterns = data.get("ambiguous_patterns", [])
        suspicious_permissions = data.get("suspicious_permissions", [])

        self.suspicious_packages = [pkg for pkg in suspicious_packages if isinstance(pkg, str)]
        self.suspicious_packages_set = {pkg.lower() for pkg in self.suspicious_packages}

        self.ambiguous_patterns = [pat for pat in ambiguous_patterns if isinstance(pat, str)]
        self.ambiguous_regexes = []
        for pattern in self.ambiguous_patterns:
            try:
                self.ambiguous_regexes.append(re.compile(pattern, re.IGNORECASE))
            except re.error:
                self.append_output(f"Regla regex invalida ignorada: {pattern}\n")

        self.suspicious_permissions = [
            perm for perm in suspicious_permissions if isinstance(perm, str)
        ]

    def _init_intelligence_layer(self) -> None:
        if IntelligentScanPipeline is None:
            self.intel_info_text.set(
                "Intelligence layer no disponible (error de importacion del modulo)."
            )
            return

        try:
            self.intel_pipeline = IntelligentScanPipeline(db_path=self.intel_db_path)
            upserted = self.intel_pipeline.sync_iocs_from_file(self.intel_ioc_file)
            self.intelligent_scan_button.config(state="normal")
            self.rebuild_baseline_button.config(state="normal")
            self.label_malicious_button.config(state="normal")
            self.label_benign_button.config(state="normal")
            self.train_model_button.config(state="normal")
            self.export_stix_button.config(state="normal")
            self.campaign_dashboard_button.config(state="normal")
            model_info = "sin modelo ML entrenado"
            if getattr(self.intel_pipeline, "ml_model", None) is not None:
                model_info = f"modelo ML cargado ({self.intel_pipeline.ml_model.version})"
            self.intel_info_text.set(
                f"Intelligence layer activa. IOC sync inicial: {upserted}. DB: {self.intel_db_path.name}. {model_info}"
            )
        except Exception as exc:
            self.intel_pipeline = None
            self.intel_info_text.set(f"Intelligence layer deshabilitada: {exc}")

    def on_closing(self) -> None:
        self._stop_logcat()
        self.master.destroy()

    def set_status(self, text: str) -> None:
        if threading.get_ident() != self.main_thread_id:
            self.master.after(0, self.set_status, text)
            return
        self.status_text.set(text)

    def append_output(self, text: str) -> None:
        if threading.get_ident() != self.main_thread_id:
            self.master.after(0, self.append_output, text)
            return

        self.output_text.config(state="normal")
        package_name_pattern = r"\b(?:[a-z0-9_]+\.)+[a-z0-9_]+\b"

        for line in text.splitlines(True):
            last_idx = 0
            for match in re.finditer(package_name_pattern, line, re.IGNORECASE):
                package_name = match.group(0)
                start, end = match.span()

                self.output_text.insert(tk.END, line[last_idx:start])

                tag = "green"
                lower_package = package_name.lower()
                if lower_package in self.suspicious_packages_set:
                    tag = "red"
                else:
                    for pattern in self.ambiguous_regexes:
                        if pattern.search(package_name):
                            tag = "yellow"
                            break

                self.output_text.insert(tk.END, package_name, tag)
                last_idx = end

            self.output_text.insert(tk.END, line[last_idx:])

        self.output_text.see(tk.END)
        self.output_text.config(state="disabled")

    def clear_output(self) -> None:
        self.output_text.config(state="normal")
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state="disabled")

    def _save_analysis_log(self, command_name: str, output_content: str) -> None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{command_name}_{timestamp}.txt"
        filepath = self.analysis_dir / filename
        try:
            filepath.write_text(
                "\n".join(
                    [
                        f"--- Comando: {command_name} ---",
                        f"--- Fecha/Hora: {timestamp} ---",
                        "",
                        output_content,
                    ]
                ),
                encoding="utf-8",
            )
            self.analysis_files.append(filepath)
            self.append_output(f"Analisis guardado en: {filename}\n")
        except Exception as exc:
            self.append_output(f"Error al guardar el analisis en {filename}: {exc}\n")

    def handle_command_output(self, output: str, command_name: str = "Comando ADB") -> None:
        if not output.endswith("\n"):
            output = f"{output}\n"
        self.append_output(output)
        self.append_output("-" * 50 + "\n")
        self._save_analysis_log(command_name, output)

    def handle_command_error(self, error_output: str, command_name: str = "Comando ADB") -> None:
        clean_error = error_output.strip() if error_output else "Error sin detalle"
        self.append_output(f"ERROR ({command_name}):\n{clean_error}\n")
        self.append_output("-" * 50 + "\n")
        self._save_analysis_log(f"ERROR_{command_name}", clean_error)

    def _run_background(self, func, status: str | None = None) -> None:
        if status:
            self.set_status(status)

        def runner() -> None:
            try:
                func()
            except Exception as exc:
                self.append_output(f"ERROR interno no controlado: {exc}\n")
            finally:
                if status:
                    self.set_status("Listo")

        threading.Thread(target=runner, daemon=True).start()

    def _format_subprocess_error(self, exc: subprocess.CalledProcessError) -> str:
        stderr = (exc.stderr or "").strip()
        stdout = (exc.stdout or "").strip()
        if stderr:
            return stderr
        if stdout:
            return stdout
        return str(exc)

    def _run_subprocess(self, args: Sequence[str], timeout: int | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(args),
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout or self.command_timeout_seconds,
        )

    def _get_selected_device(self) -> str | None:
        device = self.selected_device.get().strip()
        if not device:
            self.append_output("ERROR: No hay dispositivo seleccionado.\n")
            return None
        return device

    def _get_validated_package(self) -> str | None:
        package_name = self.package_entry.get().strip()
        if not package_name:
            self.append_output("ERROR: Ingrese un nombre de paquete.\n")
            return None
        if not is_valid_package_name(package_name):
            self.append_output(
                "ERROR: Formato de paquete invalido. Ejemplo valido: com.empresa.app\n"
            )
            return None
        return package_name

    def _set_devices(self, devices: list[str]) -> None:
        self.devices = devices
        self.device_combobox["values"] = devices
        if devices:
            self.selected_device.set(devices[0])
            self.append_output(f"Dispositivos encontrados: {', '.join(devices)}\n")
        else:
            self.selected_device.set("")
            self.append_output(
                "No se encontraron dispositivos ADB. Verifique depuracion USB y autorizacion.\n"
            )

    def initialize_adb(self) -> None:
        self.append_output("Inicializando ADB y buscando dispositivos...\n")

        def worker() -> None:
            try:
                self._run_subprocess(["adb", "start-server"], timeout=30)
                result = self._run_subprocess(["adb", "devices"], timeout=30)
                devices = extract_device_ids(result.stdout)
                self.master.after(0, self._set_devices, devices)
            except FileNotFoundError:
                self.handle_command_error(
                    "ADB no encontrado. Instale platform-tools y agregue adb al PATH.",
                    "Inicializar ADB",
                )
            except subprocess.CalledProcessError as exc:
                self.handle_command_error(self._format_subprocess_error(exc), "Inicializar ADB")
            except subprocess.TimeoutExpired:
                self.handle_command_error(
                    "Tiempo de espera agotado al inicializar ADB.",
                    "Inicializar ADB",
                )

        self._run_background(worker, status="Inicializando ADB...")

    def on_device_selected(self, _event) -> None:
        selected = self.selected_device.get().strip()
        if selected:
            self.append_output(f"Dispositivo seleccionado: {selected}\n")

    def _run_adb_query(
        self,
        command_name: str,
        shell_args: Sequence[str],
        intro_message: str,
        filter_pattern: str | Pattern[str] | None = None,
        empty_message: str | None = None,
    ) -> None:
        device = self._get_selected_device()
        if not device:
            return

        self.append_output(f"{intro_message}\n")

        def worker() -> None:
            try:
                result = self._run_subprocess(["adb", "-s", device, *shell_args])
                output = result.stdout
                if filter_pattern is not None:
                    output = filter_lines_with_pattern(output, filter_pattern)

                if not output.strip() and empty_message:
                    output = f"{empty_message}\n"

                self.handle_command_output(output, command_name)
            except FileNotFoundError:
                self.handle_command_error(
                    "ADB no encontrado. Instale platform-tools y agregue adb al PATH.",
                    command_name,
                )
            except subprocess.TimeoutExpired:
                self.handle_command_error(
                    "Tiempo de espera agotado para este comando.",
                    command_name,
                )
            except subprocess.CalledProcessError as exc:
                self.handle_command_error(self._format_subprocess_error(exc), command_name)

        self._run_background(worker, status=f"Ejecutando {command_name}...")

    def get_current_focus(self) -> None:
        self._run_adb_query(
            command_name="Obtener Foco Actual",
            shell_args=["shell", "dumpsys", "window"],
            intro_message="Consultando app en foco...",
            filter_pattern=r"mCurrentFocus",
            empty_message="No se encontro mCurrentFocus en la salida.",
        )

    def investigate_package(self) -> None:
        package_name = self._get_validated_package()
        if not package_name:
            return

        device = self._get_selected_device()
        if not device:
            return

        self.append_output(f"Investigando paquete: {package_name} en {device}\n")

        def worker() -> None:
            try:
                result = self._run_subprocess(
                    ["adb", "-s", device, "shell", "dumpsys", "package", package_name]
                )
                self.handle_command_output(result.stdout, f"Info_Paquete_{package_name}")
            except FileNotFoundError:
                self.handle_command_error(
                    "ADB no encontrado. Instale platform-tools y agregue adb al PATH.",
                    f"Info_Paquete_{package_name}",
                )
            except subprocess.TimeoutExpired:
                self.handle_command_error(
                    "Tiempo de espera agotado al consultar paquete.",
                    f"Info_Paquete_{package_name}",
                )
            except subprocess.CalledProcessError as exc:
                self.handle_command_error(
                    self._format_subprocess_error(exc),
                    f"Info_Paquete_{package_name}",
                )

        self._run_background(worker, status="Consultando paquete...")

    def _set_logcat_button_text(self, text: str) -> None:
        if threading.get_ident() != self.main_thread_id:
            self.master.after(0, self._set_logcat_button_text, text)
            return
        self.logcat_button.config(text=text)

    def _append_logcat_line(self, line: str) -> None:
        with self.logcat_lock:
            if len(self.logcat_buffer) < 10000:
                self.logcat_buffer.append(line)

    def search_ad_logs(self) -> None:
        device = self._get_selected_device()
        if not device:
            return

        with self.logcat_lock:
            running = self.logcat_process is not None and self.logcat_process.poll() is None

        if running:
            self._stop_logcat()
            return

        self.append_output("Iniciando logs en tiempo real (filtro case-insensitive: 'ad')...\n")
        self.logcat_stop_event.clear()

        try:
            process = subprocess.Popen(
                ["adb", "-s", device, "logcat"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError:
            self.append_output("ERROR: ADB no encontrado.\n")
            return
        except Exception as exc:
            self.append_output(f"ERROR al iniciar logcat: {exc}\n")
            return

        with self.logcat_lock:
            self.logcat_process = process
            self.logcat_buffer = []

        self._set_logcat_button_text("Detener Logcat")
        self.set_status("Logcat en ejecucion")

        threading.Thread(target=self._read_logcat_stdout, args=(process,), daemon=True).start()
        threading.Thread(target=self._read_logcat_stderr, args=(process,), daemon=True).start()
        threading.Thread(target=self._await_logcat_completion, args=(process,), daemon=True).start()

    def _read_logcat_stdout(self, process: subprocess.Popen[str]) -> None:
        if process.stdout is None:
            return

        ad_pattern = re.compile(r"ad", re.IGNORECASE)
        for line in process.stdout:
            if self.logcat_stop_event.is_set():
                break
            if ad_pattern.search(line):
                self._append_logcat_line(line)
                self.append_output(line)

    def _read_logcat_stderr(self, process: subprocess.Popen[str]) -> None:
        if process.stderr is None:
            return

        for line in process.stderr:
            if self.logcat_stop_event.is_set():
                break
            if line.strip():
                self.append_output(f"[logcat:stderr] {line}")

    def _await_logcat_completion(self, process: subprocess.Popen[str]) -> None:
        try:
            return_code = process.wait(timeout=None)
        except Exception:
            return_code = -1

        with self.logcat_lock:
            current_process = self.logcat_process
            captured_logcat = "".join(self.logcat_buffer)
            self.logcat_buffer = []
            if current_process is process:
                self.logcat_process = None

        if captured_logcat.strip():
            self._save_analysis_log("Logcat_Filtrado_Ads", captured_logcat)

        reason = "detenido" if self.logcat_stop_event.is_set() else "finalizado"
        self.append_output(f"Logcat {reason} (codigo {return_code}).\n")
        self._set_logcat_button_text("Ver logs en tiempo real")
        self.logcat_stop_event.clear()
        self.set_status("Listo")

    def _stop_logcat(self) -> None:
        with self.logcat_lock:
            process = self.logcat_process

        if process is None or process.poll() is not None:
            self._set_logcat_button_text("Ver logs en tiempo real")
            return

        self.append_output("Deteniendo logcat...\n")
        self.logcat_stop_event.set()

        try:
            process.terminate()
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
        except Exception as exc:
            self.append_output(f"Advertencia al detener logcat: {exc}\n")

    def search_ad_processes(self) -> None:
        self._run_adb_query(
            command_name="Procesos_Con_Ad",
            shell_args=["shell", "ps"],
            intro_message="Buscando procesos sospechosos por keyword 'ad'...",
            filter_pattern=r"ad",
            empty_message="No se encontraron procesos que coincidan con 'ad'.",
        )

    def search_packages_by_keyword(self) -> None:
        keyword = self.package_entry.get().strip()
        if not keyword:
            self.append_output("ERROR: Ingrese un keyword para buscar paquetes.\n")
            return
        if not is_safe_keyword(keyword):
            self.append_output(
                "ERROR: Keyword invalido. Use solo letras, numeros, punto, guion y guion bajo (2-80 chars).\n"
            )
            return

        device = self._get_selected_device()
        if not device:
            return

        self.append_output(f"Buscando paquetes por keyword '{keyword}' en {device}\n")

        def worker() -> None:
            try:
                result = self._run_subprocess(
                    ["adb", "-s", device, "shell", "pm", "list", "packages"]
                )
                filtered_lines = [
                    line
                    for line in result.stdout.splitlines()
                    if keyword.casefold() in line.casefold()
                ]
                if filtered_lines:
                    output = "\n".join(filtered_lines) + "\n"
                else:
                    output = f"No se encontraron paquetes que contengan '{keyword}'.\n"
                self.handle_command_output(output, f"Busqueda_Paquetes_{keyword}")
            except FileNotFoundError:
                self.handle_command_error(
                    "ADB no encontrado. Instale platform-tools y agregue adb al PATH.",
                    f"Busqueda_Paquetes_{keyword}",
                )
            except subprocess.TimeoutExpired:
                self.handle_command_error(
                    "Tiempo de espera agotado al listar paquetes.",
                    f"Busqueda_Paquetes_{keyword}",
                )
            except subprocess.CalledProcessError as exc:
                self.handle_command_error(
                    self._format_subprocess_error(exc),
                    f"Busqueda_Paquetes_{keyword}",
                )

        self._run_background(worker, status="Buscando paquetes...")

    def list_installed_packages_history(self) -> None:
        self._run_adb_query(
            command_name="Listar_Paquetes_Terceros",
            shell_args=["shell", "pm", "list", "packages", "-3"],
            intro_message="Listando paquetes de terceros...",
        )

    def list_apps_with_suspicious_permissions(self) -> None:
        package_name = self._get_validated_package()
        if not package_name:
            return

        device = self._get_selected_device()
        if not device:
            return

        self.append_output(f"Buscando permisos para el paquete: {package_name}\n")

        def worker() -> None:
            try:
                result = self._run_subprocess(
                    ["adb", "-s", device, "shell", "dumpsys", "package", package_name]
                )
                permission_lines = filter_lines_with_pattern(result.stdout, r"permission")

                flagged: list[str] = []
                for line in permission_lines.splitlines():
                    for suspicious_permission in self.suspicious_permissions:
                        if suspicious_permission in line:
                            flagged.append(line)
                            break

                output_parts = ["[PERMISOS ENCONTRADOS]\n", permission_lines or "Sin lineas de permisos.\n"]
                if flagged:
                    output_parts.append("\n[PERMISOS SOSPECHOSOS]\n")
                    output_parts.append("\n".join(flagged) + "\n")
                else:
                    output_parts.append("\nNo se detectaron permisos de alto riesgo definidos en reglas.\n")

                self.handle_command_output(
                    "".join(output_parts),
                    f"Permisos_{package_name}",
                )
            except FileNotFoundError:
                self.handle_command_error(
                    "ADB no encontrado. Instale platform-tools y agregue adb al PATH.",
                    f"Permisos_{package_name}",
                )
            except subprocess.TimeoutExpired:
                self.handle_command_error(
                    "Tiempo de espera agotado al revisar permisos.",
                    f"Permisos_{package_name}",
                )
            except subprocess.CalledProcessError as exc:
                self.handle_command_error(
                    self._format_subprocess_error(exc),
                    f"Permisos_{package_name}",
                )

        self._run_background(worker, status="Analizando permisos...")

    def monitor_current_focus(self) -> None:
        self._run_adb_query(
            command_name="Monitoreo_Foco",
            shell_args=["shell", "dumpsys", "window"],
            intro_message="Monitoreando foco actual...",
            filter_pattern=r"mCurrentFocus",
            empty_message="No se encontro mCurrentFocus en la salida.",
        )

    def extract_suspicious_apps(self) -> None:
        device = self._get_selected_device()
        if not device:
            return

        self.append_output("Analizando posibles APKs sospechosos...\n")

        def worker() -> None:
            try:
                result = self._run_subprocess(
                    ["adb", "-s", device, "shell", "pm", "list", "packages", "-f"]
                )

                suspicious_matches: list[str] = []
                ambiguous_matches: list[str] = []
                neutral_matches: list[str] = []

                for line in result.stdout.splitlines():
                    package_name = line.split("=", 1)[-1].strip() if "=" in line else line.strip()
                    lower_package = package_name.lower()

                    if lower_package in self.suspicious_packages_set:
                        suspicious_matches.append(line)
                        continue

                    is_ambiguous = any(regex.search(package_name) for regex in self.ambiguous_regexes)
                    if is_ambiguous:
                        ambiguous_matches.append(line)
                    else:
                        neutral_matches.append(line)

                output_parts = [
                    "[COINCIDENCIAS SOSPECHOSAS]\n",
                    ("\n".join(suspicious_matches) + "\n")
                    if suspicious_matches
                    else "Sin coincidencias exactas con lista sospechosa.\n",
                    "\n[COINCIDENCIAS AMBIGUAS]\n",
                    ("\n".join(ambiguous_matches[:200]) + "\n")
                    if ambiguous_matches
                    else "Sin coincidencias ambiguas.\n",
                    "\n[RESUMEN]\n",
                    f"Sospechosas exactas: {len(suspicious_matches)}\n",
                    f"Ambiguas: {len(ambiguous_matches)}\n",
                    f"Resto: {len(neutral_matches)}\n",
                ]

                self.handle_command_output("".join(output_parts), "Extraccion_APKs_Sospechosas")
            except FileNotFoundError:
                self.handle_command_error(
                    "ADB no encontrado. Instale platform-tools y agregue adb al PATH.",
                    "Extraccion_APKs_Sospechosas",
                )
            except subprocess.TimeoutExpired:
                self.handle_command_error(
                    "Tiempo de espera agotado al extraer paquetes.",
                    "Extraccion_APKs_Sospechosas",
                )
            except subprocess.CalledProcessError as exc:
                self.handle_command_error(
                    self._format_subprocess_error(exc),
                    "Extraccion_APKs_Sospechosas",
                )

        self._run_background(worker, status="Extrayendo apps sospechosas...")

    def list_all_apps(self) -> None:
        self._run_adb_query(
            command_name="Listar_Todas_Las_Apps",
            shell_args=["shell", "pm", "list", "packages"],
            intro_message="Listando todas las aplicaciones...",
        )

    def list_system_apps(self) -> None:
        self._run_adb_query(
            command_name="Listar_Apps_Sistema",
            shell_args=["shell", "pm", "list", "packages", "-s"],
            intro_message="Listando aplicaciones del sistema...",
        )

    def list_installer_apps(self) -> None:
        self._run_adb_query(
            command_name="Apps_Con_Instalador",
            shell_args=["shell", "pm", "list", "packages", "-i"],
            intro_message="Listando aplicaciones con instalador...",
        )

    def uninstall_package(self) -> None:
        package_name = self._get_validated_package()
        if not package_name:
            return

        device = self._get_selected_device()
        if not device:
            return

        confirmed = messagebox.askyesno(
            "Confirmar Desinstalacion",
            f"Desea desinstalar {package_name} del dispositivo {device}?",
        )
        if not confirmed:
            return

        self.append_output(f"Desinstalando paquete: {package_name} de {device}\n")

        def worker() -> None:
            try:
                result = self._run_subprocess(["adb", "-s", device, "uninstall", package_name])
                self.handle_command_output(result.stdout, f"Desinstalar_{package_name}")
                if "Success" in result.stdout:
                    self.append_output(f"Paquete {package_name} desinstalado exitosamente.\n")
                else:
                    self.append_output(
                        f"No se pudo desinstalar {package_name}. Verifique si es app de sistema.\n"
                    )
            except FileNotFoundError:
                self.handle_command_error(
                    "ADB no encontrado. Instale platform-tools y agregue adb al PATH.",
                    f"Desinstalar_{package_name}",
                )
            except subprocess.TimeoutExpired:
                self.handle_command_error(
                    "Tiempo de espera agotado al desinstalar paquete.",
                    f"Desinstalar_{package_name}",
                )
            except subprocess.CalledProcessError as exc:
                self.handle_command_error(
                    self._format_subprocess_error(exc),
                    f"Desinstalar_{package_name}",
                )

        self._run_background(worker, status="Desinstalando paquete...")

    def show_analysis_folder(self) -> None:
        if not self.analysis_dir.exists():
            self.append_output("La carpeta de analisis no existe.\n")
            return

        try:
            if sys.platform.startswith("win"):
                os.startfile(str(self.analysis_dir))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(self.analysis_dir)])
            else:
                subprocess.Popen(["xdg-open", str(self.analysis_dir)])
        except Exception as exc:
            self.append_output(f"Error al abrir la carpeta de analisis: {exc}\n")

    def run_intelligent_scan(self) -> None:
        if self.intel_pipeline is None:
            self.append_output("ERROR: Intelligence layer no disponible.\n")
            return

        package_name = self._get_validated_package()
        if not package_name:
            return

        device = self._get_selected_device()
        if not device:
            return

        self.append_output(
            f"Iniciando analisis inteligente para {package_name} en dispositivo {device}...\n"
        )

        def worker() -> None:
            try:
                synced = self.intel_pipeline.sync_iocs_from_file(self.intel_ioc_file)
                result = self.intel_pipeline.scan_package(device_id=device, package_name=package_name)
                self.last_intelligent_scan_id = result.scan_id

                summary_lines = [
                    "[INTELLIGENCE RESULT]",
                    f"Scan ID: {result.scan_id}",
                    f"Package: {result.package_name}",
                    f"Risk Score: {result.risk_score}",
                    f"Risk Level: {result.risk_level}",
                    f"Anomaly Score: {result.anomaly_score}",
                    f"Anomaly Zmax: {result.anomaly_zmax}",
                    f"ML Risk Score: {result.ml_risk_score}",
                    f"ML Model Version: {result.ml_model_version}",
                    f"Component Fingerprint: {result.component_fingerprint}",
                    f"APK Hash Present: {result.feature_vector.apk_hash_present}",
                    f"APK Size KB: {result.feature_vector.apk_size_kb}",
                    f"ATT&CK techniques: {len(result.attack_techniques)}",
                    f"IOC matches: {len(result.ioc_matches)}",
                    f"IOC synced: {synced}",
                    "Reasons:",
                ]
                for reason in result.reasons:
                    summary_lines.append(f"- {reason}")
                if result.attack_techniques:
                    summary_lines.append("ATT&CK Mapping (inferencia):")
                    for technique in result.attack_techniques:
                        summary_lines.append(
                            f"- {technique.get('id')} | {technique.get('name')} | {technique.get('tactic')} | conf={technique.get('confidence')}"
                        )

                summary = "\n".join(summary_lines) + "\n"
                self.handle_command_output(summary, f"Intelligent_Scan_{package_name}")

                payload = result.to_dict()
                payload["ioc_synced"] = synced
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                json_filename = f"intelligent_scan_{package_name.replace('.', '_')}_{timestamp}.json"
                json_path = self.analysis_dir / json_filename
                json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
                self.append_output(f"Reporte inteligente JSON guardado en: {json_filename}\n")
            except subprocess.CalledProcessError as exc:
                self.handle_command_error(self._format_subprocess_error(exc), "Intelligent_Scan")
            except subprocess.TimeoutExpired:
                self.handle_command_error(
                    "Tiempo de espera agotado durante analisis inteligente.",
                    "Intelligent_Scan",
                )
            except FileNotFoundError:
                self.handle_command_error(
                    "ADB no encontrado. Instale platform-tools y agregue adb al PATH.",
                    "Intelligent_Scan",
                )
            except Exception as exc:
                self.handle_command_error(str(exc), "Intelligent_Scan")

        self._run_background(worker, status="Ejecutando analisis inteligente...")

    def rebuild_intel_baseline(self) -> None:
        if self.intel_pipeline is None:
            self.append_output("ERROR: Intelligence layer no disponible.\n")
            return

        self.append_output("Reentrenando baseline estadistico con historial local...\n")

        def worker() -> None:
            try:
                rebuilt = self.intel_pipeline.rebuild_baseline(max_rows=1000)
                if rebuilt == 0:
                    self.append_output(
                        "No hay suficientes muestras para baseline. Ejecuta primero escaneos inteligentes.\n"
                    )
                else:
                    self.append_output(
                        f"Baseline actualizado con {rebuilt} muestras historicas.\n"
                    )
            except Exception as exc:
                self.handle_command_error(str(exc), "Rebuild_Baseline")

        self._run_background(worker, status="Reentrenando baseline...")

    def _label_current_package(self, label: int) -> None:
        if self.intel_pipeline is None:
            self.append_output("ERROR: Intelligence layer no disponible.\n")
            return

        package_name = self._get_validated_package()
        if not package_name:
            return

        def worker() -> None:
            try:
                scan_id = self.intel_pipeline.label_latest_scan_for_package(
                    package_name=package_name,
                    label=label,
                    source="gui",
                )
                if scan_id is None:
                    self.append_output(
                        f"No hay escaneos inteligentes previos para {package_name}. Ejecuta primero Analisis Inteligente.\n"
                    )
                    return
                label_text = "maliciosa" if label == 1 else "benigna"
                self.append_output(
                    f"Etiqueta aplicada: scan_id={scan_id}, package={package_name}, label={label_text}.\n"
                )
            except Exception as exc:
                self.handle_command_error(str(exc), "Label_Scan")

        self._run_background(worker, status="Aplicando etiqueta supervisada...")

    def label_current_package_malicious(self) -> None:
        self._label_current_package(label=1)

    def label_current_package_benign(self) -> None:
        self._label_current_package(label=0)

    def train_supervised_model(self) -> None:
        if self.intel_pipeline is None:
            self.append_output("ERROR: Intelligence layer no disponible.\n")
            return

        self.append_output("Entrenando modelo supervisado con historial etiquetado...\n")

        def worker() -> None:
            try:
                summary = self.intel_pipeline.train_supervised_model(min_samples=8, max_rows=5000)
                metrics = summary.get("metrics", {})
                self.append_output(
                    "\n".join(
                        [
                            "[ML TRAIN RESULT]",
                            f"Model: {summary.get('model_name')}",
                            f"Version: {summary.get('model_version')}",
                            f"Samples: {summary.get('trained_samples')}",
                            f"Accuracy: {metrics.get('accuracy')}",
                            f"Precision: {metrics.get('precision')}",
                            f"Recall: {metrics.get('recall')}",
                            f"F1: {metrics.get('f1')}",
                        ]
                    )
                    + "\n"
                )
                self.intel_info_text.set(
                    f"Intelligence layer activa. Modelo ML entrenado: {summary.get('model_version')}"
                )
            except Exception as exc:
                self.handle_command_error(str(exc), "Train_ML_Model")

        self._run_background(worker, status="Entrenando modelo ML...")

    def export_stix_lite_bundle(self) -> None:
        if self.intel_pipeline is None:
            self.append_output("ERROR: Intelligence layer no disponible.\n")
            return

        destination_file = filedialog.asksaveasfilename(
            title="Guardar Bundle STIX-lite",
            defaultextension=".json",
            initialfile="stix_lite_bundle.json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not destination_file:
            self.append_output("Export STIX-lite cancelado.\n")
            return

        out_path = Path(destination_file)

        def worker() -> None:
            try:
                bundle = self.intel_pipeline.export_stix_lite(
                    output_path=out_path,
                    limit=200,
                )
                self.append_output(
                    f"STIX-lite exportado en {out_path} (objetos={len(bundle.get('objects', []))}).\n"
                )
            except Exception as exc:
                self.handle_command_error(str(exc), "Export_STIX_Lite")

        self._run_background(worker, status="Exportando STIX-lite...")

    def export_campaign_dashboard(self) -> None:
        if self.intel_pipeline is None:
            self.append_output("ERROR: Intelligence layer no disponible.\n")
            return

        destination_file = filedialog.asksaveasfilename(
            title="Guardar Dashboard de Campanas",
            defaultextension=".md",
            initialfile="campaign_dashboard.md",
            filetypes=[("Markdown files", "*.md"), ("All files", "*.*")],
        )
        if not destination_file:
            self.append_output("Export dashboard de campanas cancelado.\n")
            return

        out_path = Path(destination_file)

        def worker() -> None:
            try:
                summary = self.intel_pipeline.export_campaign_dashboard(
                    output_path=out_path,
                    limit=3000,
                    min_cluster_size=2,
                    top_n=30,
                )
                self.append_output(
                    f"Dashboard de campanas exportado en {summary.get('markdown_output')} (clusters={summary.get('clusters_count')}).\n"
                )
                self.append_output(
                    f"Resumen JSON de campanas: {summary.get('json_output')}\n"
                )
            except Exception as exc:
                self.handle_command_error(str(exc), "Export_Campaign_Dashboard")

        self._run_background(worker, status="Generando dashboard de campanas...")

    def download_analysis(self) -> None:
        if not self.analysis_files and not self.gemini_analysis_content:
            self.append_output("No hay archivos de analisis para descargar.\n")
            return

        destination_dir = filedialog.askdirectory(
            title="Seleccionar Carpeta de Destino para el Analisis"
        )
        if not destination_dir:
            self.append_output("Descarga cancelada.\n")
            return

        destination_path = Path(destination_dir)

        try:
            copied_count = 0
            for filepath in self.analysis_files:
                if filepath.exists():
                    shutil.copy(filepath, destination_path)
                    copied_count += 1

            if copied_count:
                self.append_output(
                    f"Se copiaron {copied_count} archivos de analisis a: {destination_path}\n"
                )

            if self.gemini_analysis_content:
                gemini_filename = (
                    f"analisis_gemini_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                )
                gemini_filepath = destination_path / gemini_filename
                gemini_filepath.write_text(self.gemini_analysis_content, encoding="utf-8")
                self.append_output(f"Analisis de Gemini guardado en: {gemini_filepath}\n")

        except Exception as exc:
            self.append_output(f"Error al descargar archivos de analisis: {exc}\n")

    def analyze_with_gemini(self) -> None:
        text_files = sorted(self.analysis_dir.glob("*.txt"))
        if not text_files:
            self.append_output(
                "La carpeta de analisis no contiene archivos .txt. No hay nada que analizar.\n"
            )
            return

        self.append_output("Analizando con Gemini...\n")

        def worker() -> None:
            full_analysis_content = ""
            try:
                for filepath in text_files:
                    file_content = filepath.read_text(encoding="utf-8", errors="replace")
                    full_analysis_content += (
                        f"--- Contenido de {filepath.name} ---\n\n{file_content}\n\n"
                    )
            except Exception as exc:
                self.handle_command_error(
                    f"Error al leer archivos de analisis: {exc}",
                    "Analisis_Gemini",
                )
                return

            if not full_analysis_content.strip():
                self.handle_command_error(
                    "El contenido consolidado de analisis esta vacio.",
                    "Analisis_Gemini",
                )
                return

            temp_filepath: str | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    delete=False,
                    suffix=".txt",
                    encoding="utf-8",
                ) as temp_file:
                    temp_file.write(full_analysis_content)
                    temp_filepath = temp_file.name

                prompt = (
                    "Actua como analista de ciberseguridad senior especializado en Android. "
                    "Recibiras logs de ADB concatenados y debes entregar informe concluyente. "
                    "Formato: 1) Diagnostico definitivo, 2) Evidencia clave, 3) Plan de remediacion "
                    "con comandos ADB exactos. Sin explicaciones basicas y sin preguntas finales. "
                    "Respuesta en espanol tecnico y directo."
                )

                result = self._run_subprocess(
                    ["gemini", "-p", prompt, temp_filepath],
                    timeout=240,
                )

                self.gemini_analysis_content = result.stdout.strip()
                self.append_output("--- Analisis de Gemini ---\n")
                self.append_output(self.gemini_analysis_content + "\n")
                self.append_output("--- Fin del Analisis de Gemini ---\n")
                self._save_analysis_log("Analisis_Gemini", self.gemini_analysis_content)
            except FileNotFoundError:
                self.handle_command_error(
                    "Gemini CLI no encontrado. Instale Gemini CLI y agreguelo al PATH.",
                    "Analisis_Gemini",
                )
            except subprocess.TimeoutExpired:
                self.handle_command_error(
                    "Tiempo de espera agotado durante el analisis con Gemini.",
                    "Analisis_Gemini",
                )
            except subprocess.CalledProcessError as exc:
                self.handle_command_error(
                    self._format_subprocess_error(exc),
                    "Analisis_Gemini",
                )
            finally:
                if temp_filepath and Path(temp_filepath).exists():
                    try:
                        Path(temp_filepath).unlink()
                    except OSError:
                        pass

        self._run_background(worker, status="Analizando con Gemini...")

    def check_adb_path(self) -> None:
        try:
            result = subprocess.run(
                ["adb", "version"],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
            )
            first_line = result.stdout.splitlines()[0] if result.stdout else "ADB detectado"
            self.append_output(f"ADB detectado: {first_line}\n")
        except FileNotFoundError:
            self.append_output(
                "ADVERTENCIA: ADB no encontrado en PATH. Algunas funciones no estaran disponibles.\n"
            )
        except Exception as exc:
            self.append_output(f"Error al verificar ADB: {exc}\n")

    def check_gemini_installed(self) -> None:
        try:
            result = subprocess.run(
                ["gemini", "--version"],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
            )
            if result.returncode == 0:
                version = result.stdout.strip() or "Gemini CLI detectado"
                self.gemini_info_text.set(f"Gemini CLI detectado: {version}")
                self.analyze_gemini_button.config(state="normal")
            else:
                detail = result.stderr.strip() or "No disponible"
                self.gemini_info_text.set(f"Gemini CLI no disponible: {detail}")
                self.analyze_gemini_button.config(state="disabled")
        except FileNotFoundError:
            self.gemini_info_text.set("Gemini CLI no encontrado en PATH.")
            self.analyze_gemini_button.config(state="disabled")
        except Exception as exc:
            self.gemini_info_text.set(f"Error validando Gemini CLI: {exc}")
            self.analyze_gemini_button.config(state="disabled")


def create_root() -> tk.Tk:
    if tb is None:
        return tk.Tk()

    theme = os.getenv("ADB_TOOL_THEME", "flatly")
    try:
        return tb.Window(themename=theme)
    except Exception:
        return tb.Window(themename="flatly")


if __name__ == "__main__":
    root = create_root()
    app = ADBAutomationTool(root)
    root.mainloop()
