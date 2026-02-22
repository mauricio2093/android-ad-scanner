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
from typing import Callable, Pattern, Sequence

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

        self.master.title("Android Ad Scanner - Security Dashboard")
        self.master.geometry("1260x860")
        self.master.minsize(1080, 700)
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

        self.brand_assets_dir = self.base_path / "assets" / "img"
        self.logo_variant = os.getenv("ADB_TOOL_LOGO_VARIANT", "hero").strip().lower()
        self.window_icon_image: tk.PhotoImage | None = None
        self.header_logo_image: tk.PhotoImage | None = None
        self.header_logo_display: tk.PhotoImage | None = None

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
        self.workspace_pages: dict[str, tk.Frame] = {}
        self.workspace_nav_buttons: dict[str, tk.Button] = {}
        self.workspace_tab_buttons: dict[str, tk.Button] = {}
        self.active_workspace = "operations"
        self.intel_stats_signature = ""

        self._load_brand_assets()
        self._configure_theme()
        self._build_ui()
        self._load_detection_rules()
        self._init_intelligence_layer()
        self.check_adb_path()
        self.check_gemini_installed()

    def _fit_photo_image(
        self,
        image: tk.PhotoImage,
        *,
        max_width: int,
        max_height: int,
    ) -> tk.PhotoImage:
        width = image.width()
        height = image.height()
        if width <= 0 or height <= 0:
            return image

        # Tkinter escalado fino usando combinacion zoom/subsample enteros.
        best_zoom = 1
        best_subsample = 1
        best_area = 0
        for zoom in range(1, 9):
            for subsample in range(1, 9):
                scaled_width = (width * zoom) // subsample
                scaled_height = (height * zoom) // subsample
                if scaled_width <= 0 or scaled_height <= 0:
                    continue
                if scaled_width > max_width or scaled_height > max_height:
                    continue
                area = scaled_width * scaled_height
                if area > best_area:
                    best_area = area
                    best_zoom = zoom
                    best_subsample = subsample

        if best_area == 0:
            # Fallback seguro: reducir proporcional por subsample.
            width_ratio = (width + max_width - 1) // max_width
            height_ratio = (height + max_height - 1) // max_height
            factor = max(width_ratio, height_ratio, 1)
            return image.subsample(factor, factor)

        if best_zoom == 1 and best_subsample == 1:
            return image

        scaled_image = image
        if best_zoom > 1:
            scaled_image = scaled_image.zoom(best_zoom, best_zoom)
        if best_subsample > 1:
            scaled_image = scaled_image.subsample(best_subsample, best_subsample)
        return scaled_image

    def _load_brand_assets(self) -> None:
        icon_path = self.brand_assets_dir / "favicon.png"
        if icon_path.exists():
            try:
                self.window_icon_image = tk.PhotoImage(file=str(icon_path))
                self.master.iconphoto(True, self.window_icon_image)
            except tk.TclError:
                self.window_icon_image = None

        logo_path = self.brand_assets_dir / "logo-android-scan-ad.png"
        if logo_path.exists():
            try:
                self.header_logo_image = tk.PhotoImage(file=str(logo_path))
                if self.logo_variant == "compact":
                    logo_max_width, logo_max_height = 130, 82
                else:
                    # `hero` por defecto: mas presencia visual sin saturar el header.
                    logo_max_width, logo_max_height = 180, 108
                self.header_logo_display = self._fit_photo_image(
                    self.header_logo_image,
                    max_width=logo_max_width,
                    max_height=logo_max_height,
                )
            except tk.TclError:
                self.header_logo_image = None
                self.header_logo_display = None

    def _configure_theme(self) -> None:
        self.ui_tokens = {
            "canvas": "#050a1f",
            "sidebar": "#0a1230",
            "surface_0": "#101a3c",
            "surface_1": "#141f47",
            "surface_2": "#1a2858",
            "border": "#2d3e78",
            "text": "#e5ecff",
            "muted": "#95a4cb",
            "accent": "#3f7cff",
            "accent_hover": "#5f92ff",
            "accent_soft": "#243e86",
            "console_bg": "#08102a",
            "console_fg": "#d4e2ff",
            "danger": "#ff6a8a",
            "warn": "#f7b955",
            "success": "#39d8a3",
        }
        self.ui_fonts = {
            "display": ("Segoe UI Semibold", 28),
            "title": ("Segoe UI Semibold", 18),
            "subtitle": ("Segoe UI", 11),
            "metric_value": ("Segoe UI Semibold", 16),
            "body": ("Segoe UI", 10),
            "mono": ("Consolas", 10),
        }

        self.style = ttk.Style(self.master)
        available = self.style.theme_names()
        theme = os.getenv("ADB_TOOL_THEME", "clam")
        if theme not in available:
            theme = "clam" if "clam" in available else (available[0] if available else "")
        if theme:
            try:
                self.style.theme_use(theme)
            except tk.TclError:
                pass

        self.master.configure(bg=self.ui_tokens["canvas"])
        self.style.configure(".", font=self.ui_fonts["body"])
        self.style.configure(
            "TCombobox",
            fieldbackground=self.ui_tokens["surface_2"],
            background=self.ui_tokens["surface_2"],
            foreground=self.ui_tokens["text"],
            bordercolor=self.ui_tokens["border"],
            arrowsize=14,
        )
        self.style.map(
            "TCombobox",
            fieldbackground=[("readonly", self.ui_tokens["surface_2"])],
            foreground=[("readonly", self.ui_tokens["text"])],
            selectbackground=[("readonly", self.ui_tokens["surface_2"])],
            selectforeground=[("readonly", self.ui_tokens["text"])],
        )
        self.style.configure(
            "LowRisk.Horizontal.TProgressbar",
            troughcolor=self.ui_tokens["surface_2"],
            background=self.ui_tokens["success"],
            bordercolor=self.ui_tokens["surface_2"],
            lightcolor=self.ui_tokens["success"],
            darkcolor=self.ui_tokens["success"],
        )
        self.style.configure(
            "MediumRisk.Horizontal.TProgressbar",
            troughcolor=self.ui_tokens["surface_2"],
            background=self.ui_tokens["warn"],
            bordercolor=self.ui_tokens["surface_2"],
            lightcolor=self.ui_tokens["warn"],
            darkcolor=self.ui_tokens["warn"],
        )
        self.style.configure(
            "HighRisk.Horizontal.TProgressbar",
            troughcolor=self.ui_tokens["surface_2"],
            background=self.ui_tokens["danger"],
            bordercolor=self.ui_tokens["surface_2"],
            lightcolor=self.ui_tokens["danger"],
            darkcolor=self.ui_tokens["danger"],
        )

    def _create_modern_button(
        self,
        parent: tk.Misc,
        *,
        text: str,
        command,
        variant: str = "action",
        width: int | None = None,
    ) -> tk.Button:
        palettes = {
            "primary": {
                "bg": self.ui_tokens["accent"],
                "fg": "#f6f8ff",
                "hover": self.ui_tokens["accent_hover"],
                "disabled_fg": "#b6c7f5",
            },
            "ghost": {
                "bg": self.ui_tokens["surface_1"],
                "fg": self.ui_tokens["text"],
                "hover": self.ui_tokens["surface_2"],
                "disabled_fg": "#7f8eb8",
            },
            "nav": {
                "bg": self.ui_tokens["sidebar"],
                "fg": self.ui_tokens["muted"],
                "hover": self.ui_tokens["surface_1"],
                "disabled_fg": "#5f6e95",
            },
            "tab": {
                "bg": self.ui_tokens["surface_0"],
                "fg": self.ui_tokens["muted"],
                "hover": self.ui_tokens["surface_1"],
                "disabled_fg": "#6c7a9f",
            },
            "action": {
                "bg": self.ui_tokens["surface_1"],
                "fg": self.ui_tokens["text"],
                "hover": self.ui_tokens["surface_2"],
                "disabled_fg": "#8593b7",
            },
        }
        palette = palettes.get(variant, palettes["action"])
        button = tk.Button(
            parent,
            text=text,
            command=command,
            width=width,
            bg=palette["bg"],
            fg=palette["fg"],
            activebackground=palette["hover"],
            activeforeground=palette["fg"],
            disabledforeground=palette["disabled_fg"],
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=self.ui_tokens["border"],
            highlightcolor=self.ui_tokens["accent"],
            padx=12,
            pady=8,
            font=self.ui_fonts["body"],
            cursor="hand2",
        )

        if variant not in {"nav", "tab"}:
            def _on_enter(_event) -> None:
                if button.cget("state") == "normal":
                    button.configure(bg=palette["hover"])

            def _on_leave(_event) -> None:
                if button.cget("state") == "normal":
                    button.configure(bg=palette["bg"])

            button.bind("<Enter>", _on_enter)
            button.bind("<Leave>", _on_leave)
        return button

    def _create_button_grid(
        self,
        parent: tk.Frame,
        actions: Sequence[tuple[str, Callable[[], None]]],
        *,
        columns: int,
        variant: str = "action",
    ) -> list[tk.Button]:
        buttons: list[tk.Button] = []
        for col_index in range(columns):
            parent.grid_columnconfigure(col_index, weight=1)

        for index, (label, command) in enumerate(actions):
            row = index // columns
            col_index = index % columns
            button = self._create_modern_button(
                parent,
                text=label,
                command=command,
                variant=variant,
            )
            button.grid(row=row, column=col_index, padx=6, pady=6, sticky="ew")
            buttons.append(button)
        return buttons

    def _switch_workspace(self, key: str) -> None:
        target_key = key if key in self.workspace_pages else "operations"
        page = self.workspace_pages.get(target_key)
        if page is not None:
            page.tkraise()
            self.active_workspace = target_key

        for page_key, button in self.workspace_nav_buttons.items():
            if page_key == target_key:
                button.configure(bg=self.ui_tokens["surface_2"], fg=self.ui_tokens["text"])
            else:
                button.configure(bg=self.ui_tokens["sidebar"], fg=self.ui_tokens["muted"])

        for page_key, button in self.workspace_tab_buttons.items():
            if page_key == target_key:
                button.configure(bg=self.ui_tokens["surface_2"], fg=self.ui_tokens["text"])
            else:
                button.configure(bg=self.ui_tokens["surface_0"], fg=self.ui_tokens["muted"])

    def _build_ui(self) -> None:
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_columnconfigure(0, weight=1)
        self.main_frame = tk.Frame(self.master, bg=self.ui_tokens["canvas"], padx=14, pady=12)
        self.main_frame.grid(row=0, column=0, sticky="nsew")
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        header_frame = tk.Frame(
            self.main_frame,
            bg=self.ui_tokens["surface_0"],
            highlightthickness=1,
            highlightbackground=self.ui_tokens["border"],
            padx=16,
            pady=12,
        )
        header_frame.grid(row=0, column=0, sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        title_block = tk.Frame(header_frame, bg=self.ui_tokens["surface_0"])
        title_block.grid(row=0, column=0, sticky="w")
        title_block.grid_columnconfigure(1, weight=1)
        if self.header_logo_display is not None:
            tk.Label(
                title_block,
                image=self.header_logo_display,
                bg=self.ui_tokens["surface_0"],
            ).grid(row=0, column=0, rowspan=2, padx=(0, 12), sticky="w")
        tk.Label(
            title_block,
            text="Android Scan Ad",
            bg=self.ui_tokens["surface_0"],
            fg=self.ui_tokens["text"],
            font=self.ui_fonts["title"],
        ).grid(row=0, column=1, sticky="w")
        tk.Label(
            title_block,
            text="Security Operations Command Center",
            bg=self.ui_tokens["surface_0"],
            fg=self.ui_tokens["muted"],
            font=self.ui_fonts["subtitle"],
        ).grid(row=1, column=1, sticky="w")

        header_actions = tk.Frame(header_frame, bg=self.ui_tokens["surface_0"])
        header_actions.grid(row=0, column=1, sticky="e")
        self.initialize_button = self._create_modern_button(
            header_actions,
            text="Inicializar ADB",
            command=self.initialize_adb,
            variant="primary",
        )
        self.initialize_button.grid(row=0, column=0, padx=(0, 8))
        self.clear_console_header_button = self._create_modern_button(
            header_actions,
            text="Limpiar Consola",
            command=self.clear_output,
            variant="ghost",
        )
        self.clear_console_header_button.grid(row=0, column=1)

        shell_frame = tk.Frame(self.main_frame, bg=self.ui_tokens["canvas"])
        shell_frame.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        shell_frame.grid_rowconfigure(0, weight=1)
        shell_frame.grid_columnconfigure(1, weight=1)

        sidebar = tk.Frame(
            shell_frame,
            bg=self.ui_tokens["sidebar"],
            highlightthickness=1,
            highlightbackground=self.ui_tokens["border"],
            padx=10,
            pady=12,
            width=220,
        )
        sidebar.grid(row=0, column=0, sticky="nsw")
        sidebar.grid_propagate(False)
        sidebar.grid_rowconfigure(6, weight=1)

        nav_items = [
            ("operations", "Operaciones"),
            ("intelligence", "Intelligence"),
            ("reports", "Reports"),
            ("console", "Consola"),
        ]
        for index, (key, label) in enumerate(nav_items):
            button = self._create_modern_button(
                sidebar,
                text=f"  {label}",
                command=lambda selected=key: self._switch_workspace(selected),
                variant="nav",
            )
            button.grid(row=index + 1, column=0, sticky="ew", pady=4)
            self.workspace_nav_buttons[key] = button

        sidebar_footer = tk.Frame(sidebar, bg=self.ui_tokens["sidebar"])
        sidebar_footer.grid(row=7, column=0, sticky="ew", pady=(10, 0))
        tk.Label(
            sidebar_footer,
            text="Mauri",
            bg=self.ui_tokens["sidebar"],
            fg=self.ui_tokens["text"],
            font=("Segoe UI Semibold", 12),
        ).pack(anchor="w")
        tk.Label(
            sidebar_footer,
            text="Security Analyst",
            bg=self.ui_tokens["sidebar"],
            fg=self.ui_tokens["muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w")

        workspace_column = tk.Frame(shell_frame, bg=self.ui_tokens["canvas"])
        workspace_column.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        workspace_column.grid_rowconfigure(2, weight=1)
        workspace_column.grid_columnconfigure(0, weight=1)

        metrics_frame = tk.Frame(workspace_column, bg=self.ui_tokens["canvas"])
        metrics_frame.grid(row=0, column=0, sticky="ew")
        for col_index in range(5):
            metrics_frame.grid_columnconfigure(col_index, weight=1)

        self.metric_devices_count = tk.StringVar(value="0")
        self.metric_active_device = tk.StringVar(value="Ninguno")
        self.metric_reports_count = tk.StringVar(value="0")
        self.metric_intel_state = tk.StringVar(value="No inicializada")
        self.metric_gemini_state = tk.StringVar(value="No detectado")

        self._create_metric_card(metrics_frame, 0, "Dispositivos", self.metric_devices_count, "Conectados por ADB")
        self._create_metric_card(metrics_frame, 1, "Activo", self.metric_active_device, "Dispositivo seleccionado")
        self._create_metric_card(metrics_frame, 2, "Reportes", self.metric_reports_count, "Analisis guardados")
        self._create_metric_card(metrics_frame, 3, "Intelligence", self.metric_intel_state, "Pipeline defensivo")
        self._create_metric_card(metrics_frame, 4, "Gemini CLI", self.metric_gemini_state, "Estado de integracion")

        tabs_bar = tk.Frame(
            workspace_column,
            bg=self.ui_tokens["surface_0"],
            highlightthickness=1,
            highlightbackground=self.ui_tokens["border"],
            padx=8,
            pady=8,
        )
        tabs_bar.grid(row=1, column=0, sticky="ew", pady=(10, 8))
        for key, label in nav_items:
            button = self._create_modern_button(
                tabs_bar,
                text=label,
                command=lambda selected=key: self._switch_workspace(selected),
                variant="tab",
            )
            button.pack(side=tk.LEFT, padx=(0, 6))
            self.workspace_tab_buttons[key] = button

        pages_container = tk.Frame(
            workspace_column,
            bg=self.ui_tokens["surface_0"],
            highlightthickness=1,
            highlightbackground=self.ui_tokens["border"],
        )
        pages_container.grid(row=2, column=0, sticky="nsew")
        pages_container.grid_rowconfigure(0, weight=1)
        pages_container.grid_columnconfigure(0, weight=1)
        self.workspace_tabs = pages_container

        operations_page = tk.Frame(pages_container, bg=self.ui_tokens["surface_0"])
        operations_page.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)
        operations_page.grid_columnconfigure(0, weight=1)
        operations_page.grid_rowconfigure(1, weight=1)
        self.workspace_pages["operations"] = operations_page

        intelligence_page = tk.Frame(pages_container, bg=self.ui_tokens["surface_0"])
        intelligence_page.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)
        intelligence_page.grid_columnconfigure(0, weight=3)
        intelligence_page.grid_columnconfigure(1, weight=2)
        intelligence_page.grid_rowconfigure(0, weight=1)
        self.workspace_pages["intelligence"] = intelligence_page

        reports_page = tk.Frame(pages_container, bg=self.ui_tokens["surface_0"])
        reports_page.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)
        reports_page.grid_columnconfigure(0, weight=1)
        reports_page.grid_rowconfigure(1, weight=1)
        self.workspace_pages["reports"] = reports_page

        console_page = tk.Frame(pages_container, bg=self.ui_tokens["surface_0"])
        console_page.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)
        console_page.grid_columnconfigure(0, weight=1)
        console_page.grid_rowconfigure(1, weight=1)
        self.workspace_pages["console"] = console_page

        self.control_frame = tk.LabelFrame(
            operations_page,
            text="Control Operativo",
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["text"],
            bd=0,
            font=("Segoe UI Semibold", 11),
            highlightthickness=1,
            highlightbackground=self.ui_tokens["border"],
            padx=12,
            pady=10,
        )
        self.control_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        for col_index in range(6):
            self.control_frame.grid_columnconfigure(col_index, weight=1)

        self.device_label = tk.Label(
            self.control_frame,
            text="Seleccionar Dispositivo:",
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["text"],
            font=self.ui_fonts["body"],
        )
        self.device_label.grid(row=0, column=0, padx=6, pady=6, sticky="w")

        self.selected_device = tk.StringVar()
        self.device_combobox = ttk.Combobox(
            self.control_frame,
            textvariable=self.selected_device,
            state="readonly",
        )
        self.device_combobox.grid(row=0, column=1, columnspan=2, padx=6, pady=6, sticky="ew")
        self.device_combobox.bind("<<ComboboxSelected>>", self.on_device_selected)

        self.package_label = tk.Label(
            self.control_frame,
            text="Paquete / Keyword:",
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["text"],
            font=self.ui_fonts["body"],
        )
        self.package_label.grid(row=0, column=3, padx=6, pady=6, sticky="w")

        self.package_entry = tk.Entry(
            self.control_frame,
            bg=self.ui_tokens["surface_2"],
            fg=self.ui_tokens["text"],
            insertbackground=self.ui_tokens["text"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=self.ui_tokens["border"],
            highlightcolor=self.ui_tokens["accent"],
            font=self.ui_fonts["body"],
        )
        self.package_entry.grid(row=0, column=4, columnspan=2, padx=6, pady=6, sticky="ew")
        self.package_entry.insert(0, "com.example.adware")

        tk.Label(
            self.control_frame,
            text="Tip: usa paquete completo para acciones y keyword para busquedas rapidas.",
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["muted"],
            font=("Segoe UI", 9),
        ).grid(row=1, column=0, columnspan=6, padx=6, pady=(2, 0), sticky="w")

        operations_grid = tk.Frame(operations_page, bg=self.ui_tokens["surface_0"])
        operations_grid.grid(row=1, column=0, sticky="nsew")
        operations_grid.grid_columnconfigure(0, weight=5)
        operations_grid.grid_columnconfigure(1, weight=3)
        operations_grid.grid_rowconfigure(0, weight=1)

        self.command_buttons_frame = tk.LabelFrame(
            operations_grid,
            text="Playbooks de Analisis",
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["text"],
            bd=0,
            font=("Segoe UI Semibold", 11),
            highlightthickness=1,
            highlightbackground=self.ui_tokens["border"],
            padx=10,
            pady=10,
        )
        self.command_buttons_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        operation_actions: list[tuple[str, Callable[[], None]]] = [
            ("Ver app en foco", self.get_current_focus),
            ("Ver logs en tiempo real", self.search_ad_logs),
            ('Ver procesos que tengan "ad"', self.search_ad_processes),
            ("Ver paquetes por keyword", self.search_packages_by_keyword),
            ("Info detallada de paquete", self.investigate_package),
            ("Listar paquetes de terceros", self.list_installed_packages_history),
            ("Permisos sospechosos", self.list_apps_with_suspicious_permissions),
            ("Monitorear foco actual", self.monitor_current_focus),
            ("Extraer apps sospechosas", self.extract_suspicious_apps),
            ("Listar todas las apps", self.list_all_apps),
            ("Listar apps del sistema", self.list_system_apps),
            ("Apps con instalador", self.list_installer_apps),
        ]
        operation_buttons = self._create_button_grid(
            self.command_buttons_frame,
            operation_actions,
            columns=2,
            variant="action",
        )
        self.logcat_button = operation_buttons[1]

        ops_side = tk.Frame(operations_grid, bg=self.ui_tokens["surface_0"])
        ops_side.grid(row=0, column=1, sticky="nsew")
        ops_side.grid_rowconfigure(1, weight=1)
        ops_side.grid_columnconfigure(0, weight=1)

        self.action_buttons_frame = tk.LabelFrame(
            ops_side,
            text="Mantenimiento",
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["text"],
            bd=0,
            font=("Segoe UI Semibold", 11),
            highlightthickness=1,
            highlightbackground=self.ui_tokens["border"],
            padx=10,
            pady=10,
        )
        self.action_buttons_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        maintenance_actions: list[tuple[str, Callable[[], None]]] = [
            ("Desinstalar Paquete", self.uninstall_package),
            ("Mostrar Carpeta de Analisis", self.show_analysis_folder),
            ("Descargar Analisis", self.download_analysis),
        ]
        self._create_button_grid(self.action_buttons_frame, maintenance_actions, columns=1, variant="action")

        self.operations_notes = tk.LabelFrame(
            ops_side,
            text="Checklist Operativo",
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["text"],
            bd=0,
            font=("Segoe UI Semibold", 11),
            highlightthickness=1,
            highlightbackground=self.ui_tokens["border"],
            padx=12,
            pady=12,
        )
        self.operations_notes.grid(row=1, column=0, sticky="nsew")
        tk.Label(
            self.operations_notes,
            text=(
                "1) Inicializa ADB y selecciona dispositivo.\n"
                "2) Ejecuta playbooks de foco/logs para filtrar.\n"
                "3) Guarda evidencias y pasa a intelligence para enriquecimiento."
            ),
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["muted"],
            justify="left",
            wraplength=310,
            font=self.ui_fonts["body"],
        ).grid(row=0, column=0, sticky="nw")

        self.analysis_buttons_frame = tk.LabelFrame(
            intelligence_page,
            text="Gestion de Analisis Inteligente",
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["text"],
            bd=0,
            font=("Segoe UI Semibold", 11),
            highlightthickness=1,
            highlightbackground=self.ui_tokens["border"],
            padx=10,
            pady=10,
        )
        self.analysis_buttons_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.analysis_buttons_frame.grid_columnconfigure(0, weight=1)
        self.analysis_buttons_frame.grid_columnconfigure(1, weight=1)

        self.analyze_gemini_button = self._create_modern_button(
            self.analysis_buttons_frame,
            text="Analizar con Gemini",
            command=self.analyze_with_gemini,
            variant="primary",
        )
        self.analyze_gemini_button.configure(state="disabled")
        self.analyze_gemini_button.grid(row=0, column=0, padx=6, pady=6, sticky="ew")

        self.gemini_info_text = tk.StringVar(value="Gemini CLI no detectado.")
        tk.Label(
            self.analysis_buttons_frame,
            textvariable=self.gemini_info_text,
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["muted"],
            justify="left",
            wraplength=420,
            font=self.ui_fonts["body"],
        ).grid(row=0, column=1, padx=6, pady=6, sticky="w")

        self.intelligent_scan_button = self._create_modern_button(
            self.analysis_buttons_frame,
            text="Analisis Inteligente",
            command=self.run_intelligent_scan,
            variant="action",
        )
        self.intelligent_scan_button.configure(state="disabled")
        self.intelligent_scan_button.grid(row=1, column=0, padx=6, pady=6, sticky="ew")

        self.rebuild_baseline_button = self._create_modern_button(
            self.analysis_buttons_frame,
            text="Reentrenar Baseline",
            command=self.rebuild_intel_baseline,
            variant="action",
        )
        self.rebuild_baseline_button.configure(state="disabled")
        self.rebuild_baseline_button.grid(row=1, column=1, padx=6, pady=6, sticky="ew")

        self.label_malicious_button = self._create_modern_button(
            self.analysis_buttons_frame,
            text="Etiquetar Maliciosa",
            command=self.label_current_package_malicious,
            variant="action",
        )
        self.label_malicious_button.configure(state="disabled")
        self.label_malicious_button.grid(row=2, column=0, padx=6, pady=6, sticky="ew")

        self.label_benign_button = self._create_modern_button(
            self.analysis_buttons_frame,
            text="Etiquetar Benigna",
            command=self.label_current_package_benign,
            variant="action",
        )
        self.label_benign_button.configure(state="disabled")
        self.label_benign_button.grid(row=2, column=1, padx=6, pady=6, sticky="ew")

        self.train_model_button = self._create_modern_button(
            self.analysis_buttons_frame,
            text="Entrenar Modelo ML",
            command=self.train_supervised_model,
            variant="action",
        )
        self.train_model_button.configure(state="disabled")
        self.train_model_button.grid(row=3, column=0, columnspan=2, padx=6, pady=6, sticky="ew")

        self.export_stix_button = self._create_modern_button(
            self.analysis_buttons_frame,
            text="Exportar STIX-lite",
            command=self.export_stix_lite_bundle,
            variant="action",
        )
        self.export_stix_button.configure(state="disabled")
        self.export_stix_button.grid(row=4, column=0, columnspan=2, padx=6, pady=6, sticky="ew")

        self.campaign_dashboard_button = self._create_modern_button(
            self.analysis_buttons_frame,
            text="Dashboard Campanas",
            command=self.export_campaign_dashboard,
            variant="action",
        )
        self.campaign_dashboard_button.configure(state="disabled")
        self.campaign_dashboard_button.grid(row=5, column=0, columnspan=2, padx=6, pady=6, sticky="ew")

        self.intel_info_text = tk.StringVar(value="Intelligence layer no inicializada.")
        tk.Label(
            self.analysis_buttons_frame,
            textvariable=self.intel_info_text,
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["muted"],
            justify="left",
            wraplength=520,
            font=("Segoe UI", 9),
        ).grid(row=6, column=0, columnspan=2, padx=6, pady=(8, 4), sticky="w")

        intel_stats_frame = tk.LabelFrame(
            intelligence_page,
            text="Estadisticas de Riesgo",
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["text"],
            bd=0,
            font=("Segoe UI Semibold", 11),
            highlightthickness=1,
            highlightbackground=self.ui_tokens["border"],
            padx=10,
            pady=10,
        )
        intel_stats_frame.grid(row=0, column=1, sticky="nsew")
        intel_stats_frame.grid_columnconfigure(0, weight=1)
        intel_stats_frame.grid_columnconfigure(1, weight=1)
        intel_stats_frame.grid_rowconfigure(5, weight=1)

        self.stat_total_scans = tk.StringVar(value="0")
        self.stat_high_risk = tk.StringVar(value="0")
        self.stat_avg_risk = tk.StringVar(value="0.0")
        self.stat_clusters = tk.StringVar(value="0")

        self._create_insight_card(intel_stats_frame, 0, 0, "Scans Totales", self.stat_total_scans)
        self._create_insight_card(intel_stats_frame, 0, 1, "High Risk", self.stat_high_risk)
        self._create_insight_card(intel_stats_frame, 1, 0, "Riesgo Promedio", self.stat_avg_risk)
        self._create_insight_card(intel_stats_frame, 1, 1, "Clusters", self.stat_clusters)

        tk.Label(
            intel_stats_frame,
            text="Distribucion de riesgo",
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["text"],
            font=("Segoe UI Semibold", 10),
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 4))

        tk.Label(
            intel_stats_frame,
            text="Low",
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["muted"],
            font=("Segoe UI", 9),
        ).grid(row=3, column=0, sticky="w")
        self.low_risk_bar = ttk.Progressbar(
            intel_stats_frame,
            style="LowRisk.Horizontal.TProgressbar",
            maximum=100,
            value=0,
        )
        self.low_risk_bar.grid(row=3, column=1, sticky="ew", padx=(8, 0))

        tk.Label(
            intel_stats_frame,
            text="Medium",
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["muted"],
            font=("Segoe UI", 9),
        ).grid(row=4, column=0, sticky="w", pady=(4, 0))
        self.medium_risk_bar = ttk.Progressbar(
            intel_stats_frame,
            style="MediumRisk.Horizontal.TProgressbar",
            maximum=100,
            value=0,
        )
        self.medium_risk_bar.grid(row=4, column=1, sticky="ew", padx=(8, 0), pady=(4, 0))

        tk.Label(
            intel_stats_frame,
            text="High",
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["muted"],
            font=("Segoe UI", 9),
        ).grid(row=5, column=0, sticky="nw", pady=(4, 0))
        self.high_risk_bar = ttk.Progressbar(
            intel_stats_frame,
            style="HighRisk.Horizontal.TProgressbar",
            maximum=100,
            value=0,
        )
        self.high_risk_bar.grid(row=5, column=1, sticky="ew", padx=(8, 0), pady=(4, 0))

        tk.Label(
            intel_stats_frame,
            text="Ultimos escaneos",
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["text"],
            font=("Segoe UI Semibold", 10),
        ).grid(row=6, column=0, columnspan=2, sticky="w", pady=(12, 4))
        self.recent_scans_list = tk.Listbox(
            intel_stats_frame,
            bg=self.ui_tokens["surface_2"],
            fg=self.ui_tokens["text"],
            selectbackground=self.ui_tokens["accent_soft"],
            selectforeground=self.ui_tokens["text"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=self.ui_tokens["border"],
            font=("Consolas", 9),
            height=6,
        )
        self.recent_scans_list.grid(row=7, column=0, columnspan=2, sticky="nsew", pady=(0, 8))

        self.refresh_intel_button = self._create_modern_button(
            intel_stats_frame,
            text="Refrescar Estadisticas",
            command=lambda: self._refresh_intelligence_statistics(force=True),
            variant="ghost",
        )
        self.refresh_intel_button.grid(row=8, column=0, columnspan=2, sticky="ew")

        reports_header = tk.Label(
            reports_page,
            text="Reports Intelligence",
            bg=self.ui_tokens["surface_0"],
            fg=self.ui_tokens["text"],
            font=("Segoe UI Semibold", 14),
        )
        reports_header.grid(row=0, column=0, sticky="w", pady=(0, 10))
        reports_actions = tk.Frame(reports_page, bg=self.ui_tokens["surface_0"])
        reports_actions.grid(row=1, column=0, sticky="nsew")
        reports_actions.grid_columnconfigure(0, weight=1)
        reports_actions.grid_columnconfigure(1, weight=1)
        reports_actions.grid_columnconfigure(2, weight=1)
        self.reports_summary_text = tk.StringVar(
            value="Dashboard operativo listo. Genera escaneos inteligentes para alimentar correlacion."
        )
        tk.Label(
            reports_actions,
            textvariable=self.reports_summary_text,
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["muted"],
            justify="left",
            wraplength=820,
            font=self.ui_fonts["body"],
            padx=12,
            pady=10,
            relief="flat",
            highlightthickness=1,
            highlightbackground=self.ui_tokens["border"],
        ).grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 10))
        self.export_stix_reports_button = self._create_modern_button(
            reports_actions,
            text="Exportar STIX-lite",
            command=self.export_stix_lite_bundle,
            variant="action",
        )
        self.export_stix_reports_button.grid(row=1, column=0, padx=(0, 8), sticky="ew")
        self.export_campaign_reports_button = self._create_modern_button(
            reports_actions,
            text="Exportar Campaign Dashboard",
            command=self.export_campaign_dashboard,
            variant="action",
        )
        self.export_campaign_reports_button.grid(row=1, column=1, padx=(0, 8), sticky="ew")
        self.refresh_reports_button = self._create_modern_button(
            reports_actions,
            text="Actualizar Datos",
            command=lambda: self._refresh_intelligence_statistics(force=True),
            variant="ghost",
        )
        self.refresh_reports_button.grid(row=1, column=2, sticky="ew")

        console_toolbar = tk.Frame(
            console_page,
            bg=self.ui_tokens["surface_1"],
            highlightthickness=1,
            highlightbackground=self.ui_tokens["border"],
            padx=10,
            pady=8,
        )
        console_toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        console_toolbar.grid_columnconfigure(0, weight=1)
        tk.Label(
            console_toolbar,
            text="Consola en vivo: resultados de comandos, errores y eventos de escaneo.",
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["muted"],
            font=self.ui_fonts["body"],
        ).grid(row=0, column=0, sticky="w")
        self.clear_console_tab_button = self._create_modern_button(
            console_toolbar,
            text="Limpiar Salida",
            command=self.clear_output,
            variant="ghost",
        )
        self.clear_console_tab_button.grid(row=0, column=1, sticky="e")

        self.output_text = scrolledtext.ScrolledText(
            console_page,
            wrap=tk.WORD,
            height=24,
            state="disabled",
            font=self.ui_fonts["mono"],
            background=self.ui_tokens["console_bg"],
            foreground=self.ui_tokens["console_fg"],
            insertbackground=self.ui_tokens["console_fg"],
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=self.ui_tokens["border"],
            padx=10,
            pady=10,
        )
        self.output_text.grid(row=1, column=0, sticky="nsew")
        self.output_text.tag_config("red", foreground=self.ui_tokens["danger"])
        self.output_text.tag_config("yellow", foreground=self.ui_tokens["warn"])
        self.output_text.tag_config("green", foreground=self.ui_tokens["success"])

        self.status_text = tk.StringVar(value="Listo")
        status_bar = tk.Frame(
            self.main_frame,
            bg=self.ui_tokens["surface_0"],
            highlightthickness=1,
            highlightbackground=self.ui_tokens["border"],
            padx=10,
            pady=8,
        )
        status_bar.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        tk.Label(
            status_bar,
            textvariable=self.status_text,
            bg=self.ui_tokens["surface_0"],
            fg=self.ui_tokens["text"],
            anchor="w",
            font=("Segoe UI Semibold", 10),
        ).pack(fill="x")

        self.max_output_lines = 5000
        self._reload_analysis_file_index()
        self._switch_workspace("operations")
        self._refresh_intelligence_statistics(force=True)

    def _create_metric_card(
        self,
        parent: tk.Frame,
        column: int,
        title: str,
        value: tk.StringVar,
        subtitle: str,
    ) -> None:
        card = tk.Frame(
            parent,
            bg=self.ui_tokens["surface_1"],
            highlightthickness=1,
            highlightbackground=self.ui_tokens["border"],
            padx=12,
            pady=10,
        )
        card.grid(row=0, column=column, padx=4, sticky="ew")
        card.grid_columnconfigure(0, weight=1)
        tk.Label(
            card,
            text=title,
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["muted"],
            font=("Segoe UI Semibold", 10),
        ).grid(row=0, column=0, sticky="w")
        tk.Label(
            card,
            textvariable=value,
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["text"],
            font=self.ui_fonts["metric_value"],
        ).grid(row=1, column=0, sticky="w")
        tk.Label(
            card,
            text=subtitle,
            bg=self.ui_tokens["surface_1"],
            fg=self.ui_tokens["muted"],
            font=("Segoe UI", 9),
        ).grid(row=2, column=0, sticky="w")

    def _create_insight_card(
        self,
        parent: tk.Frame,
        row: int,
        column: int,
        title: str,
        value: tk.StringVar,
    ) -> None:
        card = tk.Frame(
            parent,
            bg=self.ui_tokens["surface_2"],
            highlightthickness=1,
            highlightbackground=self.ui_tokens["border"],
            padx=10,
            pady=8,
        )
        card.grid(row=row, column=column, padx=4, pady=4, sticky="ew")
        tk.Label(
            card,
            text=title,
            bg=self.ui_tokens["surface_2"],
            fg=self.ui_tokens["muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w")
        tk.Label(
            card,
            textvariable=value,
            bg=self.ui_tokens["surface_2"],
            fg=self.ui_tokens["text"],
            font=("Segoe UI Semibold", 14),
        ).pack(anchor="w")

    def _reload_analysis_file_index(self) -> None:
        self.analysis_files = sorted(self.analysis_dir.glob("*.txt"))
        self.metric_reports_count.set(str(len(self.analysis_files)))

    def _build_intel_stats_signature(self) -> str:
        analysis_count = 0
        analysis_mtime = 0
        try:
            with os.scandir(self.analysis_dir) as entries:
                for entry in entries:
                    if not entry.is_file():
                        continue
                    analysis_count += 1
                    stat = entry.stat()
                    analysis_mtime = max(analysis_mtime, int(stat.st_mtime_ns))
        except FileNotFoundError:
            pass

        db_mtime = 0
        if self.intel_db_path.exists():
            try:
                db_mtime = int(self.intel_db_path.stat().st_mtime_ns)
            except OSError:
                db_mtime = 0

        return f"{analysis_count}:{analysis_mtime}:{db_mtime}:{self.metric_gemini_state.get()}"

    def _parse_iso_datetime(self, value: str) -> datetime.datetime | None:
        try:
            parsed = datetime.datetime.fromisoformat(value)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=datetime.timezone.utc)
        return parsed.astimezone(datetime.timezone.utc)

    def _refresh_intelligence_statistics(self, force: bool = False) -> None:
        if not hasattr(self, "stat_total_scans"):
            return

        self._reload_analysis_file_index()
        signature = self._build_intel_stats_signature()
        if not force and signature == self.intel_stats_signature:
            return

        total_scans = 0
        high_risk_count = 0
        avg_risk = 0.0
        clusters_count = 0
        low_share = 0.0
        medium_share = 0.0
        high_share = 0.0
        recent_lines: list[str] = []

        if self.intel_pipeline is not None:
            try:
                records = self.intel_pipeline.db.get_scan_records(limit=1500)
                total_scans = len(records)
                if total_scans > 0:
                    total_risk = 0.0
                    low_count = 0
                    medium_count = 0
                    high_count = 0
                    for record in records:
                        score = float(record.get("risk_score", 0.0))
                        total_risk += score
                        if score >= 70:
                            high_count += 1
                        elif score >= 40:
                            medium_count += 1
                        else:
                            low_count += 1
                    avg_risk = total_risk / total_scans
                    high_risk_count = high_count
                    low_share = (low_count / total_scans) * 100.0
                    medium_share = (medium_count / total_scans) * 100.0
                    high_share = (high_count / total_scans) * 100.0

                recent = self.intel_pipeline.get_recent_scans(limit=7)
                for row in recent:
                    risk_score = float(row.get("risk_score", 0.0))
                    risk_level = str(row.get("risk_level", "LOW"))
                    package_name = str(row.get("package_name", "desconocido"))
                    created_at = str(row.get("created_at", ""))
                    created_label = created_at.replace("T", " ").replace("+00:00", "")[:16]
                    recent_lines.append(
                        f"{created_label} | {risk_level:<6} | {risk_score:>5.1f} | {package_name}"
                    )

                campaign_summary = self.intel_pipeline.analyze_campaigns(limit=1500, min_cluster_size=2)
                clusters_count = len(list(campaign_summary.get("clusters", [])))
                high_risk_global = int(campaign_summary.get("high_risk_scans", 0))
                self.reports_summary_text.set(
                    "Scans: {scans} | High risk: {high} | Clusters: {clusters} | Devices: {devices} | Packages: {packages}".format(
                        scans=int(campaign_summary.get("total_scans", 0)),
                        high=high_risk_global,
                        clusters=clusters_count,
                        devices=int(campaign_summary.get("global_device_count", 0)),
                        packages=int(campaign_summary.get("global_package_count", 0)),
                    )
                )
            except Exception as exc:
                recent_lines = [f"Error obteniendo estadisticas: {exc}"]
        else:
            recent_lines = ["Intelligence layer no disponible."]

        self.stat_total_scans.set(str(total_scans))
        self.stat_high_risk.set(str(high_risk_count))
        self.stat_avg_risk.set(f"{avg_risk:.1f}")
        self.stat_clusters.set(str(clusters_count))

        self.low_risk_bar.configure(value=low_share)
        self.medium_risk_bar.configure(value=medium_share)
        self.high_risk_bar.configure(value=high_share)

        self.recent_scans_list.delete(0, tk.END)
        if not recent_lines:
            recent_lines = ["Sin escaneos todavia."]
        for line in recent_lines:
            self.recent_scans_list.insert(tk.END, line)

        self.intel_stats_signature = signature

    def _update_device_metrics(self) -> None:
        self.metric_devices_count.set(str(len(self.devices)))
        selected = self.selected_device.get().strip()
        self.metric_active_device.set(selected if selected else "Ninguno")

    def _trim_output_if_needed(self) -> None:
        try:
            total_lines = int(self.output_text.index("end-1c").split(".")[0])
        except Exception:
            return
        if total_lines <= self.max_output_lines:
            return
        lines_to_delete = total_lines - self.max_output_lines
        self.output_text.delete("1.0", f"{lines_to_delete + 1}.0")

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
            self.metric_intel_state.set("No disponible")
            self._refresh_intelligence_statistics(force=True)
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
            self.export_stix_reports_button.config(state="normal")
            self.export_campaign_reports_button.config(state="normal")
            model_info = "sin modelo ML entrenado"
            if getattr(self.intel_pipeline, "ml_model", None) is not None:
                model_info = f"modelo ML cargado ({self.intel_pipeline.ml_model.version})"
            self.intel_info_text.set(
                f"Intelligence layer activa. IOC sync inicial: {upserted}. DB: {self.intel_db_path.name}. {model_info}"
            )
            self.metric_intel_state.set("Activa")
        except Exception as exc:
            self.intel_pipeline = None
            self.intel_info_text.set(f"Intelligence layer deshabilitada: {exc}")
            self.metric_intel_state.set("Error")
            self.export_stix_reports_button.config(state="disabled")
            self.export_campaign_reports_button.config(state="disabled")
        self._refresh_intelligence_statistics(force=True)

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

        self._trim_output_if_needed()
        self.output_text.see(tk.END)
        self.output_text.config(state="disabled")

    def clear_output(self) -> None:
        self.output_text.config(state="normal")
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state="disabled")
        self.set_status("Consola limpia")

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
            if filepath not in self.analysis_files:
                self.analysis_files.append(filepath)
            self.metric_reports_count.set(str(len(self.analysis_files)))
            self.append_output(f"Analisis guardado en: {filename}\n")
            self._refresh_intelligence_statistics()
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
            self._update_device_metrics()
            self.append_output(f"Dispositivos encontrados: {', '.join(devices)}\n")
        else:
            self.selected_device.set("")
            self._update_device_metrics()
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
        self._update_device_metrics()
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
                self.master.after(0, self._refresh_intelligence_statistics, True)
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
                self.master.after(0, self._refresh_intelligence_statistics, True)
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
                self.master.after(0, self._refresh_intelligence_statistics, True)
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
                self.master.after(0, self._refresh_intelligence_statistics, True)
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
                self.metric_gemini_state.set("Disponible")
            else:
                detail = result.stderr.strip() or "No disponible"
                self.gemini_info_text.set(f"Gemini CLI no disponible: {detail}")
                self.analyze_gemini_button.config(state="disabled")
                self.metric_gemini_state.set("No disponible")
        except FileNotFoundError:
            self.gemini_info_text.set("Gemini CLI no encontrado en PATH.")
            self.analyze_gemini_button.config(state="disabled")
            self.metric_gemini_state.set("No detectado")
        except Exception as exc:
            self.gemini_info_text.set(f"Error validando Gemini CLI: {exc}")
            self.analyze_gemini_button.config(state="disabled")
            self.metric_gemini_state.set("Error")
        self._refresh_intelligence_statistics(force=True)


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
