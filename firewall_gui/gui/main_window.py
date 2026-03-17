"""
main_window.py
Root Tk window — hosts the tabbed notebook, status bar, and refresh loop.
"""

import tkinter as tk
from tkinter import ttk
import datetime

from gui import theme
from gui.traffic_tab import TrafficTab
from gui.rules_tab import RulesTab
from gui.control_panel import ControlPanel
from gui.settings_tab import SettingsTab
from core.privilege import is_root, get_mode_label, get_mode_color

REFRESH_INTERVAL_MS = 3000   # default 3 seconds


class MainWindow:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root_priv = is_root()
        self._refresh_ms = REFRESH_INTERVAL_MS
        self._refresh_job = None

        mode = get_mode_label()
        self.root.title(f"FirewallGUI  --  {mode}")
        self.root.geometry("1280x800")
        self.root.minsize(960, 640)
        self.root.configure(bg=theme.BG_DARK)

        try:
            self.root.wm_attributes("-type", "normal")
        except Exception:
            pass

        theme.apply_theme(self.root)

        self._build_header()
        self._build_notebook()
        self._build_statusbar()
        self._schedule_refresh()

    # ─── Header ──────────────────────────────────────────────────────────────

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=theme.BG_PANEL)
        hdr.pack(fill="x", side="top")

        tk.Label(
            hdr, text="FirewallGUI",
            bg=theme.BG_PANEL, fg=theme.ACCENT,
            font=theme.FONT_TITLE, padx=18, pady=12,
        ).pack(side="left")

        badge_color = get_mode_color()
        tk.Label(
            hdr, text=f"  {get_mode_label().upper()}  ",
            bg=badge_color, fg=theme.BG_DARK,
            font=theme.FONT_BOLD, padx=6, pady=4,
        ).pack(side="right", padx=18, pady=10)

        ttk.Separator(self.root, orient="horizontal").pack(fill="x", side="top")

    # ─── Notebook ─────────────────────────────────────────────────────────────

    def _build_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        frame1 = ttk.Frame(self.notebook)
        self.traffic_tab = TrafficTab(frame1, self._on_context_action)
        self.notebook.add(frame1, text="  Traffic Monitor  ")

        frame2 = ttk.Frame(self.notebook)
        self.rules_tab = RulesTab(frame2, on_action=self._on_fw_action)
        self.notebook.add(frame2, text="  Firewall Rules  ")

        frame3 = ttk.Frame(self.notebook)
        self.control_panel = ControlPanel(frame3, on_action=self._on_fw_action)
        self.notebook.add(frame3, text="  Control Panel  ")

        frame4 = ttk.Frame(self.notebook)
        self.settings_tab = SettingsTab(
            frame4,
            on_font_size_change=self._on_font_size_change,
            on_refresh_change=self._on_refresh_change,
        )
        self.notebook.add(frame4, text="  Settings  ")

    # ─── Status bar ───────────────────────────────────────────────────────────

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=theme.BG_PANEL, height=28)
        bar.pack(fill="x", side="bottom")

        self._status_left = tk.Label(
            bar, text="", bg=theme.BG_PANEL,
            fg=theme.TEXT_SECONDARY, font=theme.FONT_SMALL, padx=10,
        )
        self._status_left.pack(side="left")

        self._status_right = tk.Label(
            bar, text="", bg=theme.BG_PANEL,
            fg=theme.TEXT_SECONDARY, font=theme.FONT_SMALL, padx=10,
        )
        self._status_right.pack(side="right")

    def _update_statusbar(self, conn_count: int):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self._status_left.configure(
            text=f"Mode: {get_mode_label()}   |   Connections: {conn_count}   |   "
                 f"Refresh: {self._refresh_ms // 1000}s",
            fg=get_mode_color(),
        )
        self._status_right.configure(text=f"Last refresh: {now}")

    # ─── Refresh loop ─────────────────────────────────────────────────────────

    def _schedule_refresh(self):
        if self._refresh_job:
            self.root.after_cancel(self._refresh_job)
        self._do_refresh()
        self._refresh_job = self.root.after(self._refresh_ms, self._schedule_refresh)

    def _do_refresh(self):
        count = self.traffic_tab.refresh()
        self._update_statusbar(count)
        if self.notebook.index("current") == 1:
            self.rules_tab.refresh()

    # ─── Settings callbacks ───────────────────────────────────────────────────

    def _on_font_size_change(self, size: int):
        """Live-update font size across the whole app."""
        theme.apply_theme(self.root, font_size=size)

    def _on_refresh_change(self, ms: int):
        """Reset the refresh loop with a new interval."""
        self._refresh_ms = ms
        self._schedule_refresh()

    # ─── Inter-tab communication ───────────────────────────────────────────────

    def _on_context_action(self, action: str, value: str, direction: str = "INPUT"):
        """Called from traffic tab right-click — pre-fills control panel."""
        self.notebook.select(2)
        self.control_panel.prefill(action, value, direction)

    def _on_fw_action(self, message: str):
        """Called after any firewall action — keeps Rules and Control Panel in sync."""
        self.rules_tab.refresh()
        self.control_panel.log_external(message)
