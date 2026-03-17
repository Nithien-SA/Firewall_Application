"""
main_window.py
Root Tk window — hosts the tabbed notebook, status bar, and refresh loop.
All emoji removed for Linux Tk compatibility.
"""

import tkinter as tk
from tkinter import ttk
import datetime

from gui import theme
from gui.traffic_tab import TrafficTab
from gui.rules_tab import RulesTab
from gui.control_panel import ControlPanel
from core.privilege import is_root, get_mode_label, get_mode_color


REFRESH_INTERVAL_MS = 3000   # 3 seconds


class MainWindow:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root_priv = is_root()

        # ── Window setup ─────────────────────────────────────────────────────
        mode = get_mode_label()
        self.root.title(f"FirewallGUI  --  {mode}")
        self.root.geometry("1280x780")
        self.root.minsize(960, 620)
        self.root.configure(bg=theme.BG_DARK)

        # Silently ignore WM hints that may not be supported
        try:
            self.root.wm_attributes("-type", "normal")
        except Exception:
            pass

        # Apply theme
        theme.apply_theme(self.root)

        # ── Build layout ─────────────────────────────────────────────────────
        self._build_header()
        self._build_notebook()
        self._build_statusbar()

        # ── Start refresh loop ───────────────────────────────────────────────
        self._schedule_refresh()

    # ─── Header ──────────────────────────────────────────────────────────────

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=theme.BG_PANEL)
        hdr.pack(fill="x", side="top")

        # Left: app name
        tk.Label(
            hdr, text="FirewallGUI",
            bg=theme.BG_PANEL, fg=theme.ACCENT,
            font=theme.FONT_TITLE, padx=18, pady=12,
        ).pack(side="left")

        # Right: privilege badge — plain text, no emoji
        badge_color = get_mode_color()
        mode_label  = get_mode_label().upper()
        tk.Label(
            hdr, text=f"  {mode_label}  ",
            bg=badge_color, fg=theme.BG_DARK,
            font=theme.FONT_BOLD, padx=6, pady=4,
        ).pack(side="right", padx=18, pady=10)

        # Separator
        ttk.Separator(self.root, orient="horizontal").pack(fill="x", side="top")

    # ─── Notebook ─────────────────────────────────────────────────────────────

    def _build_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=0, pady=0)

        # Tab 1 — Traffic Monitor
        frame1 = ttk.Frame(self.notebook)
        self.traffic_tab = TrafficTab(frame1, self._on_context_action)
        self.notebook.add(frame1, text="  Traffic Monitor  ")

        # Tab 2 — Firewall Rules
        frame2 = ttk.Frame(self.notebook)
        self.rules_tab = RulesTab(frame2, on_action=self._on_fw_action)
        self.notebook.add(frame2, text="  Firewall Rules  ")

        # Tab 3 — Control Panel
        frame3 = ttk.Frame(self.notebook)
        self.control_panel = ControlPanel(frame3, on_action=self._on_fw_action)
        self.notebook.add(frame3, text="  Control Panel  ")

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
        mode_color = get_mode_color()
        mode_label = get_mode_label()
        self._status_left.configure(
            text=f"Mode: {mode_label}   |   Connections visible: {conn_count}",
            fg=mode_color,
        )
        self._status_right.configure(text=f"Last refresh: {now}")

    # ─── Refresh loop ─────────────────────────────────────────────────────────

    def _schedule_refresh(self):
        self._do_refresh()
        self.root.after(REFRESH_INTERVAL_MS, self._schedule_refresh)

    def _do_refresh(self):
        count = self.traffic_tab.refresh()
        self._update_statusbar(count)

        # Also refresh rules tab if it's currently visible
        if self.notebook.index("current") == 1:
            self.rules_tab.refresh()

    # ─── Inter-tab communication ───────────────────────────────────────────────

    def _on_context_action(self, action: str, value: str):
        """Called when user right-clicks in traffic tab -> pre-fills control panel."""
        self.notebook.select(2)  # switch to Control Panel tab
        self.control_panel.prefill(action, value)

    def _on_fw_action(self, message: str):
        """Called after any firewall action from any tab -- keeps both tabs in sync."""
        self.rules_tab.refresh()
        self.control_panel.log_external(message)
