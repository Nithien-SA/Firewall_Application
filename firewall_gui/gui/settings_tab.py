"""
settings_tab.py
Application settings panel - font size, refresh rate, and UI preferences.
Changes are applied live using tkinter.font.Font object mutation.
"""

import tkinter as tk
from tkinter import ttk

from gui import theme


class SettingsTab:
    def __init__(self, parent: ttk.Frame, on_font_size_change, on_refresh_change):
        """
        on_font_size_change(size: int)  – called when user applies new font size
        on_refresh_change(ms: int)      – called when user changes refresh interval
        """
        self.parent = parent
        self.on_font_size_change = on_font_size_change
        self.on_refresh_change   = on_refresh_change

        parent.configure(style="TFrame")
        self._build(parent)

    def _build(self, parent):
        # ── Outer scroll container ────────────────────────────────────────────
        canvas = tk.Canvas(parent, bg=theme.BG_DARK, highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=theme.BG_DARK)
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        def on_resize(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.itemconfig(win_id, width=event.width)
        inner.bind("<Configure>", on_resize)
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(win_id, width=e.width))

        # Mousewheel
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(-1 * (e.delta // 120), "units"))

        self._build_font_section(inner)
        self._build_refresh_section(inner)
        self._build_appearance_section(inner)
        self._build_about_section(inner)

    # ─── Font settings ────────────────────────────────────────────────────────

    def _build_font_section(self, parent):
        frame = ttk.LabelFrame(parent, text=" Font & Text ")
        frame.pack(fill="x", padx=theme.PAD * 2, pady=(theme.PAD * 2, theme.PAD))
        frame.columnconfigure(1, weight=1)

        # Font size
        tk.Label(
            frame, text="Font size:",
            bg=theme.BG_PANEL, fg=theme.TEXT_SECONDARY, font=theme.FONT_NORMAL,
            anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=(16, 10), pady=(14, 6))

        self._font_size_var = tk.IntVar(value=theme._font_size)
        size_spin = tk.Spinbox(
            frame,
            from_=7, to=20,
            textvariable=self._font_size_var,
            width=6, state="readonly",
            bg=theme.BG_WIDGET, fg=theme.TEXT_PRIMARY,
            buttonbackground=theme.BG_HOVER,
            highlightthickness=0, relief="flat",
            font=theme.FONT_NORMAL,
            readonlybackground=theme.BG_WIDGET,
        )
        size_spin.grid(row=0, column=1, sticky="w", padx=(0, 16), pady=(14, 6))

        self._font_preview = tk.Label(
            frame,
            text="Preview: The quick brown fox jumps over the lazy dog  0123456789",
            bg=theme.BG_WIDGET, fg=theme.TEXT_PRIMARY,
            anchor="w", padx=8, pady=4,
        )
        self._font_preview.grid(
            row=1, column=0, columnspan=2, sticky="ew",
            padx=16, pady=(0, 6),
        )

        # Live preview update
        def _preview(*_):
            size = self._font_size_var.get()
            self._font_preview.configure(font=(theme.FONT_FAMILY, size))
        self._font_size_var.trace_add("write", _preview)

        ttk.Button(
            frame, text="Apply Font Size",
            command=self._apply_font_size,
            style="Accent.TButton",
        ).grid(row=2, column=0, columnspan=2, sticky="w",
               padx=16, pady=(4, 14))

        self._font_msg = tk.Label(
            frame, text="",
            bg=theme.BG_PANEL, fg=theme.SUCCESS,
            font=theme.FONT_SMALL, anchor="w",
        )
        self._font_msg.grid(row=3, column=0, columnspan=2, sticky="w",
                            padx=16, pady=(0, 10))

    def _apply_font_size(self):
        size = self._font_size_var.get()
        self.on_font_size_change(size)
        self._font_msg.configure(
            text=f"Font size updated to {size}pt. Some labels update immediately.",
            fg=theme.SUCCESS,
        )

    # ─── Refresh rate ─────────────────────────────────────────────────────────

    def _build_refresh_section(self, parent):
        frame = ttk.LabelFrame(parent, text=" Traffic Monitor ")
        frame.pack(fill="x", padx=theme.PAD * 2, pady=theme.PAD)
        frame.columnconfigure(1, weight=1)

        tk.Label(
            frame, text="Refresh interval (seconds):",
            bg=theme.BG_PANEL, fg=theme.TEXT_SECONDARY, font=theme.FONT_NORMAL,
            anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=(16, 10), pady=(14, 6))

        self._refresh_var = tk.IntVar(value=3)
        tk.Spinbox(
            frame,
            from_=1, to=30,
            textvariable=self._refresh_var,
            width=6, state="readonly",
            bg=theme.BG_WIDGET, fg=theme.TEXT_PRIMARY,
            buttonbackground=theme.BG_HOVER,
            highlightthickness=0, relief="flat",
            font=theme.FONT_NORMAL,
            readonlybackground=theme.BG_WIDGET,
        ).grid(row=0, column=1, sticky="w", padx=(0, 16), pady=(14, 6))

        ttk.Button(
            frame, text="Apply Refresh Rate",
            command=self._apply_refresh,
            style="Accent.TButton",
        ).grid(row=1, column=0, columnspan=2, sticky="w",
               padx=16, pady=(4, 14))

        self._refresh_msg = tk.Label(
            frame, text="",
            bg=theme.BG_PANEL, fg=theme.SUCCESS,
            font=theme.FONT_SMALL, anchor="w",
        )
        self._refresh_msg.grid(row=2, column=0, columnspan=2, sticky="w",
                               padx=16, pady=(0, 10))

    def _apply_refresh(self):
        ms = self._refresh_var.get() * 1000
        self.on_refresh_change(ms)
        self._refresh_msg.configure(
            text=f"Refresh interval set to {self._refresh_var.get()}s.",
            fg=theme.SUCCESS,
        )

    # ─── Appearance ───────────────────────────────────────────────────────────

    def _build_appearance_section(self, parent):
        frame = ttk.LabelFrame(parent, text=" Colour Accents ")
        frame.pack(fill="x", padx=theme.PAD * 2, pady=theme.PAD)

        note = (
            "The application uses a fixed dark theme. "
            "Accent and status colours:"
        )
        tk.Label(
            frame, text=note,
            bg=theme.BG_PANEL, fg=theme.TEXT_SECONDARY,
            font=theme.FONT_SMALL, anchor="w", wraplength=600, justify="left",
        ).pack(anchor="w", padx=16, pady=(12, 6))

        swatch_frame = tk.Frame(frame, bg=theme.BG_PANEL)
        swatch_frame.pack(anchor="w", padx=16, pady=(0, 14))

        swatches = [
            (theme.ACCENT,   "Accent / selected"),
            (theme.SUCCESS,  "Allowed / established"),
            (theme.DANGER,   "Blocked / drop"),
            (theme.WARNING,  "Read-only / time-wait"),
            (theme.INFO,     "Listen"),
        ]
        for color, label in swatches:
            col_frame = tk.Frame(swatch_frame, bg=theme.BG_PANEL)
            col_frame.pack(side="left", padx=(0, 18))
            tk.Frame(col_frame, bg=color, width=28, height=14).pack()
            tk.Label(
                col_frame, text=label,
                bg=theme.BG_PANEL, fg=theme.TEXT_SECONDARY,
                font=theme.FONT_SMALL,
            ).pack()

    # ─── About ────────────────────────────────────────────────────────────────

    def _build_about_section(self, parent):
        frame = ttk.LabelFrame(parent, text=" About ")
        frame.pack(fill="x", padx=theme.PAD * 2, pady=(theme.PAD, theme.PAD * 2))

        about_text = (
            "FirewallGUI  --  Centralized firewall management for Linux\n"
            "Backend: iptables    Traffic source: /proc/net/* + ss\n"
            "Rules are session-only and cleared on reboot.\n\n"
            "Run with:  sudo python3 firewall_app.py   for full access."
        )
        tk.Label(
            frame, text=about_text,
            bg=theme.BG_PANEL, fg=theme.TEXT_SECONDARY,
            font=theme.FONT_SMALL, anchor="w", justify="left",
            padx=16, pady=14,
        ).pack(anchor="w")
