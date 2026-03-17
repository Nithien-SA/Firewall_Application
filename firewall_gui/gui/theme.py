"""
theme.py
Central design system — dark slate palette with cyan accent.
Applied globally to ttk.Style and used as constants throughout the GUI.
"""

import tkinter as tk
from tkinter import ttk

# ─── Colour Palette ────────────────────────────────────────────────────────────
BG_DARK       = "#0d1117"   # main window background
BG_PANEL      = "#161b22"   # card / panel background
BG_WIDGET     = "#21262d"   # input fields, treeview bg
BG_HOVER      = "#30363d"   # hover state
BORDER        = "#30363d"   # border / separator

ACCENT        = "#00b4d8"   # primary cyan accent
ACCENT_DARK   = "#0077b6"   # secondary / pressed accent
SUCCESS       = "#00e676"   # green — allowed / established
WARNING       = "#ff9800"   # amber — read-only / time-wait
DANGER        = "#f44336"   # red — blocked / drop
INFO          = "#60a5fa"   # blue — listen

TEXT_PRIMARY   = "#e6edf3"  # main text
TEXT_SECONDARY = "#8b949e"  # muted labels
TEXT_ACCENT    = "#00b4d8"  # highlighted text

# ─── Row Tag Colours ───────────────────────────────────────────────────────────
ROW_ESTABLISHED = "#0d2818"
ROW_LISTEN      = "#0d1e30"
ROW_TIMEWAIT    = "#2d1e00"
ROW_DROP        = "#2d0d0d"
ROW_ACCEPT      = "#0d2818"

# ─── Fonts ─────────────────────────────────────────────────────────────────────
FONT_FAMILY     = "Consolas"
FONT_NORMAL     = (FONT_FAMILY, 10)
FONT_SMALL      = (FONT_FAMILY, 9)
FONT_BOLD       = (FONT_FAMILY, 10, "bold")
FONT_HEADER     = (FONT_FAMILY, 13, "bold")
FONT_TITLE      = (FONT_FAMILY, 16, "bold")
FONT_MONO       = ("Courier New", 9)

# ─── Dimensions ────────────────────────────────────────────────────────────────
PAD             = 10
PAD_SM          = 6
CORNER_RADIUS   = 6


def apply_theme(root: tk.Tk):
    """Apply the dark theme globally to all ttk widgets."""
    style = ttk.Style(root)
    style.theme_use("clam")

    # General
    style.configure(".",
        background=BG_DARK, foreground=TEXT_PRIMARY,
        font=FONT_NORMAL, borderwidth=0,
        relief="flat",
    )

    # Notebook
    style.configure("TNotebook",
        background=BG_DARK, borderwidth=0, tabmargins=[0, 0, 0, 0],
    )
    style.configure("TNotebook.Tab",
        background=BG_PANEL, foreground=TEXT_SECONDARY,
        font=FONT_BOLD, padding=[16, 8], borderwidth=0,
    )
    style.map("TNotebook.Tab",
        background=[("selected", BG_DARK), ("active", BG_HOVER)],
        foreground=[("selected", ACCENT), ("active", TEXT_PRIMARY)],
    )

    # Frame / LabelFrame
    style.configure("TFrame", background=BG_DARK)
    style.configure("Card.TFrame", background=BG_PANEL, relief="flat")
    style.configure("TLabelframe",
        background=BG_PANEL, foreground=ACCENT,
        bordercolor=BORDER, relief="flat", borderwidth=1,
    )
    style.configure("TLabelframe.Label",
        background=BG_PANEL, foreground=ACCENT, font=FONT_BOLD,
    )

    # Treeview
    style.configure("Treeview",
        background=BG_WIDGET, foreground=TEXT_PRIMARY,
        rowheight=26, fieldbackground=BG_WIDGET,
        borderwidth=0, font=FONT_NORMAL,
    )
    style.configure("Treeview.Heading",
        background=BG_PANEL, foreground=ACCENT,
        font=FONT_BOLD, relief="flat", borderwidth=0,
    )
    style.map("Treeview",
        background=[("selected", ACCENT_DARK)],
        foreground=[("selected", TEXT_PRIMARY)],
    )
    style.map("Treeview.Heading",
        background=[("active", BG_HOVER)],
    )

    # Buttons
    style.configure("TButton",
        background=BG_WIDGET, foreground=TEXT_PRIMARY,
        font=FONT_BOLD, padding=[12, 6], relief="flat",
        borderwidth=0,
    )
    style.map("TButton",
        background=[("active", BG_HOVER), ("disabled", BG_PANEL)],
        foreground=[("disabled", TEXT_SECONDARY)],
    )
    style.configure("Accent.TButton",
        background=ACCENT, foreground=BG_DARK,
        font=FONT_BOLD, padding=[12, 6],
    )
    style.map("Accent.TButton",
        background=[("active", ACCENT_DARK), ("disabled", BG_WIDGET)],
        foreground=[("disabled", TEXT_SECONDARY)],
    )
    style.configure("Danger.TButton",
        background=DANGER, foreground=TEXT_PRIMARY,
        font=FONT_BOLD, padding=[12, 6],
    )
    style.map("Danger.TButton",
        background=[("active", "#b71c1c"), ("disabled", BG_WIDGET)],
        foreground=[("disabled", TEXT_SECONDARY)],
    )
    style.configure("Success.TButton",
        background=SUCCESS, foreground=BG_DARK,
        font=FONT_BOLD, padding=[12, 6],
    )
    style.map("Success.TButton",
        background=[("active", "#00a152"), ("disabled", BG_WIDGET)],
        foreground=[("disabled", TEXT_SECONDARY)],
    )

    # Entry
    style.configure("TEntry",
        fieldbackground=BG_WIDGET, foreground=TEXT_PRIMARY,
        insertcolor=ACCENT, bordercolor=BORDER,
        relief="flat", padding=[6, 4],
    )
    style.map("TEntry",
        bordercolor=[("focus", ACCENT)],
        fieldbackground=[("disabled", BG_PANEL)],
    )

    # Combobox
    style.configure("TCombobox",
        fieldbackground=BG_WIDGET, foreground=TEXT_PRIMARY,
        background=BG_WIDGET, arrowcolor=ACCENT,
        relief="flat", padding=[6, 4],
    )
    style.map("TCombobox",
        fieldbackground=[("readonly", BG_WIDGET)],
        selectbackground=[("readonly", BG_WIDGET)],
        selectforeground=[("readonly", TEXT_PRIMARY)],
    )

    # Scrollbar
    style.configure("TScrollbar",
        background=BG_PANEL, troughcolor=BG_DARK,
        arrowcolor=TEXT_SECONDARY, borderwidth=0,
    )
    style.map("TScrollbar",
        background=[("active", BG_HOVER)],
    )

    # Separator
    style.configure("TSeparator", background=BORDER)

    # Progress / Status label areas
    style.configure("Status.TLabel",
        background=BG_PANEL, foreground=TEXT_SECONDARY,
        font=FONT_SMALL, padding=[8, 4],
    )
