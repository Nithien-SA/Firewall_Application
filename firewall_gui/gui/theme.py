"""
theme.py
Central design system — dark slate palette with cyan accent.
Fonts are tkinter.font.Font objects so size can be updated live.
"""

import tkinter as tk
from tkinter import ttk
import tkinter.font as tkfont


# ─── Colour Palette ────────────────────────────────────────────────────────────
BG_DARK       = "#0d1117"
BG_PANEL      = "#161b22"
BG_WIDGET     = "#21262d"
BG_HOVER      = "#30363d"
BORDER        = "#30363d"

ACCENT        = "#00b4d8"
ACCENT_DARK   = "#0077b6"
SUCCESS       = "#00e676"
WARNING       = "#ff9800"
DANGER        = "#f44336"
INFO          = "#60a5fa"

TEXT_PRIMARY   = "#e6edf3"
TEXT_SECONDARY = "#8b949e"
TEXT_ACCENT    = "#00b4d8"

# ─── Row Tag Colours ───────────────────────────────────────────────────────────
ROW_ESTABLISHED = "#0d2818"
ROW_LISTEN      = "#0d1e30"
ROW_TIMEWAIT    = "#2d1e00"
ROW_DROP        = "#2d0d0d"
ROW_ACCEPT      = "#0d2818"

# ─── Font settings ─────────────────────────────────────────────────────────────
FONT_FAMILY  = "DejaVu Sans Mono"
_font_size   = 10   # current size, readable by settings_tab

# These are set to Font objects by apply_theme() and updated live by update_font_size()
FONT_NORMAL  = None
FONT_SMALL   = None
FONT_BOLD    = None
FONT_HEADER  = None
FONT_TITLE   = None
FONT_MONO    = None

# ─── Dimensions ────────────────────────────────────────────────────────────────
PAD    = 10
PAD_SM = 6


def apply_theme(root: tk.Tk, font_size: int = None):
    """
    Apply the dark theme globally and (re)initialise Font objects.
    Call with font_size= to change the font size live.
    """
    global _font_size, FONT_NORMAL, FONT_SMALL, FONT_BOLD, FONT_HEADER, FONT_TITLE, FONT_MONO

    if font_size is not None:
        _font_size = font_size

    sz = _font_size
    fam = FONT_FAMILY

    if FONT_NORMAL is None:
        # First call: create Font objects (requires Tk to be running)
        FONT_NORMAL = tkfont.Font(family=fam, size=sz)
        FONT_SMALL  = tkfont.Font(family=fam, size=sz - 1)
        FONT_BOLD   = tkfont.Font(family=fam, size=sz,  weight="bold")
        FONT_HEADER = tkfont.Font(family=fam, size=sz + 3, weight="bold")
        FONT_TITLE  = tkfont.Font(family=fam, size=sz + 6, weight="bold")
        FONT_MONO   = tkfont.Font(family=fam, size=sz - 1)
    else:
        # Subsequent calls: update size in-place — propagates to all widgets using them
        FONT_NORMAL.configure(size=sz)
        FONT_SMALL.configure(size=sz - 1)
        FONT_BOLD.configure(size=sz)
        FONT_HEADER.configure(size=sz + 3)
        FONT_TITLE.configure(size=sz + 6)
        FONT_MONO.configure(size=sz - 1)

    # ── ttk styles ─────────────────────────────────────────────────────────────
    style = ttk.Style(root)
    style.theme_use("clam")

    style.configure(".",
        background=BG_DARK, foreground=TEXT_PRIMARY,
        font=FONT_NORMAL, borderwidth=0, relief="flat",
    )

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

    style.configure("TFrame", background=BG_DARK)
    style.configure("TLabelframe",
        background=BG_PANEL, foreground=ACCENT,
        bordercolor=BORDER, relief="flat", borderwidth=1,
    )
    style.configure("TLabelframe.Label",
        background=BG_PANEL, foreground=ACCENT, font=FONT_BOLD,
    )

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

    style.configure("TButton",
        background=BG_WIDGET, foreground=TEXT_PRIMARY,
        font=FONT_BOLD, padding=[12, 6], relief="flat", borderwidth=0,
    )
    style.map("TButton",
        background=[("active", BG_HOVER), ("disabled", BG_PANEL)],
        foreground=[("disabled", TEXT_SECONDARY)],
    )
    style.configure("Accent.TButton",
        background=ACCENT, foreground=BG_DARK, font=FONT_BOLD, padding=[12, 6],
    )
    style.map("Accent.TButton",
        background=[("active", ACCENT_DARK), ("disabled", BG_WIDGET)],
        foreground=[("disabled", TEXT_SECONDARY)],
    )
    style.configure("Danger.TButton",
        background=DANGER, foreground=TEXT_PRIMARY, font=FONT_BOLD, padding=[12, 6],
    )
    style.map("Danger.TButton",
        background=[("active", "#b71c1c"), ("disabled", BG_WIDGET)],
        foreground=[("disabled", TEXT_SECONDARY)],
    )
    style.configure("Success.TButton",
        background=SUCCESS, foreground=BG_DARK, font=FONT_BOLD, padding=[12, 6],
    )
    style.map("Success.TButton",
        background=[("active", "#00a152"), ("disabled", BG_WIDGET)],
        foreground=[("disabled", TEXT_SECONDARY)],
    )

    style.configure("TEntry",
        fieldbackground=BG_WIDGET, foreground=TEXT_PRIMARY,
        insertcolor=ACCENT, bordercolor=BORDER, relief="flat", padding=[6, 4],
    )
    style.map("TEntry",
        bordercolor=[("focus", ACCENT)],
        fieldbackground=[("disabled", BG_PANEL)],
    )

    style.configure("TCombobox",
        fieldbackground=BG_WIDGET, foreground=TEXT_PRIMARY,
        background=BG_WIDGET, arrowcolor=ACCENT, relief="flat", padding=[6, 4],
    )
    style.map("TCombobox",
        fieldbackground=[("readonly", BG_WIDGET)],
        selectbackground=[("readonly", BG_WIDGET)],
        selectforeground=[("readonly", TEXT_PRIMARY)],
    )

    style.configure("TScrollbar",
        background=BG_PANEL, troughcolor=BG_DARK,
        arrowcolor=TEXT_SECONDARY, borderwidth=0,
    )
    style.map("TScrollbar", background=[("active", BG_HOVER)])

    style.configure("TSeparator", background=BORDER)
