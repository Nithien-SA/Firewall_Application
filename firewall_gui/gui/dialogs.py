"""
dialogs.py
Reusable modal dialogs for the FirewallGUI application.
"""

import tkinter as tk
from tkinter import ttk


def _center_on(dlg: tk.Toplevel, parent: tk.Widget):
    """Center a Toplevel on its parent window."""
    dlg.update_idletasks()
    root = parent.winfo_toplevel()
    rx, ry = root.winfo_rootx(), root.winfo_rooty()
    rw, rh = root.winfo_width(), root.winfo_height()
    dw, dh = dlg.winfo_width(), dlg.winfo_height()
    dlg.geometry(f"+{rx + (rw - dw) // 2}+{ry + (rh - dh) // 2}")


def ask_chain(parent: tk.Widget, verb: str = "Apply") -> str | None:
    """
    Modal dialog asking which iptables chain(s) to target.

    Parameters
    ----------
    parent : tk.Widget  – any widget (dialog centers on its root window)
    verb   : str        – verb shown in the prompt, e.g. "Flush" or "Delete from"

    Returns
    -------
    'INPUT' | 'OUTPUT' | 'BOTH'  or  None (cancelled / closed)
    """
    # Import here to avoid circular imports with theme
    from gui import theme

    result = [None]

    dlg = tk.Toplevel(parent)
    dlg.title("Select Chain")
    dlg.configure(bg=theme.BG_DARK)
    dlg.resizable(False, False)
    dlg.transient(parent.winfo_toplevel())
    dlg.grab_set()

    # Prompt
    tk.Label(
        dlg,
        text=f"{verb} rules from which chain?",
        bg=theme.BG_DARK, fg=theme.TEXT_PRIMARY,
        font=theme.FONT_BOLD, padx=24, pady=16,
    ).pack()

    # Divider
    ttk.Separator(dlg, orient="horizontal").pack(fill="x", padx=16)

    # Buttons
    btn_frame = tk.Frame(dlg, bg=theme.BG_DARK)
    btn_frame.pack(pady=16, padx=24)

    style = ttk.Style(dlg)

    def choose(val):
        result[0] = val
        dlg.destroy()

    ttk.Button(btn_frame, text="INPUT",  command=lambda: choose("INPUT"),
               style="Accent.TButton").pack(side="left", padx=(0, 6))
    ttk.Button(btn_frame, text="OUTPUT", command=lambda: choose("OUTPUT"),
               style="Accent.TButton").pack(side="left", padx=(0, 6))
    ttk.Button(btn_frame, text="BOTH",   command=lambda: choose("BOTH"),
               style="TButton").pack(side="left", padx=(0, 14))
    ttk.Button(btn_frame, text="Cancel", command=dlg.destroy,
               style="TButton").pack(side="left")

    _center_on(dlg, parent)
    dlg.wait_window()
    return result[0]


def ask_block_direction(parent: tk.Widget, label: str, value: str) -> str | None:
    """
    Modal dialog asking which direction to block a port or IP on.
    Shown when the user right-clicks in the Traffic Monitor.

    Parameters
    ----------
    label : str  – 'IP' or 'Port'
    value : str  – the IP address or port number string

    Returns
    -------
    'INPUT' | 'OUTPUT' | 'BOTH'  or  None (cancelled)
    """
    from gui import theme

    result = [None]

    dlg = tk.Toplevel(parent)
    dlg.title(f"Block {label}")
    dlg.configure(bg=theme.BG_DARK)
    dlg.resizable(False, False)
    dlg.transient(parent.winfo_toplevel())
    dlg.grab_set()

    # Title
    tk.Label(
        dlg, text=f"Block {label}:  {value}",
        bg=theme.BG_DARK, fg=theme.ACCENT,
        font=theme.FONT_BOLD,
    ).pack(padx=24, pady=(16, 4))

    # Explanation grid
    info_frame = tk.Frame(dlg, bg=theme.BG_PANEL, padx=16, pady=8)
    info_frame.pack(fill="x", padx=16, pady=(0, 4))

    rows = [
        ("INPUT",  f"Block {label} from reaching this machine"),
        ("OUTPUT", f"Block this machine from connecting to {label}"),
        ("BOTH",   f"Block all communication with {label}"),
    ]
    for r_label, r_desc in rows:
        row = tk.Frame(info_frame, bg=theme.BG_PANEL)
        row.pack(fill="x", pady=2)
        tk.Label(row, text=f"{r_label:<8}", bg=theme.BG_PANEL,
                 fg=theme.ACCENT, font=theme.FONT_BOLD, width=8, anchor="w").pack(side="left")
        tk.Label(row, text=r_desc, bg=theme.BG_PANEL,
                 fg=theme.TEXT_SECONDARY, font=theme.FONT_SMALL, anchor="w").pack(side="left")

    ttk.Separator(dlg, orient="horizontal").pack(fill="x", padx=16, pady=4)

    # Buttons
    btn_frame = tk.Frame(dlg, bg=theme.BG_DARK)
    btn_frame.pack(pady=12, padx=24)

    def choose(val):
        result[0] = val
        dlg.destroy()

    ttk.Button(btn_frame, text="INPUT",  command=lambda: choose("INPUT"),
               style="Danger.TButton").pack(side="left", padx=(0, 6))
    ttk.Button(btn_frame, text="OUTPUT", command=lambda: choose("OUTPUT"),
               style="Danger.TButton").pack(side="left", padx=(0, 6))
    ttk.Button(btn_frame, text="BOTH",   command=lambda: choose("BOTH"),
               style="Danger.TButton").pack(side="left", padx=(0, 14))
    ttk.Button(btn_frame, text="Cancel", command=dlg.destroy,
               style="TButton").pack(side="left")

    _center_on(dlg, parent)
    dlg.wait_window()
    return result[0]
