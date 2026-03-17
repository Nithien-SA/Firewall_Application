#!/usr/bin/env python3
"""
firewall_app.py
Entry point for the FirewallGUI application.

Usage:
    python3 firewall_app.py          # Read-only mode (no root)
    sudo python3 firewall_app.py     # Administrator mode (full control)
"""

import sys
import os
import tkinter as tk

# ── Ensure the project root is on sys.path so imports work ───────────────────
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.privilege import is_root, get_mode_label
from gui.main_window import MainWindow


def main():
    mode = get_mode_label()
    root_icon = "🛡" if is_root() else "👁"
    print(f"{root_icon}  FirewallGUI starting in {mode} mode  {root_icon}")

    if not is_root():
        print(
            "  ⚠  Running without root privileges.\n"
            "     Traffic monitoring is available, but firewall rule\n"
            "     management is disabled.\n"
            "     Re-run as:  sudo python3 firewall_app.py"
        )
    else:
        print("  ✓  Root detected — full firewall management enabled.")

    # Check for iptables availability (informational)
    import subprocess
    try:
        subprocess.run(
            ["iptables", "--version"],
            capture_output=True, check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("  ⚠  WARNING: 'iptables' command not found. "
              "Firewall features will not work.")

    # ── Launch Tk ─────────────────────────────────────────────────────────────
    root = tk.Tk()

    # Try to set a window icon (silently ignore if unavailable)
    try:
        root.tk.call("wm", "iconphoto", root._w, tk.PhotoImage(data=""))
    except Exception:
        pass

    # DPI awareness (useful on HiDPI Linux desktops)
    try:
        root.tk.call("tk", "scaling", 1.0)
    except Exception:
        pass

    app = MainWindow(root)

    def on_close():
        print("FirewallGUI closed.")
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
