"""
privilege.py
Detects whether the application is running with root privileges.
"""

import os


def is_root() -> bool:
    """Return True if the current process is running as root (UID 0)."""
    return os.geteuid() == 0


def get_mode_label() -> str:
    """Return a human-readable privilege mode label."""
    return "Administrator" if is_root() else "Read-Only"


def get_mode_color() -> str:
    """Return a colour string representing the privilege level."""
    return "#00e676" if is_root() else "#ff9800"  # green for root, amber for user
