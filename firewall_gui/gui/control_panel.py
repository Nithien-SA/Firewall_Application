"""
control_panel.py
GUI forms for blocking/allowing IPs and ports.
All write actions are disabled in non-root mode.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import re

from gui import theme
from core import firewall
from core.privilege import is_root


def _validate_port(value: str) -> tuple[bool, str]:
    try:
        p = int(value.strip())
        if 1 <= p <= 65535:
            return True, ""
        return False, f"Port must be between 1 and 65535 (got {p})."
    except ValueError:
        return False, f"'{value}' is not a valid port number."


def _validate_ip(value: str) -> tuple[bool, str]:
    # Accept plain IP or CIDR
    ip = value.strip()
    cidr_match = re.match(
        r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$", ip
    )
    if cidr_match:
        return True, ""
    # IPv6 rough check
    if ":" in ip:
        return True, ""
    return False, f"'{ip}' is not a valid IPv4/CIDR or IPv6 address."


class ControlPanel:
    def __init__(self, parent: ttk.Frame, on_action=None):
        """
        on_action(message): called after any firewall action (for cross-tab refresh).
        """
        self.parent = parent
        self.on_action = on_action
        self._root = is_root()
        self._disabled_tip = "  🔒 Requires sudo"

        parent.configure(style="TFrame")

        # Top section: two side-by-side LabelFrames
        top = tk.Frame(parent, bg=theme.BG_DARK)
        top.pack(fill="x", padx=theme.PAD, pady=theme.PAD)
        top.columnconfigure(0, weight=1)
        top.columnconfigure(1, weight=1)

        self._build_port_panel(top)
        self._build_ip_panel(top)
        self._build_output_log(parent)

        if not self._root:
            self._build_readonly_banner(parent)

    # ─── Port panel ───────────────────────────────────────────────────────────

    def _build_port_panel(self, parent):
        frame = ttk.LabelFrame(parent, text=" Block / Allow Port ")
        frame.grid(row=0, column=0, sticky="nsew", padx=(0, theme.PAD_SM), pady=0)
        frame.columnconfigure(1, weight=1)

        row = 0

        def lbl(text, r):
            tk.Label(
                frame, text=text, bg=theme.BG_PANEL,
                fg=theme.TEXT_SECONDARY, font=theme.FONT_NORMAL,
                anchor="w",
            ).grid(row=r, column=0, sticky="w", padx=(12, 8), pady=6)

        # Port entry
        lbl("Port number:", row)
        self._port_var = tk.StringVar()
        self._port_entry = ttk.Entry(frame, textvariable=self._port_var, width=16)
        self._port_entry.grid(row=row, column=1, sticky="ew", padx=(0, 12), pady=6)
        row += 1

        # Protocol
        lbl("Protocol:", row)
        self._proto_var = tk.StringVar(value="TCP")
        proto_combo = ttk.Combobox(
            frame, textvariable=self._proto_var,
            values=["TCP", "UDP", "Both"], state="readonly", width=10,
        )
        proto_combo.grid(row=row, column=1, sticky="w", padx=(0, 12), pady=6)
        row += 1

        # Buttons
        btn_frame = tk.Frame(frame, bg=theme.BG_PANEL)
        btn_frame.grid(row=row, column=0, columnspan=2, pady=(8, 12), padx=12)

        state = "normal" if self._root else "disabled"

        self._block_port_btn = ttk.Button(
            btn_frame, text="🚫  Block Port",
            command=self._do_block_port,
            style="Danger.TButton", state=state,
        )
        self._block_port_btn.pack(side="left", padx=(0, 8))

        self._allow_port_btn = ttk.Button(
            btn_frame, text="✅  Allow Port",
            command=self._do_allow_port,
            style="Success.TButton", state=state,
        )
        self._allow_port_btn.pack(side="left", padx=(0, 8))

        self._unblock_port_btn = ttk.Button(
            btn_frame, text="❌  Remove Block",
            command=self._do_unblock_port,
            state=state,
        )
        self._unblock_port_btn.pack(side="left")

    # ─── IP panel ─────────────────────────────────────────────────────────────

    def _build_ip_panel(self, parent):
        frame = ttk.LabelFrame(parent, text=" Block / Allow IP Address ")
        frame.grid(row=0, column=1, sticky="nsew", padx=(theme.PAD_SM, 0), pady=0)
        frame.columnconfigure(1, weight=1)

        row = 0

        def lbl(text, r):
            tk.Label(
                frame, text=text, bg=theme.BG_PANEL,
                fg=theme.TEXT_SECONDARY, font=theme.FONT_NORMAL,
                anchor="w",
            ).grid(row=r, column=0, sticky="w", padx=(12, 8), pady=6)

        # IP entry
        lbl("IP / CIDR:", row)
        self._ip_var = tk.StringVar()
        self._ip_entry = ttk.Entry(frame, textvariable=self._ip_var, width=22)
        self._ip_entry.grid(row=row, column=1, sticky="ew", padx=(0, 12), pady=6)
        row += 1

        # Direction
        lbl("Direction:", row)
        self._direction_var = tk.StringVar(value="INPUT")
        dir_combo = ttk.Combobox(
            frame, textvariable=self._direction_var,
            values=["INPUT", "OUTPUT"], state="readonly", width=10,
        )
        dir_combo.grid(row=row, column=1, sticky="w", padx=(0, 12), pady=6)
        row += 1

        # Buttons
        btn_frame = tk.Frame(frame, bg=theme.BG_PANEL)
        btn_frame.grid(row=row, column=0, columnspan=2, pady=(8, 12), padx=12)

        state = "normal" if self._root else "disabled"

        self._block_ip_btn = ttk.Button(
            btn_frame, text="🚫  Block IP",
            command=self._do_block_ip,
            style="Danger.TButton", state=state,
        )
        self._block_ip_btn.pack(side="left", padx=(0, 8))

        self._allow_ip_btn = ttk.Button(
            btn_frame, text="✅  Allow IP",
            command=self._do_allow_ip,
            style="Success.TButton", state=state,
        )
        self._allow_ip_btn.pack(side="left", padx=(0, 8))

        self._unblock_ip_btn = ttk.Button(
            btn_frame, text="❌  Remove Block",
            command=self._do_unblock_ip,
            state=state,
        )
        self._unblock_ip_btn.pack(side="left")

    # ─── Output log ───────────────────────────────────────────────────────────

    def _build_output_log(self, parent):
        log_frame = ttk.LabelFrame(parent, text=" Command Output ")
        log_frame.pack(fill="both", expand=True, padx=theme.PAD, pady=(theme.PAD_SM, theme.PAD))

        self._log_text = tk.Text(
            log_frame,
            bg=theme.BG_WIDGET, fg=theme.TEXT_PRIMARY,
            font=theme.FONT_MONO, relief="flat",
            insertbackground=theme.ACCENT, state="disabled",
        )
        self._log_text.pack(fill="both", expand=True, padx=4, pady=4)

        scroll = ttk.Scrollbar(log_frame, command=self._log_text.yview)
        self._log_text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")

    def _build_readonly_banner(self, parent):
        banner = tk.Frame(parent, bg=theme.WARNING, pady=6)
        banner.pack(fill="x", padx=theme.PAD, pady=(0, theme.PAD))
        tk.Label(
            banner,
            text="🔒  Read-Only Mode — All firewall actions are disabled.\n"
                 "Restart the application with:  sudo python3 firewall_app.py",
            bg=theme.WARNING, fg=theme.BG_DARK, font=theme.FONT_BOLD,
        ).pack()

    # ─── Log helper ───────────────────────────────────────────────────────────

    def _log(self, msg: str, ok: bool = True):
        color = theme.SUCCESS if ok else theme.DANGER
        self._log_text.configure(state="normal")
        import datetime
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self._log_text.insert("end", f"[{timestamp}] {'✓' if ok else '✗'}  {msg}\n")
        self._log_text.see("end")
        self._log_text.configure(state="disabled")
        if self.on_action:
            self.on_action(msg)

    # ─── Port actions ─────────────────────────────────────────────────────────

    def _get_port(self) -> tuple[bool, int]:
        ok, err = _validate_port(self._port_var.get())
        if not ok:
            messagebox.showerror("Invalid Port", err)
            return False, 0
        return True, int(self._port_var.get().strip())

    def _do_block_port(self):
        ok, port = self._get_port()
        if not ok:
            return
        proto = self._proto_var.get().lower()
        try:
            success, msg = firewall.block_port(port, proto)
            self._log(msg, success)
        except PermissionError as e:
            messagebox.showerror("Permission Denied", str(e))

    def _do_allow_port(self):
        ok, port = self._get_port()
        if not ok:
            return
        proto = self._proto_var.get().lower()
        try:
            success, msg = firewall.allow_port(port, proto)
            self._log(msg, success)
        except PermissionError as e:
            messagebox.showerror("Permission Denied", str(e))

    def _do_unblock_port(self):
        ok, port = self._get_port()
        if not ok:
            return
        proto = self._proto_var.get().lower()
        try:
            success, msg = firewall.unblock_port(port, proto)
            self._log(msg, success)
        except PermissionError as e:
            messagebox.showerror("Permission Denied", str(e))

    # ─── IP actions ───────────────────────────────────────────────────────────

    def _get_ip(self) -> tuple[bool, str]:
        ok, err = _validate_ip(self._ip_var.get())
        if not ok:
            messagebox.showerror("Invalid IP", err)
            return False, ""
        return True, self._ip_var.get().strip()

    def _do_block_ip(self):
        ok, ip = self._get_ip()
        if not ok:
            return
        direction = self._direction_var.get()
        try:
            success, msg = firewall.block_ip(ip, direction)
            self._log(msg, success)
        except PermissionError as e:
            messagebox.showerror("Permission Denied", str(e))

    def _do_allow_ip(self):
        ok, ip = self._get_ip()
        if not ok:
            return
        direction = self._direction_var.get()
        try:
            success, msg = firewall.allow_ip(ip, direction)
            self._log(msg, success)
        except PermissionError as e:
            messagebox.showerror("Permission Denied", str(e))

    def _do_unblock_ip(self):
        ok, ip = self._get_ip()
        if not ok:
            return
        direction = self._direction_var.get()
        try:
            success, msg = firewall.unblock_ip(ip, direction)
            self._log(msg, success)
        except PermissionError as e:
            messagebox.showerror("Permission Denied", str(e))

    # ─── Pre-fill (called from traffic tab context menu) ──────────────────────

    def prefill(self, action: str, value: str):
        """Pre-fill the appropriate form field from a right-click action."""
        if action == "block_ip":
            self._ip_var.set(value)
            self._ip_entry.focus_set()
            self._log(f"Pre-filled IP: {value}  (from Traffic Monitor right-click)", ok=True)
        elif action == "block_port":
            self._port_var.set(value)
            self._port_entry.focus_set()
            self._log(f"Pre-filled Port: {value}  (from Traffic Monitor right-click)", ok=True)
