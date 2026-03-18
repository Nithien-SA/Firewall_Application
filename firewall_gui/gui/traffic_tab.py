"""
traffic_tab.py
Live network connections table. Right-click context menu:
  - Block Remote IP     : shows direction dialog -> calls iptables directly
  - Block Local Port    : shows direction dialog -> calls iptables directly
  - Inspect Packets     : sends connection to Packet Inspector tab
  - Connection Details  : info popup
"""

import tkinter as tk
from tkinter import ttk, messagebox

from gui import theme
from gui import dialogs
from core import firewall
from core.traffic import get_connections
from core.privilege import is_root

COLUMNS = (
    "protocol", "local_port", "local_ip",
    "remote_ip", "remote_port", "state", "pid", "process",
)
COL_LABELS = {
    "protocol":    "Proto",
    "local_port":  "Local Port",
    "local_ip":    "Local IP",
    "remote_ip":   "Remote IP",
    "remote_port": "Remote Port",
    "state":       "State",
    "pid":         "PID",
    "process":     "Process",
}
COL_WIDTHS = {
    "protocol": 65, "local_port": 95, "local_ip": 150,
    "remote_ip": 150, "remote_port": 95, "state": 115,
    "pid": 70, "process": 170,
}


class TrafficTab:
    def __init__(self, parent: ttk.Frame, on_context_action, on_block_action=None):
        """
        on_context_action(action, value, direction):
            Called for non-block actions (inspect, pre-fill).
            action = 'inspect_ip'|'inspect_port'
        on_block_action(message):
            Called after a successful immediate block so other tabs refresh.
        """
        self.parent = parent
        self.on_context_action = on_context_action
        self.on_block_action   = on_block_action
        self._connections = []
        self._sort_col = None
        self._sort_rev = False

        parent.configure(style="TFrame")
        self._build_toolbar(parent)
        self._build_table(parent)
        self._build_context_menu()

    # ─── Toolbar ──────────────────────────────────────────────────────────────

    def _build_toolbar(self, parent):
        bar = tk.Frame(parent, bg=theme.BG_DARK)
        bar.pack(fill="x", padx=theme.PAD, pady=(theme.PAD, 4))

        tk.Label(bar, text="Filter:", bg=theme.BG_DARK,
                 fg=theme.TEXT_SECONDARY, font=theme.FONT_NORMAL).pack(side="left", padx=(0, 6))

        self._filter_var = tk.StringVar()
        self._filter_var.trace_add("write", lambda *_: self._apply_filter())
        ttk.Entry(bar, textvariable=self._filter_var, width=30).pack(side="left", padx=(0, 10))

        ttk.Button(bar, text="Refresh Now",
                   command=self.refresh, style="Accent.TButton").pack(side="left", padx=(0, 6))
        ttk.Button(bar, text="Clear Filter",
                   command=lambda: self._filter_var.set("")).pack(side="left")

        self._count_label = tk.Label(bar, text="", bg=theme.BG_DARK,
                                     fg=theme.TEXT_SECONDARY, font=theme.FONT_SMALL)
        self._count_label.pack(side="right", padx=8)

    # ─── Table ────────────────────────────────────────────────────────────────

    def _build_table(self, parent):
        container = ttk.Frame(parent)
        container.pack(fill="both", expand=True, padx=theme.PAD, pady=(0, theme.PAD))

        vsb = ttk.Scrollbar(container, orient="vertical")
        hsb = ttk.Scrollbar(container, orient="horizontal")

        self.tree = ttk.Treeview(
            container, columns=COLUMNS, show="headings",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set,
            selectmode="browse",
        )
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        for col in COLUMNS:
            self.tree.heading(col, text=COL_LABELS[col],
                              command=lambda c=col: self._sort_by(c))
            self.tree.column(col, width=COL_WIDTHS[col], minwidth=50, stretch=False)

        self.tree.tag_configure("ESTABLISHED", background=theme.ROW_ESTABLISHED)
        self.tree.tag_configure("LISTEN",      background=theme.ROW_LISTEN)
        self.tree.tag_configure("TIME_WAIT",   background=theme.ROW_TIMEWAIT)
        self.tree.tag_configure("UDP",         background=theme.BG_WIDGET)
        self.tree.tag_configure("OTHER",       background=theme.BG_WIDGET)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<Double-1>", self._on_double_click)

    # ─── Context menu ─────────────────────────────────────────────────────────

    def _build_context_menu(self):
        self._ctx_menu = tk.Menu(
            self.parent, tearoff=0,
            bg=theme.BG_PANEL, fg=theme.TEXT_PRIMARY,
            activebackground=theme.ACCENT_DARK, activeforeground=theme.TEXT_PRIMARY,
            font=theme.FONT_NORMAL, bd=0,
        )
        self._ctx_menu.add_command(label="Block Remote IP ...",    command=self._ctx_block_ip)
        self._ctx_menu.add_command(label="Block Local Port ...",   command=self._ctx_block_port)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="Inspect Packets",        command=self._ctx_inspect)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="Connection Details",     command=self._ctx_show_details)

    def _get_selected(self):
        sel = self.tree.selection()
        return self.tree.item(sel[0], "values") if sel else None

    def _on_right_click(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self._ctx_menu.post(event.x_root, event.y_root)

    # ─── Block IP ─────────────────────────────────────────────────────────────

    def _ctx_block_ip(self):
        vals = self._get_selected()
        if not vals:
            return
        remote_ip = str(vals[3]).strip()
        if not remote_ip or remote_ip in ("0.0.0.0", "::", "*", ""):
            messagebox.showinfo("No Remote IP",
                                "This connection has no remote IP to block.")
            return

        direction = dialogs.ask_block_direction(self.tree, label="IP", value=remote_ip)
        if direction is None:
            return

        if not is_root():
            messagebox.showerror("Root Required",
                                 "Blocking requires root.\n"
                                 "Restart as:  sudo python3 firewall_app.py")
            return

        try:
            success, msg = firewall.block_ip(remote_ip, direction)
            if success:
                messagebox.showinfo("Blocked", msg)
                if self.on_block_action:
                    self.on_block_action(msg)
            else:
                messagebox.showerror("Block Failed", msg)
        except PermissionError as e:
            messagebox.showerror("Permission Denied", str(e))

    # ─── Block Port ───────────────────────────────────────────────────────────

    def _ctx_block_port(self):
        vals = self._get_selected()
        if not vals:
            return
        local_port = str(vals[1]).strip()
        if not local_port or local_port in ("0", "*", ""):
            messagebox.showinfo("No Port", "This connection has no local port to block.")
            return

        direction = dialogs.ask_block_direction(self.tree, label="Port", value=local_port)
        if direction is None:
            return

        if not is_root():
            messagebox.showerror("Root Required",
                                 "Blocking requires root.\n"
                                 "Restart as:  sudo python3 firewall_app.py")
            return

        try:
            # Attempt both TCP and UDP for the port
            success, msg = firewall.block_port(int(local_port), "both", direction)
            if success:
                messagebox.showinfo("Blocked", msg)
                if self.on_block_action:
                    self.on_block_action(msg)
            else:
                messagebox.showerror("Block Failed", msg)
        except (PermissionError, ValueError) as e:
            messagebox.showerror("Error", str(e))

    # ─── Inspect Packets ──────────────────────────────────────────────────────

    def _ctx_inspect(self):
        vals = self._get_selected()
        if not vals:
            return
        remote_ip   = str(vals[3]).strip()
        local_port  = str(vals[1]).strip()
        # Sanitise
        host = remote_ip  if remote_ip not in ("0.0.0.0", "::", "*", "")  else ""
        port = local_port if local_port not in ("0", "*", "")              else ""
        self.on_context_action("inspect", host, port)

    # ─── Connection Details ───────────────────────────────────────────────────

    def _ctx_show_details(self):
        vals = self._get_selected()
        if not vals:
            return
        labels = list(COL_LABELS.values())
        lines  = "\n".join(f"{labels[i]:<15}: {vals[i]}" for i in range(len(vals)))
        messagebox.showinfo("Connection Details", lines)

    def _on_double_click(self, _event):
        self._ctx_show_details()

    # ─── Sorting ──────────────────────────────────────────────────────────────

    def _sort_by(self, col: str):
        self._sort_rev = not self._sort_rev if self._sort_col == col else False
        self._sort_col = col
        self._populate(self._connections)

    # ─── Data refresh ─────────────────────────────────────────────────────────

    def refresh(self) -> int:
        conns = get_connections()
        self._connections = conns
        self._apply_filter()
        return len(conns)

    def _apply_filter(self):
        ftext = self._filter_var.get().strip().lower()
        filtered = [
            c for c in self._connections
            if not ftext or any(ftext in str(v).lower() for v in (
                c.protocol, c.local_ip, c.local_port,
                c.remote_ip, c.remote_port, c.state, c.process_name,
            ))
        ]
        self._populate(filtered)

    def _populate(self, conns: list):
        if self._sort_col:
            attr = _col_attr(self._sort_col)
            try:
                conns = sorted(
                    conns,
                    key=lambda c: (
                        int(getattr(c, attr, 0))
                        if self._sort_col in ("local_port", "remote_port", "pid")
                        else str(getattr(c, attr, "")).lower()
                    ),
                    reverse=self._sort_rev,
                )
            except Exception:
                pass

        self.tree.delete(*self.tree.get_children())
        for c in conns:
            pid_str = str(c.pid) if c.pid > 0 else ""
            values  = (
                c.protocol, c.local_port, c.local_ip,
                c.remote_ip   if c.remote_port else "",
                c.remote_port if c.remote_port else "",
                c.state, pid_str, c.process_name,
            )
            self.tree.insert("", "end", values=values, tags=(_state_tag(c.state),))

        self._count_label.configure(
            text=f"Showing {len(conns)} / {len(self._connections)} connections",
        )


def _col_attr(col: str) -> str:
    return {
        "protocol": "protocol", "local_port": "local_port", "local_ip": "local_ip",
        "remote_ip": "remote_ip", "remote_port": "remote_port", "state": "state",
        "pid": "pid", "process": "process_name",
    }.get(col, col)


def _state_tag(state: str) -> str:
    s = state.upper()
    if s == "ESTABLISHED":                              return "ESTABLISHED"
    if s in ("LISTEN", "0A"):                           return "LISTEN"
    if s in ("TIME_WAIT", "FIN_WAIT1", "FIN_WAIT2"):   return "TIME_WAIT"
    if s in ("UDP", "UDP6"):                            return "UDP"
    return "OTHER"
