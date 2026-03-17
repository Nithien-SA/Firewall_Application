"""
traffic_tab.py
Live network connections table with auto-refresh, filtering,
colour-coded rows, and a right-click context menu.
"""

import tkinter as tk
from tkinter import ttk, messagebox

from gui import theme
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
    "protocol": 60, "local_port": 90, "local_ip": 150,
    "remote_ip": 150, "remote_port": 90, "state": 110,
    "pid": 70, "process": 160,
}


class TrafficTab:
    def __init__(self, parent: ttk.Frame, on_context_action):
        """
        on_context_action(action, value):
            action = "block_ip" | "block_port"
            value  = ip_string  | port_string
        """
        self.parent = parent
        self.on_context_action = on_context_action
        self._connections = []
        self._sort_col = None
        self._sort_rev = False

        parent.configure(style="TFrame")
        self._build_toolbar(parent)
        self._build_table(parent)
        self._build_context_menu()

    # ─── Toolbar ──────────────────────────────────────────────────────────────

    def _build_toolbar(self, parent):
        bar = tk.Frame(parent, bg=theme.BG_DARK, pady=6)
        bar.pack(fill="x", padx=theme.PAD, pady=(theme.PAD, 0))

        tk.Label(
            bar, text="Filter:", bg=theme.BG_DARK,
            fg=theme.TEXT_SECONDARY, font=theme.FONT_NORMAL,
        ).pack(side="left", padx=(0, 6))

        self._filter_var = tk.StringVar()
        self._filter_var.trace_add("write", lambda *_: self._apply_filter())
        filter_entry = ttk.Entry(bar, textvariable=self._filter_var, width=30)
        filter_entry.pack(side="left", padx=(0, 12))

        ttk.Button(
            bar, text="⟳  Refresh Now",
            command=self.refresh, style="Accent.TButton",
        ).pack(side="left", padx=4)

        ttk.Button(
            bar, text="✕  Clear Filter",
            command=lambda: self._filter_var.set(""),
        ).pack(side="left", padx=4)

        self._count_label = tk.Label(
            bar, text="", bg=theme.BG_DARK,
            fg=theme.TEXT_SECONDARY, font=theme.FONT_SMALL,
        )
        self._count_label.pack(side="right", padx=8)

    # ─── Table ────────────────────────────────────────────────────────────────

    def _build_table(self, parent):
        container = ttk.Frame(parent)
        container.pack(fill="both", expand=True, padx=theme.PAD, pady=theme.PAD)

        # Scrollbars
        vsb = ttk.Scrollbar(container, orient="vertical")
        hsb = ttk.Scrollbar(container, orient="horizontal")

        self.tree = ttk.Treeview(
            container,
            columns=COLUMNS,
            show="headings",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
            selectmode="browse",
        )
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        # Headings + columns
        for col in COLUMNS:
            self.tree.heading(
                col, text=COL_LABELS[col],
                command=lambda c=col: self._sort_by(c),
            )
            self.tree.column(col, width=COL_WIDTHS[col], minwidth=50, stretch=False)

        # Row tags for colour-coding
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

        # Bind events
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
        self._ctx_menu.add_command(
            label="🚫  Block this Remote IP",
            command=self._ctx_block_ip,
        )
        self._ctx_menu.add_command(
            label="🔒  Block this Local Port",
            command=self._ctx_block_port,
        )
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(
            label="ℹ️   Connection Details",
            command=self._ctx_show_details,
        )

    def _get_selected_values(self):
        sel = self.tree.selection()
        if not sel:
            return None
        return self.tree.item(sel[0], "values")

    def _on_right_click(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self._ctx_menu.post(event.x_root, event.y_root)

    def _ctx_block_ip(self):
        vals = self._get_selected_values()
        if vals:
            remote_ip = vals[3]  # remote_ip column
            if remote_ip and remote_ip not in ("0.0.0.0", "::", "*", ""):
                self.on_context_action("block_ip", remote_ip)

    def _ctx_block_port(self):
        vals = self._get_selected_values()
        if vals:
            local_port = vals[1]  # local_port column
            proto = vals[0].lower()[:3]
            if local_port and local_port not in ("0", "*", ""):
                self.on_context_action("block_port", str(local_port))

    def _ctx_show_details(self):
        vals = self._get_selected_values()
        if not vals:
            return
        labels = list(COL_LABELS.values())
        detail_lines = "\n".join(
            f"{labels[i]:<15}: {vals[i]}" for i in range(len(vals))
        )
        messagebox.showinfo("Connection Details", detail_lines)

    def _on_double_click(self, event):
        self._ctx_show_details()

    # ─── Sorting ──────────────────────────────────────────────────────────────

    def _sort_by(self, col: str):
        if self._sort_col == col:
            self._sort_rev = not self._sort_rev
        else:
            self._sort_col = col
            self._sort_rev = False
        self._populate(self._connections)

    # ─── Data refresh ─────────────────────────────────────────────────────────

    def refresh(self) -> int:
        """Fetch fresh connection data and repopulate the table. Returns count."""
        conns = get_connections()
        self._connections = conns
        self._apply_filter()
        return len(conns)

    def _apply_filter(self):
        ftext = self._filter_var.get().strip().lower()
        if ftext:
            filtered = [
                c for c in self._connections
                if any(ftext in str(v).lower() for v in (
                    c.protocol, c.local_ip, c.local_port,
                    c.remote_ip, c.remote_port, c.state, c.process_name,
                ))
            ]
        else:
            filtered = list(self._connections)
        self._populate(filtered)

    def _populate(self, conns: list):
        # Sort
        if self._sort_col:
            col_index = list(COL_LABELS.keys()).index(self._sort_col)
            try:
                conns = sorted(
                    conns,
                    key=lambda c: (int(getattr(c, _col_attr(self._sort_col), 0))
                                   if self._sort_col in ("local_port", "remote_port", "pid")
                                   else str(getattr(c, _col_attr(self._sort_col), "")).lower()),
                    reverse=self._sort_rev,
                )
            except Exception:
                pass

        # Repopulate tree
        self.tree.delete(*self.tree.get_children())
        for c in conns:
            pid_str = str(c.pid) if c.pid > 0 else ""
            values = (
                c.protocol, c.local_port, c.local_ip,
                c.remote_ip if c.remote_port else "",
                c.remote_port if c.remote_port else "",
                c.state, pid_str, c.process_name,
            )
            tag = _state_tag(c.state)
            self.tree.insert("", "end", values=values, tags=(tag,))

        visible = len(conns)
        total = len(self._connections)
        self._count_label.configure(
            text=f"Showing {visible} / {total} connections",
        )


def _col_attr(col: str) -> str:
    mapping = {
        "protocol": "protocol", "local_port": "local_port",
        "local_ip": "local_ip", "remote_ip": "remote_ip",
        "remote_port": "remote_port", "state": "state",
        "pid": "pid", "process": "process_name",
    }
    return mapping.get(col, col)


def _state_tag(state: str) -> str:
    s = state.upper()
    if s == "ESTABLISHED":
        return "ESTABLISHED"
    if s == "LISTEN" or s == "0A":
        return "LISTEN"
    if s in ("TIME_WAIT", "FIN_WAIT1", "FIN_WAIT2"):
        return "TIME_WAIT"
    if s in ("UDP", "UDP6"):
        return "UDP"
    return "OTHER"
