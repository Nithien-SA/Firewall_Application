"""
rules_tab.py
Displays current iptables chain rules.
Sudo users can delete individual rules or flush the chain.
All emoji removed for Linux Tk compatibility.
"""

import tkinter as tk
from tkinter import ttk, messagebox

from gui import theme
from gui import dialogs
from core import firewall
from core.privilege import is_root

COLUMNS = ("line", "target", "protocol", "source", "destination", "options")
COL_LABELS = {
    "line": "#", "target": "Target", "protocol": "Protocol",
    "source": "Source", "destination": "Destination", "options": "Options / Match",
}
COL_WIDTHS = {
    "line": 45, "target": 90, "protocol": 80,
    "source": 160, "destination": 160, "options": 320,
}


class RulesTab:
    def __init__(self, parent: ttk.Frame, on_action=None):
        self.parent = parent
        self._root = is_root()
        self._chain_var = tk.StringVar(value="INPUT")
        self._rules = []
        self._on_action = on_action

        parent.configure(style="TFrame")
        self._build_toolbar(parent)
        self._build_table(parent)
        self._build_action_bar(parent)
        self.refresh()

    # ─── Toolbar ──────────────────────────────────────────────────────────────

    def _build_toolbar(self, parent):
        bar = tk.Frame(parent, bg=theme.BG_DARK)
        bar.pack(fill="x", padx=theme.PAD, pady=(theme.PAD, 4))

        tk.Label(
            bar, text="Chain:",
            bg=theme.BG_DARK, fg=theme.TEXT_SECONDARY,
            font=theme.FONT_NORMAL,
        ).pack(side="left", padx=(0, 6))

        chain_combo = ttk.Combobox(
            bar, textvariable=self._chain_var,
            values=["INPUT", "OUTPUT", "FORWARD"],
            state="readonly", width=12,
        )
        chain_combo.pack(side="left", padx=(0, 10))
        chain_combo.bind("<<ComboboxSelected>>", lambda _: self.refresh())

        ttk.Button(
            bar, text="Refresh",
            command=self.refresh, style="Accent.TButton",
        ).pack(side="left", padx=(0, 6))

        self._status_label = tk.Label(
            bar, text="",
            bg=theme.BG_DARK, fg=theme.TEXT_SECONDARY,
            font=theme.FONT_SMALL,
        )
        self._status_label.pack(side="right", padx=8)

    # ─── Table ────────────────────────────────────────────────────────────────

    def _build_table(self, parent):
        container = ttk.Frame(parent)
        container.pack(fill="both", expand=True, padx=theme.PAD, pady=0)

        vsb = ttk.Scrollbar(container, orient="vertical")
        self.tree = ttk.Treeview(
            container,
            columns=COLUMNS,
            show="headings",
            yscrollcommand=vsb.set,
            selectmode="browse",
        )
        vsb.config(command=self.tree.yview)

        for col in COLUMNS:
            self.tree.heading(col, text=COL_LABELS[col])
            self.tree.column(
                col, width=COL_WIDTHS[col], minwidth=40,
                stretch=(col == "options"),
            )

        self.tree.tag_configure("DROP",   background=theme.ROW_DROP,   foreground=theme.DANGER)
        self.tree.tag_configure("ACCEPT", background=theme.ROW_ACCEPT,  foreground=theme.SUCCESS)
        self.tree.tag_configure("LOG",    background=theme.BG_WIDGET,   foreground=theme.WARNING)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

    # ─── Action bar ───────────────────────────────────────────────────────────

    def _build_action_bar(self, parent):
        # Buttons row
        btn_bar = tk.Frame(parent, bg=theme.BG_DARK)
        btn_bar.pack(fill="x", padx=theme.PAD, pady=(theme.PAD_SM, 4))

        state = "normal" if self._root else "disabled"

        if self._root:
            del_label   = "Delete Selected Rule"
            flush_label = "Flush All Rules"
        else:
            del_label   = "Delete Selected Rule  (requires sudo)"
            flush_label = "Flush All Rules  (requires sudo)"

        self._delete_btn = ttk.Button(
            btn_bar, text=del_label,
            command=self._delete_selected,
            style="Danger.TButton", state=state,
        )
        self._delete_btn.pack(side="left", padx=(0, 8))

        self._flush_btn = ttk.Button(
            btn_bar, text=flush_label,
            command=self._flush_chain,
            style="Danger.TButton", state=state,
        )
        self._flush_btn.pack(side="left")

        if not self._root:
            tk.Label(
                btn_bar,
                text="Read-only mode -- restart with:  sudo python3 firewall_app.py",
                bg=theme.BG_DARK, fg=theme.WARNING, font=theme.FONT_SMALL,
            ).pack(side="right", padx=8)

        # Command output log
        log_frame = ttk.LabelFrame(parent, text=" Last Command Output ")
        log_frame.pack(fill="x", padx=theme.PAD, pady=(0, theme.PAD))

        self._log_text = tk.Text(
            log_frame,
            height=3, bg=theme.BG_WIDGET, fg=theme.TEXT_PRIMARY,
            font=theme.FONT_MONO, relief="flat", state="disabled",
            insertbackground=theme.ACCENT,
        )
        self._log_text.pack(fill="x", padx=4, pady=4)

    # ─── Refresh ──────────────────────────────────────────────────────────────

    def refresh(self):
        chain = self._chain_var.get()
        ok, rules, err = firewall.get_rules(chain)
        self._rules = rules

        self.tree.delete(*self.tree.get_children())

        if not ok:
            self._status_label.configure(text=f"Error: {err}", fg=theme.DANGER)
            return

        for rule in rules:
            tag = rule.target.upper() if rule.target.upper() in ("DROP", "ACCEPT", "LOG") else ""
            self.tree.insert("", "end", values=(
                rule.line_num, rule.target, rule.protocol,
                rule.source, rule.destination, rule.options,
            ), tags=(tag,) if tag else ())

        self._status_label.configure(
            text=f"{len(rules)} rule(s) in {chain}",
            fg=theme.TEXT_SECONDARY,
        )

    # ─── Actions ──────────────────────────────────────────────────────────────

    def _log(self, msg: str, ok: bool = True):
        color = theme.SUCCESS if ok else theme.DANGER
        self._log_text.configure(state="normal", fg=color)
        self._log_text.delete("1.0", "end")
        self._log_text.insert("end", msg)
        self._log_text.configure(state="disabled")

    def _delete_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Please select a rule to delete.")
            return
        vals = self.tree.item(sel[0], "values")
        line_num = int(vals[0])
        chain    = self._chain_var.get()

        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Delete rule #{line_num} from the {chain} chain?\n\n"
            f"  Target:      {vals[1]}\n"
            f"  Protocol:    {vals[2]}\n"
            f"  Source:      {vals[3]}\n"
            f"  Destination: {vals[4]}",
        )
        if not confirm:
            return

        ok, msg = firewall.delete_rule_by_line(chain, line_num)
        self._log(msg, ok)
        if ok:
            self.refresh()
            if self._on_action:
                self._on_action(msg)

    def _flush_chain(self):
        # 1. Ask which chain(s) to flush
        chain_choice = dialogs.ask_chain(self.parent, verb="Flush")
        if chain_choice is None:
            return

        # 2. Build list of chains to flush
        if chain_choice == "BOTH":
            chains = ["INPUT", "OUTPUT"]
        else:
            chains = [chain_choice]

        # 3. Confirm
        chain_str = " + ".join(chains)
        confirm = messagebox.askyesno(
            "Confirm Flush",
            f"Delete ALL rules from: {chain_str}?\n\nThis cannot be undone.",
            icon="warning",
        )
        if not confirm:
            return

        # 4. Execute flush(es)
        messages = []
        any_ok = False
        for ch in chains:
            ok, msg = firewall.flush_chain(ch)
            messages.append(msg)
            if ok:
                any_ok = True

        combined = "\n".join(messages)
        self._log(combined, any_ok)

        if any_ok:
            # Refresh the currently viewed chain
            self.refresh()
            if self._on_action:
                self._on_action(combined)
