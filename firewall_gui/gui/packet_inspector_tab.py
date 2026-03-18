"""
packet_inspector_tab.py
Wireshark-like live packet capture panel.
Uses tcpdump via core.packet_capture in a background thread.
Packets are queued and pulled into the GUI via root.after().
"""

import tkinter as tk
from tkinter import ttk, messagebox
import queue
import threading

from gui import theme
from core.packet_capture import PacketCapture, Packet
from core.privilege import is_root

# ─── Protocol colour map ──────────────────────────────────────────────────────
PROTO_COLOURS = {
    "TCP":   ("#0d1e30", theme.INFO),       # blue tint
    "UDP":   ("#1a1a0d", "#d4c35a"),        # yellow tint
    "ICMP":  ("#1a0d1a", "#c084fc"),        # purple tint
    "ARP":   ("#1a1f0d", "#86efac"),        # light green
    "IPv6":  ("#0d1e1e", "#67e8f9"),        # teal
    "OTHER": (theme.BG_WIDGET, theme.TEXT_SECONDARY),
}

COLUMNS = ("#", "Time", "Source IP", "Src Port", "Dest IP", "Dst Port",
           "Protocol", "Flags", "Length", "Info")
COL_IDS = ("num", "ts", "src_ip", "src_port", "dst_ip", "dst_port",
           "proto", "flags", "length", "info")
COL_WIDTHS = {
    "num": 45, "ts": 120, "src_ip": 140, "src_port": 75,
    "dst_ip": 140, "dst_port": 75, "proto": 65, "flags": 75,
    "length": 60, "info": 400,
}


class PacketInspectorTab:
    def __init__(self, parent: ttk.Frame, root: tk.Tk):
        self.parent = parent
        self.root   = root
        self._capture = PacketCapture(
            on_packet=self._on_packet,
            on_error=self._on_error,
            on_stop=self._on_stop,
        )
        self._queue: queue.Queue[Packet] = queue.Queue()
        self._packets: list[Packet] = []   # full unfiltered list
        self._poll_job = None
        self._max_packets = 2000           # rolling buffer limit

        parent.configure(style="TFrame")
        self._build_toolbar(parent)
        self._build_table(parent)
        self._build_detail_panel(parent)

        if not is_root():
            self._show_noperm_banner(parent)

    # ─── Permission banner ────────────────────────────────────────────────────

    def _show_noperm_banner(self, parent):
        ban = tk.Frame(parent, bg=theme.WARNING, pady=4)
        ban.pack(fill="x", padx=theme.PAD, pady=(0, 4))
        tk.Label(
            ban,
            text="Packet capture requires root.  Restart as:  sudo python3 firewall_app.py",
            bg=theme.WARNING, fg=theme.BG_DARK, font=theme.FONT_BOLD,
        ).pack()

    # ─── Toolbar ──────────────────────────────────────────────────────────────

    def _build_toolbar(self, parent):
        bar = tk.Frame(parent, bg=theme.BG_DARK)
        bar.pack(fill="x", padx=theme.PAD, pady=(theme.PAD, 0))

        # Interface
        tk.Label(bar, text="Interface:", bg=theme.BG_DARK,
                 fg=theme.TEXT_SECONDARY, font=theme.FONT_NORMAL).pack(side="left", padx=(0, 4))
        self._iface_var = tk.StringVar(value="any")
        ttk.Entry(bar, textvariable=self._iface_var, width=8).pack(side="left", padx=(0, 12))

        # Capture filter
        tk.Label(bar, text="Capture filter:", bg=theme.BG_DARK,
                 fg=theme.TEXT_SECONDARY, font=theme.FONT_NORMAL).pack(side="left", padx=(0, 4))
        self._cap_filter_var = tk.StringVar()
        self._cap_filter_entry = ttk.Entry(bar, textvariable=self._cap_filter_var, width=26)
        self._cap_filter_entry.pack(side="left", padx=(0, 12))

        # Single toggle button: Start Capture / Stop [N pkts]
        self._toggle_btn = ttk.Button(
            bar,
            text="Start Capture",
            command=self._toggle_capture,
            style="Success.TButton",
            state="normal" if is_root() else "disabled",
        )
        self._toggle_btn.pack(side="left", padx=(0, 14))

        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=6)

        # Display filter (like Wireshark's filter bar)
        tk.Label(bar, text="Display filter:", bg=theme.BG_DARK,
                 fg=theme.TEXT_SECONDARY, font=theme.FONT_NORMAL).pack(side="left", padx=(0, 4))
        self._disp_filter_var = tk.StringVar()
        self._disp_filter_var.trace_add("write", lambda *_: self._apply_display_filter())
        ttk.Entry(bar, textvariable=self._disp_filter_var, width=22).pack(side="left", padx=(0, 6))

        proto_label = tk.Label(bar, text="Protocol:", bg=theme.BG_DARK,
                               fg=theme.TEXT_SECONDARY, font=theme.FONT_NORMAL)
        proto_label.pack(side="left", padx=(0, 4))
        self._proto_filter_var = tk.StringVar(value="All")
        proto_cb = ttk.Combobox(
            bar, textvariable=self._proto_filter_var,
            values=["All", "TCP", "UDP", "ICMP", "ARP", "IPv6", "OTHER"],
            state="readonly", width=8,
        )
        proto_cb.pack(side="left", padx=(0, 6))
        proto_cb.bind("<<ComboboxSelected>>", lambda _: self._apply_display_filter())

        ttk.Button(bar, text="Clear", command=self._clear).pack(side="left", padx=4)

    # ─── Packet list table ────────────────────────────────────────────────────

    def _build_table(self, parent):
        container = ttk.Frame(parent)
        container.pack(fill="both", expand=True, padx=theme.PAD, pady=(theme.PAD_SM, 0))

        vsb = ttk.Scrollbar(container, orient="vertical")
        hsb = ttk.Scrollbar(container, orient="horizontal")

        self.tree = ttk.Treeview(
            container, columns=COL_IDS, show="headings",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set,
            selectmode="browse",
        )
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        for col_id, col_label in zip(COL_IDS, COLUMNS):
            self.tree.heading(col_id, text=col_label)
            self.tree.column(
                col_id, width=COL_WIDTHS[col_id], minwidth=40,
                stretch=(col_id == "info"),
            )

        # Configure protocol colour tags
        for proto, (bg, fg) in PROTO_COLOURS.items():
            self.tree.tag_configure(proto, background=bg, foreground=fg)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    # ─── Detail panel ─────────────────────────────────────────────────────────

    def _build_detail_panel(self, parent):
        frame = ttk.LabelFrame(parent, text=" Packet Detail ")
        frame.pack(fill="x", padx=theme.PAD, pady=(theme.PAD_SM, theme.PAD))

        self._detail_text = tk.Text(
            frame, height=6, bg=theme.BG_WIDGET, fg=theme.TEXT_PRIMARY,
            font=theme.FONT_MONO, relief="flat", state="disabled",
            insertbackground=theme.ACCENT, wrap="word",
        )
        vsb = ttk.Scrollbar(frame, command=self._detail_text.yview)
        self._detail_text.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._detail_text.pack(fill="x", padx=(4, 0), pady=4)

    # ─── Capture control ──────────────────────────────────────────────────────

    def _toggle_capture(self):
        if self._capture.is_running:
            self._stop_capture()
        else:
            self._start_capture()

    def _start_capture(self):
        filt  = self._cap_filter_var.get().strip()
        iface = self._iface_var.get().strip() or "any"
        self._packets.clear()
        self.tree.delete(*self.tree.get_children())
        self._detail_clear()
        self._toggle_btn.configure(text="Stop  [starting...]", style="Danger.TButton")
        self._cap_filter_entry.configure(state="disabled")
        self._capture.start(filter_expr=filt, interface=iface)
        self._poll_queue()

    def _stop_capture(self):
        self._capture.stop()
        self._stop_poll()
        n = len(self._packets)
        self._toggle_btn.configure(
            text="Start Capture", style="Success.TButton",
            state="normal" if is_root() else "disabled",
        )
        self._cap_filter_entry.configure(state="normal")

    def _clear(self):
        self._stop_capture()
        self._packets.clear()
        self.tree.delete(*self.tree.get_children())
        self._detail_clear()

    # ─── Queue polling (thread-safe GUI update) ───────────────────────────────

    def _poll_queue(self):
        try:
            batch = []
            for _ in range(50):   # drain up to 50 packets per tick
                batch.append(self._queue.get_nowait())
        except queue.Empty:
            pass

        for pkt in batch:
            self._packets.append(pkt)

        # Rolling buffer
        if len(self._packets) > self._max_packets:
            overflow = len(self._packets) - self._max_packets
            self._packets = self._packets[overflow:]
            self.tree.delete(*self.tree.get_children())
            self._repopulate()

        if batch:
            self._insert_packets(batch)
            n = len(self._packets)
            self._toggle_btn.configure(text=f"Stop  [{n} pkts]")

        if self._capture.is_running:
            self._poll_job = self.root.after(200, self._poll_queue)

    def _stop_poll(self):
        if self._poll_job:
            self.root.after_cancel(self._poll_job)
            self._poll_job = None

    # ─── Packet callbacks (from background thread) ────────────────────────────

    def _on_packet(self, pkt: Packet):
        self._queue.put(pkt)

    def _on_error(self, msg: str):
        def _show():
            messagebox.showerror("Capture Error", msg)
            self._toggle_btn.configure(
                text="Start Capture", style="Success.TButton",
                state="normal" if is_root() else "disabled",
            )
            self._cap_filter_entry.configure(state="normal")
        self.root.after(0, _show)

    def _on_stop(self):
        def _update():
            if not self._capture.is_running:
                self._toggle_btn.configure(
                    text="Start Capture", style="Success.TButton",
                    state="normal" if is_root() else "disabled",
                )
                self._cap_filter_entry.configure(state="normal")
        self.root.after(0, _update)

    # ─── Table helpers ────────────────────────────────────────────────────────

    def _insert_packets(self, pkts: list[Packet]):
        """Insert only packets that pass the current display filter."""
        ftext = self._disp_filter_var.get().strip().lower()
        proto_f = self._proto_filter_var.get()

        for pkt in pkts:
            if not self._packet_passes(pkt, ftext, proto_f):
                continue
            tag = pkt.protocol if pkt.protocol in PROTO_COLOURS else "OTHER"
            self.tree.insert("", "end", tags=(tag,), values=(
                pkt.number, pkt.timestamp,
                pkt.src_ip, pkt.src_port,
                pkt.dst_ip, pkt.dst_port,
                pkt.protocol, pkt.flags, pkt.length,
                pkt.info[:120],
            ))

    def _repopulate(self):
        ftext  = self._disp_filter_var.get().strip().lower()
        proto_f = self._proto_filter_var.get()
        for pkt in self._packets:
            if not self._packet_passes(pkt, ftext, proto_f):
                continue
            tag = pkt.protocol if pkt.protocol in PROTO_COLOURS else "OTHER"
            self.tree.insert("", "end", tags=(tag,), values=(
                pkt.number, pkt.timestamp,
                pkt.src_ip, pkt.src_port,
                pkt.dst_ip, pkt.dst_port,
                pkt.protocol, pkt.flags, pkt.length,
                pkt.info[:120],
            ))

    @staticmethod
    def _packet_passes(pkt: Packet, ftext: str, proto_filter: str) -> bool:
        if proto_filter and proto_filter != "All":
            if pkt.protocol.upper() != proto_filter.upper():
                return False
        if ftext:
            haystack = " ".join([
                pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port,
                pkt.protocol, pkt.flags, pkt.info,
            ]).lower()
            # Support simple AND queries: "tcp 443"
            for term in ftext.split():
                if term not in haystack:
                    return False
        return True

    def _apply_display_filter(self):
        self.tree.delete(*self.tree.get_children())
        self._repopulate()

    # ─── Packet detail ────────────────────────────────────────────────────────

    def _on_select(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        if not vals:
            return
        try:
            num = int(vals[0])
            pkt = next((p for p in self._packets if p.number == num), None)
        except (ValueError, IndexError):
            pkt = None

        self._detail_clear()
        self._detail_text.configure(state="normal")
        if pkt:
            sep  = "-" * 60
            lines = [
                f"Packet #{pkt.number}  —  {pkt.timestamp}",
                sep,
                f"Protocol   : {pkt.protocol}",
                f"Source     : {pkt.src_ip or '—'}  port {pkt.src_port or '—'}",
                f"Destination: {pkt.dst_ip or '—'}  port {pkt.dst_port or '—'}",
            ]
            if pkt.flags:
                lines.append(f"TCP Flags  : [{pkt.flags}]")
            if pkt.length:
                lines.append(f"Length     : {pkt.length} bytes")
            lines += [
                "",
                "--- Header / Info ---",
                pkt.info or "(none)",
                "",
                "--- Raw tcpdump ---",
                pkt.raw or "(none)",
            ]
            if pkt.payload.strip():
                lines += [
                    "",
                    "--- Payload (ASCII) ---",
                    pkt.payload,
                ]
            self._detail_text.insert("end", "\n".join(lines))
        self._detail_text.configure(state="disabled")

    def _detail_clear(self):
        self._detail_text.configure(state="normal")
        self._detail_text.delete("1.0", "end")
        self._detail_text.configure(state="disabled")

    # ─── Called from traffic tab right-click ─────────────────────────────────

    def set_filter_and_start(self, host: str = "", port: str = ""):
        """Pre-fill capture filter from a traffic tab right-click and start capture."""
        parts = []
        if host:
            parts.append(f"host {host}")
        if port:
            parts.append(f"port {port}")
        filt = " and ".join(parts)
        self._cap_filter_var.set(filt)
        if is_root():
            self._start_capture()
        else:
            messagebox.showwarning(
                "Root Required",
                "Packet capture requires root privileges.\n"
                "Restart as:  sudo python3 firewall_app.py",
            )
