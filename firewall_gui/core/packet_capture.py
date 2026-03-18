"""
packet_capture.py
Background tcpdump capture engine.

Key design decisions:
- Uses `-i any -n -nn -l -A` so we get payload ASCII, no name resolution,
  and line-buffered stdout.
- With `-i any`, tcpdump prefixes some lines with "<iface> In/Out" — the
  regex strips this optional prefix.
- Multi-line output (header + payload) is grouped: a new packet starts
  whenever a line matches the unix-timestamp pattern; continuation lines
  (spaces/tabs or hex/ascii dump) are appended to the current packet's
  raw buffer.
- Packets are pushed to the GUI via a callback from the reader thread.
"""

import subprocess
import threading
import re
import time
from dataclasses import dataclass, field


# ─── Data model ───────────────────────────────────────────────────────────────

@dataclass
class Packet:
    number:    int
    timestamp: str
    src_ip:    str
    src_port:  str
    dst_ip:    str
    dst_port:  str
    protocol:  str      # TCP, UDP, ICMP, ARP, IPv6, OTHER
    flags:     str      # TCP flags
    length:    str      # byte count
    info:      str      # decoded header summary
    payload:   str      # ASCII payload (may be empty)
    raw:       str      # complete multi-line raw dump


# ─── Timestamp detection ──────────────────────────────────────────────────────
# Matches "1710123456.789012" or "14:05:09.123456" as first token on a line
_TS_START = re.compile(r"^[\d]+[.:]\d+")

# ─── IP packet regex ─────────────────────────────────────────────────────────
# Handles optional "  ethX In  " or "  ethX Out " prefix inserted by -i any
_RE_IP = re.compile(
    r"(?:^|[\s\t])"
    r"IP(?:v6)?\s+"
    r"(?P<src>[a-fA-F0-9:.[\]%\w]+?)\.(?P<sp>[\w]+)"
    r"\s+>\s+"
    r"(?P<dst>[a-fA-F0-9:.[\]%\w]+?)\.(?P<dp>[\w]+)"
    r":\s+(?P<info>.+)$"
)

# ARP pattern
_RE_ARP = re.compile(r"\bARP,\s*(?P<info>.+)$")

# TCP Flags
_RE_FLAGS = re.compile(r"Flags\s+\[([^\]]*)\]")

# Length field
_RE_LEN = re.compile(r"\blength\s+(\d+)")


def _fmt_ts(raw_ts: str) -> str:
    """Format a unix-epoch timestamp string to HH:MM:SS.usec."""
    try:
        val = float(raw_ts)
        usec = int((val % 1) * 1_000_000)
        return time.strftime("%H:%M:%S", time.localtime(val)) + f".{usec:06d}"
    except ValueError:
        return raw_ts


def _parse_packet(lines: list[str], number: int) -> "Packet | None":
    """Parse a group of tcpdump lines into a Packet."""
    if not lines:
        return None

    first = lines[0]
    raw   = "\n".join(lines)

    # Extract timestamp from first token
    ts_raw = first.split()[0] if first.split() else ""
    ts     = _fmt_ts(ts_raw)

    # Try to find the IP pattern anywhere in the first line
    m = _RE_IP.search(first)
    if m:
        info   = m.group("info").strip()
        flags  = ""
        fm     = _RE_FLAGS.search(info)
        if fm:
            flags = fm.group(1)
        lm     = _RE_LEN.search(info)
        length = lm.group(1) if lm else ""

        # Determine protocol
        proto = "TCP" if flags or "tcp" in first.lower() else \
                "UDP" if "UDP" in first or "udp" in first.lower() else \
                "ICMP" if "ICMP" in first else \
                "IPv6" if "IPv6" in first else "OTHER"

        # Collect payload lines (non-header continuation)
        payload_lines = []
        for line in lines[1:]:
            stripped = line.strip()
            if stripped:
                payload_lines.append(stripped)
        payload = "\n".join(payload_lines)

        return Packet(
            number=number, timestamp=ts,
            src_ip=m.group("src"),  src_port=m.group("sp"),
            dst_ip=m.group("dst"),  dst_port=m.group("dp"),
            protocol=proto, flags=flags, length=length,
            info=info, payload=payload, raw=raw,
        )

    # Try ARP
    ma = _RE_ARP.search(first)
    if ma:
        return Packet(
            number=number, timestamp=ts,
            src_ip="", src_port="", dst_ip="", dst_port="",
            protocol="ARP", flags="", length="",
            info=ma.group("info"), payload="", raw=raw,
        )

    # Fallback: store raw as info
    return Packet(
        number=number, timestamp=ts,
        src_ip="", src_port="", dst_ip="", dst_port="",
        protocol="OTHER", flags="", length="",
        info=first, payload="\n".join(lines[1:]), raw=raw,
    )


# ─── Capture engine ───────────────────────────────────────────────────────────

class PacketCapture:
    """
    Manages a tcpdump subprocess and delivers Packet objects via on_packet().
    Reader thread groups multi-line output and pushes complete packets.
    """

    def __init__(self, on_packet, on_error=None, on_stop=None):
        self.on_packet = on_packet
        self.on_error  = on_error
        self.on_stop   = on_stop
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._count   = 0

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self, filter_expr: str = "", interface: str = "any"):
        """Start capture. Stops any existing session first."""
        self.stop()

        # -A : ASCII payload   -nn : no name resolution (IPs and ports as numbers)
        # -l : line buffered   -tt : unix epoch timestamps (needed for _fmt_ts)
        cmd = ["tcpdump", "-i", interface, "-nn", "-l", "-tt", "-A"]
        if filter_expr.strip():
            # Split and extend (shell-like) — user enters bpf filter tokens
            cmd += filter_expr.strip().split()

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            if self.on_error:
                self.on_error(
                    "tcpdump not found.\n"
                    "Install it with:  sudo apt install tcpdump"
                )
            return
        except PermissionError as e:
            if self.on_error:
                self.on_error(
                    f"Permission denied: {e}\n"
                    "Run as root:  sudo python3 firewall_app.py"
                )
            return

        self._running = True
        self._count   = 0
        self._thread  = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None
        if self.on_stop:
            self.on_stop()

    # ─── Reader (background thread) ───────────────────────────────────────────

    def _reader(self):
        """
        Read stdout line by line.
        Lines starting with a timestamp begin a new packet; other lines
        (indented payload / hex dump) are appended to the current packet.
        """
        current: list[str] = []

        def emit():
            if current:
                self._count += 1
                pkt = _parse_packet(current, self._count)
                if pkt:
                    self.on_packet(pkt)
                current.clear()

        try:
            for line in self._proc.stdout:
                if not self._running:
                    break
                # Strip only the newline, keep leading spaces (payload indent)
                line = line.rstrip("\n")
                if not line:
                    continue

                if _TS_START.match(line):
                    emit()          # flush previous packet
                    current.append(line)
                else:
                    current.append(line)

            emit()  # flush final packet
        except Exception as exc:
            if self._running and self.on_error:
                self.on_error(str(exc))
        finally:
            self._running = False
            if self.on_stop:
                self.on_stop()
