"""
packet_capture.py
Background tcpdump capture engine.
Spawns a tcpdump subprocess in a thread and pushes parsed Packet
objects to the GUI via a callback (safe to call from any thread).
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
    protocol:  str      # TCP, UDP, ICMP, ARP, IPv6, other
    flags:     str      # TCP flags if present
    length:    str
    info:      str      # full info portion from tcpdump
    raw:       str      # complete raw line


# ─── Regex patterns ───────────────────────────────────────────────────────────

# IP packet:  14:23:45.123456 IP 1.2.3.4.443 > 5.6.7.8.54321: Flags [S], ...
_RE_IP = re.compile(
    r"^(?P<ts>\d+\.\d+)\s+"
    r"IP(?:v6)?\s+"
    r"(?P<src>[\w:.\[\]]+?)\.(?P<sp>\w+)\s+>\s+"
    r"(?P<dst>[\w:.\[\]]+?)\.(?P<dp>\w+):\s+"
    r"(?P<info>.+)$"
)

# ARP:  14:23:45.123456 ARP, Request who-has ...
_RE_ARP = re.compile(r"^(?P<ts>\d+\.\d+)\s+ARP,\s+(?P<info>.+)$")

# Generic fallback
_RE_GEN = re.compile(r"^(?P<ts>\d+\.\d+)\s+(?P<rest>.+)$")

# TCP Flags extraction from info
_RE_FLAGS = re.compile(r"Flags\s+\[([^\]]*)\]")


def _detect_protocol(line: str, info: str) -> str:
    """Heuristically determine protocol name from a tcpdump line."""
    il = line.lower()
    if " arp," in il or "arp " in il:
        return "ARP"
    if "icmp" in il:
        return "ICMP"
    if "udp" in il or " udp" in info.lower():
        return "UDP"
    if "flags" in info.lower():   # TCP has Flags field
        return "TCP"
    if "ipv6" in il or "ip6 " in il:
        return "IPv6"
    return "OTHER"


def _parse_line(line: str, number: int) -> Packet | None:
    """Parse a single tcpdump output line into a Packet. Returns None if unparseable."""
    line = line.strip()
    if not line or line.startswith("tcpdump") or line.startswith("dropped"):
        return None

    # Try IP pattern
    m = _RE_IP.match(line)
    if m:
        info  = m.group("info")
        flags = ""
        fmatch = _RE_FLAGS.search(info)
        if fmatch:
            flags = fmatch.group(1)
        proto  = _detect_protocol(line, info)
        length = ""
        lm = re.search(r"length\s+(\d+)", info)
        if lm:
            length = lm.group(1)
        ts_raw = float(m.group("ts"))
        ts_str = time.strftime("%H:%M:%S", time.localtime(ts_raw)) + \
                 f".{int((ts_raw % 1) * 1000000):06d}"[0:10]
        return Packet(
            number=number,
            timestamp=ts_str,
            src_ip=m.group("src"),   src_port=m.group("sp"),
            dst_ip=m.group("dst"),   dst_port=m.group("dp"),
            protocol=proto, flags=flags, length=length,
            info=info, raw=line,
        )

    # Try ARP pattern
    m = _RE_ARP.match(line)
    if m:
        ts_raw = float(m.group("ts"))
        ts_str = time.strftime("%H:%M:%S", time.localtime(ts_raw))
        return Packet(
            number=number, timestamp=ts_str,
            src_ip="", src_port="", dst_ip="", dst_port="",
            protocol="ARP", flags="", length="",
            info=m.group("info"), raw=line,
        )

    # Generic fallback
    m = _RE_GEN.match(line)
    if m:
        ts_raw_str = m.group("ts")
        try:
            ts_raw = float(ts_raw_str)
            ts_str = time.strftime("%H:%M:%S", time.localtime(ts_raw))
        except ValueError:
            ts_str = ts_raw_str
        return Packet(
            number=number, timestamp=ts_str,
            src_ip="", src_port="", dst_ip="", dst_port="",
            protocol="OTHER", flags="", length="",
            info=m.group("rest"), raw=line,
        )

    return None


# ─── Capture engine ───────────────────────────────────────────────────────────

class PacketCapture:
    """
    Manages a tcpdump subprocess and pushes packets to on_packet() callback.
    Thread-safe: callbacks are fired from a background thread; the GUI
    should use root.after() or a queue to update widgets safely.
    """

    def __init__(self, on_packet, on_error=None, on_stop=None):
        self.on_packet = on_packet   # callable(Packet)
        self.on_error  = on_error    # callable(str)
        self.on_stop   = on_stop     # callable()
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._count = 0

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self, filter_expr: str = "", interface: str = "any"):
        """Start a new capture. Stops any existing one first."""
        self.stop()

        cmd = ["tcpdump", "-i", interface, "-n", "-l", "-tt"]
        if filter_expr.strip():
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
                self.on_error("tcpdump not found. Install with:  sudo apt install tcpdump")
            return
        except PermissionError:
            if self.on_error:
                self.on_error("Permission denied. Run the app as root:  sudo python3 firewall_app.py")
            return

        self._running = True
        self._count   = 0
        self._thread  = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the running capture."""
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

    def _reader(self):
        """Background thread: read tcpdump stdout line by line."""
        try:
            for line in self._proc.stdout:
                if not self._running:
                    break
                self._count += 1
                pkt = _parse_line(line, self._count)
                if pkt:
                    self.on_packet(pkt)
        except Exception as e:
            if self._running and self.on_error:
                self.on_error(str(e))
        finally:
            self._running = False
            if self.on_stop:
                self.on_stop()
