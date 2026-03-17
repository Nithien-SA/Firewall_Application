"""
traffic.py
Reads live network connections from /proc/net/* and supplements with
`ss -tunap` for process name resolution.
"""

import subprocess
import socket
import struct
import os
import re
from collections import namedtuple

Connection = namedtuple(
    "Connection",
    ["protocol", "local_ip", "local_port", "remote_ip", "remote_port",
     "state", "pid", "process_name"]
)

# TCP state map (hex code → human label)
TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT",  "03": "SYN_RECV",
    "04": "FIN_WAIT1",   "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE",       "08": "CLOSE_WAIT","09": "LAST_ACK",
    "0A": "LISTEN",      "0B": "CLOSING",   "0C": "NEW_SYN_RECV",
}


def _hex_to_ip(hex_str: str) -> str:
    """Convert a little-endian hex IP string to dotted-decimal notation."""
    try:
        addr = int(hex_str, 16)
        return socket.inet_ntoa(struct.pack("<I", addr))
    except Exception:
        return hex_str


def _hex_to_ip6(hex_str: str) -> str:
    """Convert a little-endian 128-bit hex string to IPv6 notation."""
    try:
        parts = [hex_str[i:i+8] for i in range(0, 32, 8)]
        packed = b"".join(struct.pack("<I", int(p, 16)) for p in parts)
        return socket.inet_ntop(socket.AF_INET6, packed)
    except Exception:
        return hex_str


def _hex_to_port(hex_str: str) -> int:
    return int(hex_str, 16)


def _build_inode_to_pid() -> dict:
    """Map socket inodes → (pid, process_name) by scanning /proc/*/fd."""
    mapping = {}
    try:
        for pid_str in os.listdir("/proc"):
            if not pid_str.isdigit():
                continue
            pid = int(pid_str)
            fd_dir = f"/proc/{pid}/fd"
            try:
                for fd in os.listdir(fd_dir):
                    link_path = os.path.join(fd_dir, fd)
                    try:
                        target = os.readlink(link_path)
                        m = re.match(r"socket:\[(\d+)\]", target)
                        if m:
                            inode = int(m.group(1))
                            # get process name
                            comm_file = f"/proc/{pid}/comm"
                            try:
                                with open(comm_file) as f:
                                    name = f.read().strip()
                            except Exception:
                                name = "unknown"
                            mapping[inode] = (pid, name)
                    except OSError:
                        pass
            except OSError:
                pass
    except Exception:
        pass
    return mapping


def _parse_proc_net(path: str, proto: str, is_ipv6: bool,
                    inode_map: dict, is_udp: bool = False) -> list:
    connections = []
    try:
        with open(path) as f:
            lines = f.readlines()[1:]  # skip header
    except FileNotFoundError:
        return connections

    for line in lines:
        parts = line.split()
        if len(parts) < 10:
            continue

        local_raw, remote_raw = parts[1], parts[2]
        state_hex = parts[3]
        inode = int(parts[9])

        if is_ipv6:
            l_ip_hex, l_port_hex = local_raw.rsplit(":", 1)
            r_ip_hex, r_port_hex = remote_raw.rsplit(":", 1)
            local_ip = _hex_to_ip6(l_ip_hex)
            remote_ip = _hex_to_ip6(r_ip_hex)
        else:
            l_ip_hex, l_port_hex = local_raw.split(":")
            r_ip_hex, r_port_hex = remote_raw.split(":")
            local_ip = _hex_to_ip(l_ip_hex)
            remote_ip = _hex_to_ip(r_ip_hex)

        local_port = _hex_to_port(l_port_hex)
        remote_port = _hex_to_port(r_port_hex)

        if is_udp:
            state = "UDP"
        else:
            state = TCP_STATES.get(state_hex.upper(), state_hex)

        pid, pname = inode_map.get(inode, (-1, ""))

        connections.append(Connection(
            protocol=proto,
            local_ip=local_ip,
            local_port=local_port,
            remote_ip=remote_ip,
            remote_port=remote_port,
            state=state,
            pid=pid,
            process_name=pname,
        ))
    return connections


def _parse_ss_output() -> list:
    """
    Supplementary: use `ss -tunap` for a quick connection list.
    Returns list of Connection namedtuples. Used when /proc parsing is limited.
    """
    connections = []
    try:
        result = subprocess.run(
            ["ss", "-tunap"],
            capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().splitlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0].lower()
            state = parts[1] if proto.startswith("tcp") else "UDP"
            local_str = parts[4]
            remote_str = parts[5] if len(parts) > 5 else "*:*"

            def split_addr(s):
                if s.startswith("["):  # IPv6
                    bracket_end = s.rfind("]")
                    ip = s[1:bracket_end]
                    port_str = s[bracket_end+2:] if bracket_end+1 < len(s) else "0"
                else:
                    if ":" in s:
                        ip, port_str = s.rsplit(":", 1)
                    else:
                        ip, port_str = s, "0"
                try:
                    port = int(port_str)
                except ValueError:
                    port = 0
                return ip, port

            local_ip, local_port = split_addr(local_str)
            remote_ip, remote_port = split_addr(remote_str)

            # Extract pid/process from users:(("nginx",pid=1234,fd=5))
            pid, pname = -1, ""
            if len(parts) > 6:
                user_field = " ".join(parts[6:])
                m = re.search(r'\("([^"]+)",pid=(\d+)', user_field)
                if m:
                    pname = m.group(1)
                    pid = int(m.group(2))

            connections.append(Connection(
                protocol=proto, local_ip=local_ip, local_port=local_port,
                remote_ip=remote_ip, remote_port=remote_port,
                state=state, pid=pid, process_name=pname,
            ))
    except Exception:
        pass
    return connections


def get_connections() -> list:
    """
    Return a deduplicated list of all active network connections.
    Combines /proc/net/* parsing with `ss` output for best coverage.
    """
    inode_map = _build_inode_to_pid()

    proc_conns = []
    proc_conns += _parse_proc_net("/proc/net/tcp",  "TCP",  False, inode_map)
    proc_conns += _parse_proc_net("/proc/net/tcp6", "TCP6", True,  inode_map)
    proc_conns += _parse_proc_net("/proc/net/udp",  "UDP",  False, inode_map, is_udp=True)
    proc_conns += _parse_proc_net("/proc/net/udp6", "UDP6", True,  inode_map, is_udp=True)

    # Use ss for process names where /proc gave empty names
    ss_conns = _parse_ss_output()
    ss_map = {(c.local_port, c.remote_port, c.protocol.lower()[:3]): c for c in ss_conns}

    enriched = []
    for c in proc_conns:
        key = (c.local_port, c.remote_port, c.protocol.lower()[:3])
        if (not c.process_name) and key in ss_map:
            ss = ss_map[key]
            c = c._replace(process_name=ss.process_name, pid=ss.pid)
        enriched.append(c)

    # Add any from ss not already in proc
    proc_keys = {(c.local_port, c.remote_port) for c in enriched}
    for c in ss_conns:
        if (c.local_port, c.remote_port) not in proc_keys:
            enriched.append(c)

    return enriched
