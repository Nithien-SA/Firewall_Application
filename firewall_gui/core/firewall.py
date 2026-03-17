"""
firewall.py
Wrappers around iptables commands.
All write operations require root privileges (os.geteuid() == 0).
Note: rules are session-only and will not survive a reboot.
"""

import subprocess
import os
import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class Rule:
    line_num: int
    target: str
    protocol: str
    source: str
    destination: str
    options: str
    raw: str


def _is_root() -> bool:
    return os.geteuid() == 0


def _require_root():
    if not _is_root():
        raise PermissionError(
            "Root privileges are required to modify firewall rules.\n"
            "Please restart the application with: sudo python3 firewall_app.py"
        )


def _run(cmd: list, timeout: int = 10) -> tuple[bool, str, str]:
    """Run a shell command. Returns (success, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out."
    except FileNotFoundError as e:
        return False, "", f"Command not found: {e}"




# ─── Read Operations (no root required) ───────────────────────────────────────

def get_rules(chain: str = "INPUT") -> tuple[bool, list[Rule], str]:
    """
    Return current iptables rules for the given chain.
    Returns (success, list_of_Rule, error_message).
    """
    ok, stdout, stderr = _run(["iptables", "-L", chain, "-n", "--line-numbers", "-v"])
    if not ok:
        # Try without -v in case of permissions
        ok, stdout, stderr = _run(["iptables", "-L", chain, "-n", "--line-numbers"])
    if not ok:
        return False, [], stderr or "Failed to read iptables rules."

    rules = []
    lines = stdout.splitlines()
    # Skip header lines (first 2 lines: chain name + column headers)
    data_lines = [l for l in lines[2:] if l.strip()]

    for line in data_lines:
        parts = line.split()
        if not parts:
            continue
        try:
            line_num = int(parts[0])
            # With -v: num pkts bytes target prot opt in out source destination [extra]
            # Without -v: num target prot opt source destination [extra]
            if len(parts) >= 9:
                # verbose output
                target = parts[3]
                protocol = parts[4]
                source = parts[7]
                destination = parts[8]
                options = " ".join(parts[9:])
            elif len(parts) >= 6:
                target = parts[1]
                protocol = parts[2]
                source = parts[4]
                destination = parts[5]
                options = " ".join(parts[6:])
            else:
                target = parts[1] if len(parts) > 1 else ""
                protocol = ""
                source = ""
                destination = ""
                options = ""

            rules.append(Rule(
                line_num=line_num, target=target, protocol=protocol,
                source=source, destination=destination,
                options=options, raw=line,
            ))
        except (ValueError, IndexError):
            continue

    return True, rules, ""


def get_all_chains() -> tuple[bool, list[str], str]:
    """List all available iptables chains."""
    ok, stdout, stderr = _run(["iptables", "-L", "-n"])
    if not ok:
        return False, [], stderr
    chains = re.findall(r"^Chain (\S+)", stdout, re.MULTILINE)
    return True, chains, ""


# ─── Write Operations (root required) ─────────────────────────────────────────

def block_port(port: int, protocol: str = "tcp") -> tuple[bool, str]:
    """Block all system communication on a port (both INPUT and OUTPUT chains)."""
    _require_root()
    protocols = ["tcp", "udp"] if protocol.lower() == "both" else [protocol.lower()]
    messages = []
    success = True
    for proto in protocols:
        # Block incoming connections arriving at this port
        ok_in, _, err_in = _run([
            "iptables", "-A", "INPUT",
            "-p", proto, "--dport", str(port),
            "-j", "DROP"
        ])
        # Block outgoing connections going TO this port on remote hosts
        ok_out, _, err_out = _run([
            "iptables", "-A", "OUTPUT",
            "-p", proto, "--dport", str(port),
            "-j", "DROP"
        ])
        if ok_in and ok_out:
            messages.append(f"Blocked {proto.upper()} port {port} (INPUT + OUTPUT)")
        else:
            if not ok_in:
                messages.append(f"INPUT block failed for {proto.upper()} port {port}: {err_in}")
            if not ok_out:
                messages.append(f"OUTPUT block failed for {proto.upper()} port {port}: {err_out}")
            success = False

    return success, "\n".join(messages)


def unblock_port(port: int, protocol: str = "tcp") -> tuple[bool, str]:
    """Remove DROP rules for a port from both INPUT and OUTPUT chains."""
    _require_root()
    protocols = ["tcp", "udp"] if protocol.lower() == "both" else [protocol.lower()]
    messages = []
    success = True
    for proto in protocols:
        ok_in, _, err_in = _run([
            "iptables", "-D", "INPUT",
            "-p", proto, "--dport", str(port),
            "-j", "DROP"
        ])
        ok_out, _, err_out = _run([
            "iptables", "-D", "OUTPUT",
            "-p", proto, "--dport", str(port),
            "-j", "DROP"
        ])
        if ok_in and ok_out:
            messages.append(f"Unblocked {proto.upper()} port {port} (INPUT + OUTPUT)")
        else:
            if not ok_in:
                messages.append(f"INPUT unblock failed for {proto.upper()} port {port}: {err_in}")
            if not ok_out:
                messages.append(f"OUTPUT unblock failed for {proto.upper()} port {port}: {err_out}")
            success = False

    return success, "\n".join(messages)


def block_ip(ip: str, direction: str = "INPUT") -> tuple[bool, str]:
    """Block all traffic from a specific IP address."""
    _require_root()
    flag = "-s" if direction == "INPUT" else "-d"
    ok, _, stderr = _run([
        "iptables", "-A", direction, flag, ip, "-j", "DROP"
    ])
    if ok:
        return True, f"Blocked IP {ip} on {direction}"
    return False, f"Failed to block IP {ip}: {stderr}"


def unblock_ip(ip: str, direction: str = "INPUT") -> tuple[bool, str]:
    """Remove DROP rule for a specific IP address."""
    _require_root()
    flag = "-s" if direction == "INPUT" else "-d"
    ok, _, stderr = _run([
        "iptables", "-D", direction, flag, ip, "-j", "DROP"
    ])
    if ok:
        return True, f"Unblocked IP {ip} on {direction}"
    return False, f"Failed to unblock IP {ip}: {stderr}"


def delete_rule_by_line(chain: str, line_num: int) -> tuple[bool, str]:
    """Delete an iptables rule by its line number in the given chain."""
    _require_root()
    ok, _, stderr = _run(["iptables", "-D", chain, str(line_num)])
    if ok:
        return True, f"Deleted rule #{line_num} from {chain}"
    return False, f"Failed to delete rule #{line_num}: {stderr}"


def flush_chain(chain: str = "INPUT") -> tuple[bool, str]:
    """Flush (delete all rules from) a chain."""
    _require_root()
    ok, _, stderr = _run(["iptables", "-F", chain])
    if ok:
        return True, f"Flushed all rules from {chain}"
    return False, f"Failed to flush {chain}: {stderr}"


def allow_port(port: int, protocol: str = "tcp") -> tuple[bool, str]:
    """Explicitly ACCEPT a port on both INPUT and OUTPUT chains."""
    _require_root()
    protocols = ["tcp", "udp"] if protocol.lower() == "both" else [protocol.lower()]
    messages = []
    success = True
    for proto in protocols:
        ok_in, _, err_in = _run([
            "iptables", "-I", "INPUT", "1",
            "-p", proto, "--dport", str(port),
            "-j", "ACCEPT"
        ])
        ok_out, _, err_out = _run([
            "iptables", "-I", "OUTPUT", "1",
            "-p", proto, "--dport", str(port),
            "-j", "ACCEPT"
        ])
        if ok_in and ok_out:
            messages.append(f"Allowed {proto.upper()} port {port} (INPUT + OUTPUT)")
        else:
            if not ok_in:
                messages.append(f"INPUT allow failed for {proto.upper()} port {port}: {err_in}")
            if not ok_out:
                messages.append(f"OUTPUT allow failed for {proto.upper()} port {port}: {err_out}")
            success = False

    return success, "\n".join(messages)


def allow_ip(ip: str, direction: str = "INPUT") -> tuple[bool, str]:
    """Insert an ACCEPT rule at the top for a specific IP."""
    _require_root()
    flag = "-s" if direction == "INPUT" else "-d"
    ok, _, stderr = _run([
        "iptables", "-I", direction, "1", flag, ip, "-j", "ACCEPT"
    ])
    if ok:
        return True, f"Allowed IP {ip} on {direction}"
    return False, f"Failed to allow IP {ip}: {stderr}"
