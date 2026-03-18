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
    Verbose output columns (with -v  --line-numbers):
      0:num  1:pkts  2:bytes  3:target  4:prot  5:opt  6:in  7:out  8:source  9:dest  10+:options
    Non-verbose (without -v):
      0:num  1:target  2:prot  3:opt  4:source  5:dest  6+:options
    """
    ok, stdout, stderr = _run(["iptables", "-L", chain, "-n", "--line-numbers", "-v"])
    verbose = ok
    if not ok:
        ok, stdout, stderr = _run(["iptables", "-L", chain, "-n", "--line-numbers"])
    if not ok:
        return False, [], stderr or "Failed to read iptables rules."

    rules = []
    lines = stdout.splitlines()
    # Skip header lines (chain name + column labels)
    data_lines = [l for l in lines[2:] if l.strip()]

    for line in data_lines:
        parts = line.split()
        if not parts:
            continue
        try:
            line_num = int(parts[0])
        except ValueError:
            continue

        try:
            if verbose and len(parts) >= 10:
                # VERBOSE: num pkts bytes target prot opt in out source destination [extra...]
                target      = parts[3]
                protocol    = parts[4]
                # parts[5]=opt  parts[6]=in  parts[7]=out
                source      = parts[8]
                destination = parts[9]
                options     = " ".join(parts[10:])
            elif len(parts) >= 6:
                # NON-VERBOSE: num target prot opt source destination [extra...]
                target      = parts[1]
                protocol    = parts[2]
                # parts[3]=opt
                source      = parts[4]
                destination = parts[5]
                options     = " ".join(parts[6:])
            else:
                target      = parts[1] if len(parts) > 1 else ""
                protocol    = ""
                source      = ""
                destination = ""
                options     = ""

            rules.append(Rule(
                line_num=line_num, target=target, protocol=protocol,
                source=source, destination=destination,
                options=options, raw=line,
            ))
        except IndexError:
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

def block_port(port: int, protocol: str = "tcp", direction: str = "BOTH") -> tuple[bool, str]:
    """Block a port. Uses -I (insert at top) so DROP fires before any ACCEPT rules."""
    _require_root()
    protocols = ["tcp", "udp"] if protocol.lower() == "both" else [protocol.lower()]
    chains = _chains_for(direction)
    messages = []
    success = True
    for proto in protocols:
        for chain in chains:
            ok, _, err = _run([
                "iptables", "-I", chain, "1",   # INSERT at position 1 (top)
                "-p", proto, "--dport", str(port),
                "-j", "DROP"
            ])
            if ok:
                messages.append(f"Blocked {proto.upper()} port {port} on {chain}")
            else:
                messages.append(f"FAILED block {proto.upper()} port {port} on {chain}: {err}")
                success = False
    return success, "\n".join(messages)


def unblock_port(port: int, protocol: str = "tcp", direction: str = "BOTH") -> tuple[bool, str]:
    """Remove DROP rules for a port. direction = INPUT | OUTPUT | BOTH."""
    _require_root()
    protocols = ["tcp", "udp"] if protocol.lower() == "both" else [protocol.lower()]
    chains = _chains_for(direction)
    messages = []
    success = True
    for proto in protocols:
        for chain in chains:
            ok, _, err = _run([
                "iptables", "-D", chain,
                "-p", proto, "--dport", str(port),
                "-j", "DROP"
            ])
            if ok:
                messages.append(f"Unblocked {proto.upper()} port {port} on {chain}")
            else:
                messages.append(f"FAILED unblock {proto.upper()} port {port} on {chain}: {err}")
                success = False
    return success, "\n".join(messages)


def block_ip(ip: str, direction: str = "INPUT") -> tuple[bool, str]:
    """Block an IP. Uses -I (insert at top) so DROP fires before any ACCEPT rules."""
    _require_root()
    messages = []
    success = True
    for chain in _chains_for(direction):
        flag = "-s" if chain == "INPUT" else "-d"
        ok, _, err = _run(["iptables", "-I", chain, "1", flag, ip, "-j", "DROP"])
        if ok:
            messages.append(f"Blocked IP {ip} on {chain}")
        else:
            messages.append(f"FAILED block IP {ip} on {chain}: {err}")
            success = False
    return success, "\n".join(messages)


def unblock_ip(ip: str, direction: str = "INPUT") -> tuple[bool, str]:
    """Remove DROP rules for an IP. direction = INPUT | OUTPUT | BOTH."""
    _require_root()
    messages = []
    success = True
    for chain in _chains_for(direction):
        flag = "-s" if chain == "INPUT" else "-d"
        ok, _, err = _run(["iptables", "-D", chain, flag, ip, "-j", "DROP"])
        if ok:
            messages.append(f"Unblocked IP {ip} on {chain}")
        else:
            messages.append(f"FAILED unblock IP {ip} on {chain}: {err}")
            success = False
    return success, "\n".join(messages)


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


def allow_port(port: int, protocol: str = "tcp", direction: str = "BOTH") -> tuple[bool, str]:
    """Insert ACCEPT rule for a port. direction = INPUT | OUTPUT | BOTH."""
    _require_root()
    protocols = ["tcp", "udp"] if protocol.lower() == "both" else [protocol.lower()]
    chains = _chains_for(direction)
    messages = []
    success = True
    for proto in protocols:
        for chain in chains:
            ok, _, err = _run([
                "iptables", "-I", chain, "1",
                "-p", proto, "--dport", str(port),
                "-j", "ACCEPT"
            ])
            if ok:
                messages.append(f"Allowed {proto.upper()} port {port} on {chain}")
            else:
                messages.append(f"FAILED allow {proto.upper()} port {port} on {chain}: {err}")
                success = False
    return success, "\n".join(messages)


def allow_ip(ip: str, direction: str = "INPUT") -> tuple[bool, str]:
    """Insert ACCEPT rule for an IP. direction = INPUT | OUTPUT | BOTH."""
    _require_root()
    messages = []
    success = True
    for chain in _chains_for(direction):
        flag = "-s" if chain == "INPUT" else "-d"
        ok, _, err = _run([
            "iptables", "-I", chain, "1", flag, ip, "-j", "ACCEPT"
        ])
        if ok:
            messages.append(f"Allowed IP {ip} on {chain}")
        else:
            messages.append(f"FAILED allow IP {ip} on {chain}: {err}")
            success = False
    return success, "\n".join(messages)


def _chains_for(direction: str) -> list[str]:
    """Return list of chains for the given direction string."""
    d = direction.upper()
    if d == "BOTH":
        return ["INPUT", "OUTPUT"]
    if d in ("INPUT", "OUTPUT", "FORWARD"):
        return [d]
    return ["INPUT"]  # safe default
