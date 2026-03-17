# FirewallGUI

A centralized firewall management GUI for Linux, built with Python 3 + Tkinter.

## Features

| Feature | Non-Sudo | Sudo |
|---|---|---|
| View live network connections | ✅ | ✅ |
| Filter/search connections | ✅ | ✅ |
| View current iptables rules | ✅ (limited) | ✅ |
| Block / Allow ports | ❌ | ✅ |
| Block / Allow IPs | ❌ | ✅ |
| Delete individual rules | ❌ | ✅ |
| Flush rule chain | ❌ | ✅ |
| Rules survive reboot | — | ✅ (auto-saved) |

## Requirements

```bash
# Python 3.8+, tkinter, iptables
sudo apt install python3-tk iptables
```

> **Note:** Firewall rules are session-only — they will be cleared on reboot.

## Running

```bash
# Read-only mode (traffic monitoring only)
python3 firewall_app.py

# Administrator mode (full firewall management)
sudo python3 firewall_app.py
```

## Project Structure

```
firewall_gui/
├── firewall_app.py        # Entry point
├── core/
│   ├── privilege.py       # Root detection
│   ├── traffic.py         # Live connection reader (/proc/net/* + ss)
│   └── firewall.py        # iptables command wrappers
├── gui/
│   ├── theme.py           # Dark theme + ttk styles
│   ├── main_window.py     # Root window + tab notebook + refresh loop
│   ├── traffic_tab.py     # Live connections table
│   ├── rules_tab.py       # iptables rules viewer
│   └── control_panel.py   # Block/Allow forms
└── README.md
```

## How Rules Work

Rules are applied immediately via `iptables` and are **session-only** — they will be cleared when the system reboots. This is intentional for safety.

## Traffic Monitor

- Reads `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`
- Cross-references `/proc/<pid>/fd` symlinks for process names
- Supplemented by `ss -tunap` for more complete process info
- Auto-refreshes every **3 seconds**
- Colour coding:
  - 🟢 Green — ESTABLISHED
  - 🔵 Blue — LISTEN
  - 🟡 Amber — TIME_WAIT / FIN_WAIT

## Quick Usage

1. **Block a port**: Go to **Control Panel** → Port section → enter port number → select protocol → click **Block Port**
2. **Block an IP**: Right-click any connection in **Traffic Monitor** → **Block this Remote IP** (auto-fills the form in Control Panel)
3. **View rules**: Go to **Firewall Rules** tab → select chain → click Refresh
4. **Remove a rule**: In **Firewall Rules** tab → select row → click **Delete Selected Rule**
