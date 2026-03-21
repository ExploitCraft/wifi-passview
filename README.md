# 📡 wifi-passview

> Cross-platform CLI to dump all saved WiFi credentials in one command — Linux, Windows, and macOS.

[![CI](https://github.com/ExploitCraft/wifi-passview/actions/workflows/ci.yml/badge.svg)](https://github.com/ExploitCraft/wifi-passview/actions)
[![PyPI](https://img.shields.io/pypi/v/wifi-passview)](https://pypi.org/project/wifi-passview/)
[![Python](https://img.shields.io/pypi/pyversions/wifi-passview)](https://pypi.org/project/wifi-passview/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Features

- 🐧 **Linux** — reads NetworkManager, wpa_supplicant, and iwd configs
- 🪟 **Windows** — uses `netsh wlan` to extract all profiles and passwords
- 🍎 **macOS** — queries Keychain via `security find-generic-password`
- 📊 **Multiple output formats** — terminal (Rich), JSON, CSV
- 🔒 **Redact mode** — partially mask passwords in output (`my***23`)
- 🔍 **Search** — filter profiles by SSID name

---

## Installation

```bash
pip install wifi-passview
```

Or from source:

```bash
git clone https://github.com/ExploitCraft/wifi-passview
cd wifi-passview
pip install -e .
```

> **Linux note:** Reading NetworkManager configs in `/etc/NetworkManager/system-connections/` requires root. Run with `sudo` for full results.

---

## Quick Start

```bash
# Dump all saved WiFi profiles
wifi-passview dump

# Redact passwords in output (safe for screenshots)
wifi-passview dump --redact

# Hide passwords entirely
wifi-passview dump --no-password

# Export to JSON
wifi-passview dump --format json --output wifi.json

# Export to CSV
wifi-passview dump --format csv --output wifi.csv

# Search for a specific network
wifi-passview search "HomeNetwork"
```

---

## Example Output

```
╭─ wifi-passview — saved WiFi credential dumper ─╮

SSID                  PASSWORD           AUTH       BAND    AUTO
CoffeeShopWifi        latteplease        WPA-PSK    —       yes
HomeNetwork           (none / open)      —          2.4GHz  yes
OfficeWifi5G          Su93r$ecret!       WPA2-PSK   5GHz    yes
GuestNetwork          abc123             WPA-PSK    —       no

╭─ Summary ─────────────────────────╮
  Platform        linux
  Total profiles  4
  With password   3
  Without pass    1
╰───────────────────────────────────╯
```

---

## Platform Notes

### Linux
Reads from (in order):
1. `/etc/NetworkManager/system-connections/` — requires sudo
2. `/etc/wpa_supplicant/wpa_supplicant.conf`
3. `/var/lib/iwd/*.psk`
4. `nmcli` fallback (SSID list only, no passwords)

### Windows
Uses `netsh wlan show profiles` + `netsh wlan show profile name=X key=clear`.
No admin required for saved profiles in the current user context.

### macOS
Uses `networksetup -listpreferredwirelessnetworks` + `security find-generic-password`.
May prompt for Keychain access on first run.

---

## CLI Reference

```
Usage: wifi-passview [OPTIONS] COMMAND [ARGS]...

Commands:
  dump    Dump all saved WiFi profiles and passwords
  search  Search saved profiles by SSID name

Options for dump:
  --format     terminal | json | csv   (default: terminal)
  --output     Write output to file
  --redact     Partially mask passwords
  --no-password  Hide passwords entirely
  --ssid       Filter to a specific SSID (partial match)
```

---

## Part of the LeakHound Ecosystem

`wifi-passview` is part of [LeakHound](https://github.com/ExploitCraft/leakhound) — a unified secret hunting toolkit.

| Tool | Description |
|------|-------------|
| [envleaks](https://github.com/ExploitCraft/envleaks) | Codebase & git history secret scanner |
| [gitdork](https://github.com/ExploitCraft/gitdork) | Google/Shodan dork generator |
| **wifi-passview** | Cross-platform WiFi credential dumper (this repo) |
| [leakhound](https://github.com/ExploitCraft/leakhound) | Unified CLI wrapping all three |

---

## Disclaimer

This tool is intended for **use on your own systems only**. Only dump credentials from devices you own or have explicit permission to audit. The author is not responsible for misuse.

---

## License

MIT © [ExploitCraft](https://github.com/ExploitCraft)
