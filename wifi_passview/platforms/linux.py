"""
Linux WiFi credential extractor.

Supports:
  - NetworkManager (most distros: Ubuntu, Fedora, Arch, Debian)
  - wpa_supplicant (/etc/wpa_supplicant/wpa_supplicant.conf)
  - iwd (Intel Wireless Daemon)
"""

from __future__ import annotations

import configparser
import re
import subprocess
from pathlib import Path

from ..models import ScanResult, WifiProfile

NM_PATHS = [
    Path("/etc/NetworkManager/system-connections"),
    Path("/run/NetworkManager/system-connections"),
    Path(str(Path.home()) + "/.config/NetworkManager/system-connections"),
]

WPA_SUPPLICANT_PATHS = [
    Path("/etc/wpa_supplicant/wpa_supplicant.conf"),
    Path("/etc/wpa_supplicant.conf"),
]

IWD_PATH = Path("/var/lib/iwd")


def get_profiles() -> ScanResult:
    result = ScanResult(platform="linux")

    _try_networkmanager(result)
    _try_wpa_supplicant(result)
    _try_iwd(result)
    _try_nmcli(result)

    # Deduplicate by SSID
    seen: set[str] = set()
    deduped = []
    for p in result.profiles:
        if p.ssid not in seen:
            seen.add(p.ssid)
            deduped.append(p)
    result.profiles = deduped

    return result


def _try_networkmanager(result: ScanResult):
    """Parse NetworkManager keyfile connections."""
    for nm_dir in NM_PATHS:
        if not nm_dir.exists():
            continue
        for conf_file in nm_dir.iterdir():
            try:
                _parse_nm_file(conf_file, result)
            except Exception as e:
                result.errors.append(f"NM parse error {conf_file}: {e}")


def _parse_nm_file(path: Path, result: ScanResult):
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        result.errors.append(
            f"Permission denied: {path}. Try running with sudo."
        )
        return

    config = configparser.RawConfigParser()
    config.read_string(content)

    if not config.has_section("wifi"):
        return

    ssid = config.get("wifi", "ssid", fallback=None)
    if not ssid:
        return

    # Strip surrounding quotes if present
    ssid = ssid.strip('"')

    password = None
    auth_type = None

    if config.has_section("wifi-security"):
        auth_type = config.get("wifi-security", "key-mgmt", fallback=None)
        password = (
            config.get("wifi-security", "psk", fallback=None)
            or config.get("wifi-security", "wep-key0", fallback=None)
            or config.get("wifi-security", "password", fallback=None)
        )
        if password:
            password = password.strip('"')

    auto_connect_str = config.get("connection", "autoconnect", fallback="yes")
    auto_connect = auto_connect_str.lower() != "no"

    result.profiles.append(WifiProfile(
        ssid=ssid,
        password=password,
        auth_type=auth_type,
        auto_connect=auto_connect,
    ))


def _try_wpa_supplicant(result: ScanResult):
    """Parse wpa_supplicant.conf."""
    for wpa_path in WPA_SUPPLICANT_PATHS:
        if not wpa_path.exists():
            continue
        try:
            content = wpa_path.read_text(encoding="utf-8", errors="replace")
        except PermissionError:
            result.errors.append(
                f"Permission denied: {wpa_path}. Try running with sudo."
            )
            continue

        network_blocks = re.findall(
            r'network\s*=\s*\{([^}]+)\}', content, re.DOTALL
        )
        for block in network_blocks:
            ssid_m = re.search(r'ssid\s*=\s*"([^"]+)"', block)
            psk_m  = re.search(r'psk\s*=\s*"([^"]+)"', block)
            key_m  = re.search(r'wep_key0\s*=\s*"?([^\s"]+)"?', block)

            if not ssid_m:
                continue

            result.profiles.append(WifiProfile(
                ssid=ssid_m.group(1),
                password=(psk_m.group(1) if psk_m else None)
                         or (key_m.group(1) if key_m else None),
                auth_type="WPA-PSK" if psk_m else ("WEP" if key_m else "OPEN"),
            ))


def _try_iwd(result: ScanResult):
    """Parse iwd network state files."""
    if not IWD_PATH.exists():
        return
    for state_file in IWD_PATH.rglob("*.psk"):
        try:
            content = state_file.read_text(encoding="utf-8", errors="replace")
            ssid = state_file.stem
            psk_m = re.search(r'Passphrase\s*=\s*(.+)', content)
            result.profiles.append(WifiProfile(
                ssid=ssid,
                password=psk_m.group(1).strip() if psk_m else None,
                auth_type="WPA-PSK",
            ))
        except Exception as e:
            result.errors.append(f"iwd parse error {state_file}: {e}")


def _try_nmcli(result: ScanResult):
    """
    Fallback: use nmcli to list known SSIDs (no passwords, but useful
    when NM conf files aren't readable without sudo).
    """
    existing_ssids = {p.ssid for p in result.profiles}
    try:
        out = subprocess.run(
            ["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"],
            capture_output=True, text=True, timeout=5
        )
        if out.returncode != 0:
            return
        for line in out.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and "wireless" in parts[1].lower():
                ssid = parts[0].strip()
                if ssid and ssid not in existing_ssids:
                    result.profiles.append(WifiProfile(
                        ssid=ssid,
                        password=None,
                        auth_type="unknown (run as root for passwords)",
                    ))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
