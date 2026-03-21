"""
macOS WiFi credential extractor.

Uses:
  - airport CLI to list preferred networks
  - security find-generic-password to pull passwords from Keychain
  - networksetup -listpreferredwirelessnetworks as fallback
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from ..models import ScanResult, WifiProfile

AIRPORT_PATH = (
    "/System/Library/PrivateFrameworks/Apple80211.framework"
    "/Versions/Current/Resources/airport"
)


def get_profiles() -> ScanResult:
    result = ScanResult(platform="macos")

    ssids = _get_preferred_networks(result)
    for ssid in ssids:
        password = _get_keychain_password(ssid, result)
        result.profiles.append(WifiProfile(
            ssid=ssid,
            password=password,
        ))

    return result


def _get_preferred_networks(result: ScanResult) -> list[str]:
    """Get list of preferred network SSIDs via networksetup."""
    ssids: list[str] = []

    # Try networksetup first (no special permissions needed for list)
    try:
        interfaces_out = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True, text=True, timeout=10
        )
        wifi_iface = None
        for line in interfaces_out.stdout.splitlines():
            if "Wi-Fi" in line or "AirPort" in line:
                next_line_idx = interfaces_out.stdout.splitlines().index(line) + 1
                lines = interfaces_out.stdout.splitlines()
                if next_line_idx < len(lines):
                    iface_m = re.search(r"Device:\s*(\w+)", lines[next_line_idx])
                    if iface_m:
                        wifi_iface = iface_m.group(1)
                break

        if wifi_iface:
            pref_out = subprocess.run(
                ["networksetup", "-listpreferredwirelessnetworks", wifi_iface],
                capture_output=True, text=True, timeout=10
            )
            for line in pref_out.stdout.splitlines():
                line = line.strip()
                if line and "Preferred networks" not in line:
                    ssids.append(line)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        result.errors.append(f"networksetup error: {e}")

    # Fallback: airport -I to get current SSID at minimum
    if not ssids and Path(AIRPORT_PATH).exists():
        try:
            airport_out = subprocess.run(
                [AIRPORT_PATH, "-I"],
                capture_output=True, text=True, timeout=10
            )
            ssid_m = re.search(r"\s+SSID:\s*(.+)", airport_out.stdout)
            if ssid_m:
                ssids.append(ssid_m.group(1).strip())
        except subprocess.TimeoutExpired:
            pass

    return ssids


def _get_keychain_password(ssid: str, result: ScanResult) -> str | None:
    """Extract WiFi password from macOS Keychain."""
    try:
        out = subprocess.run(
            [
                "security",
                "find-generic-password",
                "-D", "AirPort network password",
                "-a", ssid,
                "-w",
            ],
            capture_output=True, text=True, timeout=10
        )
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
        # Non-zero return usually means not found or access denied
        if out.returncode == 128:
            result.errors.append(
                f"Keychain access denied for '{ssid}'. "
                "Grant Terminal access in System Settings > Privacy > Keychain."
            )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        result.errors.append(f"Keychain error for '{ssid}': {e}")
    return None
