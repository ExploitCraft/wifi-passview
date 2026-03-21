"""
Windows WiFi credential extractor.

Uses: netsh wlan show profiles / netsh wlan show profile name="X" key=clear
"""

from __future__ import annotations

import re
import subprocess

from ..models import ScanResult, WifiProfile


def get_profiles() -> ScanResult:
    result = ScanResult(platform="windows")

    try:
        profiles_out = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
        )
    except FileNotFoundError:
        result.errors.append("netsh not found — are you running on Windows?")
        return result
    except subprocess.TimeoutExpired:
        result.errors.append("netsh timed out.")
        return result

    ssids = re.findall(r"All User Profile\s*:\s*(.+)", profiles_out.stdout)

    for ssid in ssids:
        ssid = ssid.strip()
        profile = _get_profile_detail(ssid, result)
        result.profiles.append(profile)

    return result


def _get_profile_detail(ssid: str, result: ScanResult) -> WifiProfile:
    try:
        detail_out = subprocess.run(
            ["netsh", "wlan", "show", "profile", f"name={ssid}", "key=clear"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
        )
    except subprocess.TimeoutExpired:
        result.errors.append(f"Timeout fetching detail for '{ssid}'")
        return WifiProfile(ssid=ssid)

    text = detail_out.stdout

    password_m  = re.search(r"Key Content\s*:\s*(.+)", text)
    auth_m      = re.search(r"Authentication\s*:\s*(.+)", text)
    autoconn_m  = re.search(r"Connection mode\s*:\s*(.+)", text)
    band_m      = re.search(r"Radio type\s*:\s*(.+)", text)

    return WifiProfile(
        ssid=ssid,
        password=password_m.group(1).strip() if password_m else None,
        auth_type=auth_m.group(1).strip() if auth_m else None,
        band=band_m.group(1).strip() if band_m else None,
        auto_connect=(
            autoconn_m.group(1).strip().lower() == "connect automatically"
            if autoconn_m else None
        ),
    )
