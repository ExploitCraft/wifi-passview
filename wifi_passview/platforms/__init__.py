"""Platform detection and dispatch."""

from __future__ import annotations

import sys

from ..models import ScanResult


def get_profiles() -> ScanResult:
    """Auto-detect the current platform and extract WiFi profiles."""
    platform = sys.platform

    if platform.startswith("linux"):
        from .linux import get_profiles as _get
    elif platform == "win32":
        from .windows import get_profiles as _get
    elif platform == "darwin":
        from .macos import get_profiles as _get
    else:
        result = ScanResult(platform=platform)
        result.errors.append(f"Unsupported platform: {platform}")
        return result

    return _get()
