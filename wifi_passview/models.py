"""Shared data models."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class WifiProfile:
    ssid: str
    password: str | None = None
    auth_type: str | None = None
    interface: str | None = None
    bssid: str | None = None
    band: str | None = None  # 2.4GHz / 5GHz
    last_connected: str | None = None
    auto_connect: bool | None = None

    @property
    def has_password(self) -> bool:
        return bool(self.password)

    def redact(self) -> "WifiProfile":
        """Return a copy with the password partially redacted."""
        if self.password and len(self.password) > 4:
            redacted = (
                self.password[:2]
                + "*" * (len(self.password) - 4)
                + self.password[-2:]
            )
        elif self.password:
            redacted = "****"
        else:
            redacted = None
        return WifiProfile(
            ssid=self.ssid,
            password=redacted,
            auth_type=self.auth_type,
            interface=self.interface,
            bssid=self.bssid,
            band=self.band,
            last_connected=self.last_connected,
            auto_connect=self.auto_connect,
        )


@dataclass
class ScanResult:
    profiles: list[WifiProfile] = field(default_factory=list)
    platform: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.profiles)

    @property
    def with_password(self) -> int:
        return sum(1 for p in self.profiles if p.has_password)

    @property
    def without_password(self) -> int:
        return self.total - self.with_password
