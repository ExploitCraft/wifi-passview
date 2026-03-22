# Changelog

## [1.1.0] - 2024-04-01

### Fixed
- **Critical** — `PermissionError` crash when `iterdir()` on `/etc/NetworkManager/system-connections` without sudo; now caught and added to `result.errors` with a helpful message
- **Medium** — `PermissionError` crash on `IWD_PATH.rglob("*.psk")` without sudo; same fix applied
- **Low** — `OSError` on `nm_dir.iterdir()` for other filesystem errors now caught gracefully

### Changed
- Version bumped to `1.1.0`
- README updated with ExploitCraft header and docs link

## [1.0.0] - 2024-01-01

### Added
- Initial release
- Linux support: NetworkManager, wpa_supplicant, iwd, nmcli fallback
- Windows support: netsh wlan extraction
- macOS support: Keychain via security CLI
- Terminal, JSON, and CSV output formats
- `--redact` mode for safe screenshots
- `dump` and `search` commands
