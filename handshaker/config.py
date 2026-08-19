"""Configuration loading with validation.

Validation is strict on purpose: unknown keys or out-of-range values are
rejected so the runtime never operates on a guessed or silently-broken config.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

from .constants import DEFAULT_CONFIG
from .exceptions import ConfigError

# Allowed top-level keys. Adding a feature requires adding its key here —
# there is no silent pass-through.
_ALLOWED_TOP_KEYS = {
    "general",
    "adapter",
    "scan",
    "capture",
    "verify",
    "deauth",
    "pmkid",
    "learning",
    "nim",
    "targets",
    "tools",
}

_DEFAULTS: dict[str, Any] = {
    "general": {
        "interface": None,          # auto-detect when None
        "require_root": True,
        "consent_required": True,
        "output_root": None,        # defaults to data/ under the project
        "log_level": "INFO",
    },
    "adapter": {
        "auto_monitor": True,
        "reset_on_exit": True,
        "check_injection": True,
        "channel_hop": False,
    },
    "scan": {
        "dwell": 12,                # seconds per channel
        "bands": ["2.4GHz", "5GHz"],
        "min_signal": -90,          # dBm threshold
    },
    "capture": {
        "format": "pcapng",         # pcapng preferred (hcxdumptool-friendly)
        "max_duration": 300,        # seconds per target
        "write_interval": 2,        # force-flush interval (seconds)
        "wpa_only": True,           # ignore WEP / OPN targets
        # hcxdumptool attack modes for the MAIN handshake capture:
        #   1 = PMKID (clientless), 2 = EAPOL passive, 3 = EAPOL deauth.
        # We capture PMKID (1) + passive EAPOL (2); the strategist drives the
        # active deauth with aireplay-ng / mdk4 / bettercap.
        "hcxdumptool_attack": ["1", "2"],
    },
    "verify": {
        # Strict: require ALL 4 EAPOL messages (M1..M4) of the handshake.
        "require_full_handshake": True,
        # If strict is off, at minimum require a crackable M2(+SNonce,MIC)+M3 pair.
        "require_mic": True,
        "require_nonce": True,
        "min_packets": 4,
        "tools": ["tshark", "aircrack-ng", "hcxpcapngtool"],
        "delete_on_fail": True,     # reject & delete anything that isn't a 4-way HS
        "quarantine_before_delete": True,
    },
    "deauth": {
        "enabled": True,
        "max_bursts": 8,
        "burst_size": 15,           # deauth packets per burst
        "cooldown": 4,              # seconds between bursts
        "reason_codes": [1, 4, 7],  # 1=unspec, 4=disassoc, 7=class3-failure
        "tools": ["aireplay-ng", "mdk4", "bettercap"],
    },
    "pmkid": {
        "enabled": True,
        "hcxdumptool_filter": ["1"],   # attack modes: 1=PMKID, 2=passive, 3=deauth
        "convert_to_22000": True,
    },
    "learning": {
        "enabled": True,
        "exploration": 0.25,        # epsilon-greedy exploration rate
        "decay": 0.95,              # per-session decay for stale outcomes
        "min_observations": 2,      # min trials before trusting learned policy
    },
    "nim": {
        "enabled": False,           # fully optional; tool is independent without it
        "api_key": None,            # NIM_API_KEY env var preferred
        "base_url": "https://integrate.api.nvidia.com/v1",
        "model": None,
        "max_suggestions": 8,
        "timeout": 20,
    },
    "targets": {
        "bssid": [],                # optional explicit targets
        "essid": [],
        "channel": [],
        "max_targets": 0,           # 0 = unlimited
        "exclude": [],              # BSSIDs to never touch
    },
    "tools": {
        # Per-tool explicit overrides; None means "auto-detect".
        "overrides": {},
    },
}


def _merge(default: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Deep-merge an override dict onto a defaults dict (no new keys allowed)."""
    out = copy.deepcopy(default)
    for key, value in override.items():
        if key not in out:
            raise ConfigError(f"Unknown config key: {key!r}")
        if isinstance(value, dict) and isinstance(out[key], dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: Path | str | None = None) -> dict[str, Any]:
    """Load config from ``path`` (or the default location) and validate it."""
    cfg_path = Path(path) if path else DEFAULT_CONFIG
    raw: dict[str, Any] = {}
    if cfg_path.exists():
        try:
            loaded = yaml.safe_load(cfg_path.read_text()) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"Failed to parse config {cfg_path}: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ConfigError(f"Config {cfg_path} must be a YAML mapping.")
        raw = loaded

    unknown = set(raw) - _ALLOWED_TOP_KEYS
    if unknown:
        raise ConfigError(f"Unknown top-level config section(s): {sorted(unknown)}")

    cfg = _merge(_DEFAULTS, raw)

    # --- Range / sanity validation (fail fast, no silent clamping) --- #
    verify = cfg["verify"]
    if not isinstance(verify["require_full_handshake"], bool):
        raise ConfigError("verify.require_full_handshake must be a boolean.")
    if verify["min_packets"] < 1:
        raise ConfigError("verify.min_packets must be >= 1.")

    learn = cfg["learning"]
    if not (0.0 <= float(learn["exploration"]) <= 1.0):
        raise ConfigError("learning.exploration must be in [0, 1].")
    if not (0.0 <= float(learn["decay"]) <= 1.0):
        raise ConfigError("learning.decay must be in [0, 1].")

    deauth = cfg["deauth"]
    if deauth["burst_size"] < 1 or deauth["max_bursts"] < 0:
        raise ConfigError("deauth.burst_size must be >= 1 and max_bursts >= 0.")

    return cfg
