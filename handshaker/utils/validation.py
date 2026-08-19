"""Runtime value validators and parsers.

Every value entering the strategy / verification layers is parsed with an
explicit, lenient-by-design parser that returns ``None`` on garbage rather
than guessing. This is the anti-hallucination backbone: "I don't know" is a
valid and safe answer.
"""

from __future__ import annotations

import re
from typing import Iterable

# A canonical BSSID / MAC address.
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")


def parse_mac(value: str) -> str | None:
    """Normalise a MAC address to lowercase colon-separated form, or None."""
    if not value:
        return None
    # Accept '-', ':' or no separators.
    candidate = value.replace("-", ":").lower()
    if not _MAC_RE.match(candidate):
        return None
    return candidate


def parse_int(value: object, default: int | None = None) -> int | None:
    """Parse an int strictly; return ``default`` (None) on failure."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


def parse_signal_dbm(value: str) -> int | None:
    """Parse a signal reading like '-57' into an int dBm, or None."""
    v = value.strip()
    if not v or v in {"-1", "--", "N/A"}:
        return None
    try:
        return int(float(v))
    except ValueError:
        return None


def parse_channel(value: str) -> int | None:
    """Parse a channel like '6', '36', or '11,' into an int, or None."""
    v = value.strip().rstrip(",")
    n = parse_int(v)
    return n if n is not None and 1 <= n <= 233 else None


def unique_macs(values: Iterable[str]) -> list[str]:
    """Return a deduplicated, ordered list of valid MACs from an iterable."""
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        mac = parse_mac(v)
        if mac and mac not in seen:
            seen.add(mac)
            out.append(mac)
    return out
