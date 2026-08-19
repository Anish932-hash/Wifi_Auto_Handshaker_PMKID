"""Wireless adapter management: detect, monitor mode, injection test, reset.

The adapter layer never guesses adapter state — it interrogates the system
(``iw``/``iwconfig``/``airmon-ng``/``rfkill``) and reports what it observes.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from ..constants import TOOL_AIRMON_NG, TOOL_AIREPLAY_NG, TOOL_IW, TOOL_RFKILL
from ..exceptions import AdapterError, NoAdapterError
from ..tools.registry import ToolRegistry
from ..utils.proc import run

log = logging.getLogger("handshaker.adapter")

_INTERFACE_RE = re.compile(r"^\s*(?:phy#\d+\s+)?(wlan\w+|wl\w+|mon\w+)\s+", re.MULTILINE)
_MONITOR_HINT_RE = re.compile(r"Type:\s*monitor", re.IGNORECASE)


@dataclass
class AdapterInfo:
    """Observed facts about a wireless adapter (no inferred fields)."""

    interface: str
    monitor_mode: bool = False
    injection_ok: bool | None = None   # None == not tested
    channels: list[int] = field(default_factory=list)


class AdapterManager:
    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    # ------------------------------------------------------------------ #
    # Detection
    # ------------------------------------------------------------------ #
    def detect_interfaces(self) -> list[str]:
        """List wireless interfaces present on the system."""
        found: set[str] = set()
        # iw dev is authoritative when present.
        if self.registry.has(TOOL_IW):
            res = run([self.registry.iw().path, "dev"], timeout=15, check=False)
            for line in res.stdout.splitlines():
                m = re.match(r"^\s*Interface\s+(\S+)", line)
                if m:
                    found.add(m.group(1))
        else:
            res = run(["iwconfig"], timeout=15, check=False)
            for line in res.stdout.splitlines():
                m = re.match(r"^(\S+)\s+IEEE\s+802\.11", line)
                if m:
                    found.add(m.group(1))
        # airmon-ng's own listing can reveal monitor interfaces too.
        if self.registry.has(TOOL_AIRMON_NG):
            res = run([self.registry.airmon().path], timeout=15, check=False)
            for line in res.stdout.splitlines():
                m = re.search(r"^\s*(?:phy\d+\s+)?Interface\s+(mon\w+|wlan\w+|wl\w+)", line)
                if m:
                    found.add(m.group(1))
        return sorted(found)

    def select_interface(self, requested: str | None = None) -> str:
        """Pick a working interface; prefer an explicit request, else auto-detect."""
        ifaces = self.detect_interfaces()
        if not ifaces:
            raise NoAdapterError("No wireless adapter detected. Is it plugged in / unblocked?")
        if requested and requested in ifaces:
            return requested
        if requested:
            raise NoAdapterError(
                f"Requested interface '{requested}' not found. Available: {', '.join(ifaces)}"
            )
        # Prefer managed (non-mon) interfaces for the starting point.
        managed = [i for i in ifaces if not i.startswith(("mon", "wlan0mon"))]
        return (managed or ifaces)[0]

    # ------------------------------------------------------------------ #
    # Mode control
    # ------------------------------------------------------------------ #
    def is_monitor(self, interface: str) -> bool:
        if self.registry.has(TOOL_IW):
            res = run([self.registry.iw().path, "dev", interface, "info"], timeout=15, check=False)
            return bool(_MONITOR_HINT_RE.search(res.stdout))
        res = run(["iwconfig", interface], timeout=15, check=False)
        return "Mode:Monitor" in res.output

    def enable_monitor(self, interface: str) -> str:
        """Enable monitor mode, returning the (possibly new) interface name."""
        if self.is_monitor(interface):
            log.info("%s already in monitor mode", interface)
            return interface
        if self.registry.has(TOOL_AIRMON_NG):
            # Kill conflicting processes first (NetworkManager etc.).
            self.registry.airmon().check_kill()
            res = self.registry.airmon().start_monitor(interface)
            new_iface = _parse_monitor_interface(res.output)
            if new_iface:
                return new_iface
        # Fallback: raw iw set type monitor.
        if self.registry.has(TOOL_IW):
            self.registry.iw().set_mode(interface, "monitor")
            run([self.registry.iw().path, "dev", interface, "set", "txpower", "fixed", "3000"], check=False)
            return interface
        raise AdapterError(f"Could not enable monitor mode on {interface} (airmon-ng/iw unavailable).")

    def reset(self, interface: str) -> None:
        """Restore managed mode and restart network services."""
        if self.registry.has(TOOL_AIRMON_NG):
            self.registry.airmon().stop_monitor(interface)
        if self.registry.has(TOOL_IW):
            self.registry.iw().set_mode(interface, "managed")
        # Bring NetworkManager back up if it was killed.
        run(["service", "NetworkManager", "restart"], timeout=30, check=False)
        run(["service", "wpa_supplicant", "restart"], timeout=30, check=False)
        log.info("Adapter %s reset to managed mode", interface)

    def check_injection(self, interface: str) -> bool:
        """Run aireplay-ng --test; return True only on observed success."""
        if not self.registry.has(TOOL_AIREPLAY_NG):
            log.warning("aireplay-ng missing; cannot test injection.")
            return False
        res = self.registry.aireplay().test_injection(interface)
        ok = "Injection is working!" in res.output
        log.info("Injection test: %s", "PASS" if ok else "FAIL/UNKNOWN")
        return ok

    def unblock_rfkill(self) -> None:
        if self.registry.has(TOOL_RFKILL):
            self.registry.rfkill().unblock_all()


def _parse_monitor_interface(output: str) -> str | None:
    """airmon-ng prints '(mac80211 monitor mode vif enabled for X on Y)'."""
    m = re.search(r"monitor mode vif enabled for\s+\[?(\S+?)\]?", output)
    if m:
        return m.group(1).strip("[]")
    m = re.search(r"monitor mode enabled on\s+(\S+)", output)
    if m:
        return m.group(1)
    return None
