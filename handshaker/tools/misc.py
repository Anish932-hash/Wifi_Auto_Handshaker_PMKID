"""Wrappers for remaining Kali WiFi tools (bettercap, mdk4, wifite, etc.).

Every tool that is useful for the WiFi pentesting workflow gets a wrapper so
*none* of the standard Kali WiFi tools are abandoned. Availability is detected
at runtime; the strategist only uses tools that are actually present.
"""

from __future__ import annotations

from ..constants import (
    TOOL_BETTERCAP,
    TOOL_CAPINFOS,
    TOOL_COWPATTY,
    TOOL_IW,
    TOOL_IWCONFIG,
    TOOL_KISMET,
    TOOL_MDK4,
    TOOL_PYRIT,
    TOOL_RFKILL,
    TOOL_WASH,
    TOOL_WIFITE,
    TOOL_WIFITE2,
    TOOL_WIRESHARK,
)
from ..utils.proc import ProcResult, run
from .base import Tool


class Bettercap(Tool):
    name = TOOL_BETTERCAP

    def deauth(
        self,
        interface: str,
        bssid: str,
        *,
        client: str = "*",
        packets: int = 30,
    ) -> ProcResult:
        """Deauth via bettercap's wifi.deauth module."""
        script = (
            f'set wifi.interface {interface}; '
            f'wifi.recon on; '
            f'wifi.deauth {bssid}; '
            f'wifi.deauth {client}; '
            "sleep 1; quit"
        )
        # packets/burst tuning via caplet is verbose; use a compact caplet file
        # is not required for a basic deauth. Keep it scripted and bounded.
        args = [self.path, "-eval", script, "-silent"]
        return run(args, timeout=45, check=False)

    def caplet_deauth(self, interface: str, bssid: str, client: str, count: int) -> ProcResult:
        """Burst-precise deauth using an inline caplet."""
        script = (
            f"set wifi.interface {interface}; "
            f"set wifi.deauth.skip {0}; "
            "wifi.recon on; "
            + "; ".join([f"wifi.deauth {bssid}" for _ in range(count)])
            + f"; wifi.deauth {client}; sleep 1; quit"
        )
        return run([self.path, "-eval", script, "-silent"], timeout=60, check=False)


class Mdk4(Tool):
    name = TOOL_MDK4

    def deauth(self, interface: str, bssid: str, *, count: int = 10) -> ProcResult:
        """Targeted deauth using mdk4's 'd' (deauth/disassoc) attack mode."""
        args = [
            self.path, interface, "d",
            "-B", bssid,          # whitelist this BSSID
            "-c", "1",            # single channel (set channel first)
            "-s", str(count),     # packets per burst (approx)
        ]
        return run(args, timeout=30, check=False)

    def beacon_flood(self, interface: str, count: int = 60) -> ProcResult:
        """Flood beacons (mostly useful for smoke-testing; not for capture)."""
        return run([self.path, interface, "b", "-n", str(count)], timeout=30, check=False)


class Wifite(Tool):
    name = TOOL_WIFITE

    def auto(self, *extra: str) -> ProcResult:
        return run([self.path, *extra], timeout=1800, check=False)


class Wifite2(Wifite):
    name = TOOL_WIFITE2


class Cowpatty(Tool):
    name = TOOL_COWPATTY

    def check_handshake(self, capture_file: str, essid: str) -> ProcResult:
        """cowpatty can verify a 4-way handshake exists for a target ESSID."""
        return run(
            [self.path, "-r", capture_file, "-s", essid, "-c"],
            timeout=60,
            check=False,
        )


class Pyrit(Tool):
    name = TOOL_PYRIT

    def check_handshakes(self, capture_file: str) -> ProcResult:
        """pyrit analyze reports whether the capture holds a valid handshake."""
        return run(
            [self.path, "-r", capture_file, "analyze"],
            timeout=60,
            check=False,
        )


class Wash(Tool):
    name = TOOL_WASH

    def scan(self, interface: str) -> ProcResult:
        return run([self.path, "-i", interface, "-a"], timeout=120, check=False)


class Kismet(Tool):
    name = TOOL_KISMET

    def scan(self, interface: str, out_prefix: str) -> ProcResult:
        return run(
            [self.path, "-c", interface, "--log-prefix", out_prefix],
            timeout=300,
            check=False,
        )


class Capinfos(Tool):
    name = TOOL_CAPINFOS

    def info(self, capture_file: str) -> ProcResult:
        return run([self.path, capture_file], timeout=30, check=False)


class Iw(Tool):
    name = TOOL_IW

    def set_mode(self, interface: str, mode: str) -> ProcResult:
        return run([self.path, "dev", interface, "set", "type", mode], timeout=15, check=False)

    def set_channel(self, interface: str, channel: str) -> ProcResult:
        return run([self.path, "dev", interface, "set", "channel", channel], timeout=15, check=False)


class Iwconfig(Tool):
    name = TOOL_IWCONFIG

    def mode(self, interface: str, mode: str) -> ProcResult:
        return run([self.path, interface, "mode", mode], timeout=15, check=False)


class Rfkill(Tool):
    name = TOOL_RFKILL

    def list_all(self) -> ProcResult:
        return run([self.path, "list"], timeout=15, check=False)

    def unblock_all(self) -> ProcResult:
        return run([self.path, "unblock", "wifi"], timeout=15, check=False)


class WiresharkGui(Tool):
    name = TOOL_WIRESHARK

    def open(self, capture_file: str) -> ProcResult:
        return run([self.path, capture_file], timeout=30, check=False)
