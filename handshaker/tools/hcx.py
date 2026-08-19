"""hcxdumptool / hcxpcapngtool / hcxlabtool wrappers.

hcxdumptool is the primary PMKID + EAPOL capture engine (a modern,
filter-aware alternative to airodump-ng). hcxpcapngtool converts raw captures
to hashcat 22000 format and independently reports EAPOL/PMKID presence.
"""

from __future__ import annotations

from ..constants import (
    TOOL_HCXDUMPTOOL,
    TOOL_HCXLABTOOL,
    TOOL_HCXPCAPNGTOOL,
    TOOL_HCXPSCKTOOL,
)
from ..utils.proc import ProcResult, run
from .base import Tool


class Hcxdumptool(Tool):
    name = TOOL_HCXDUMPTOOL

    def capture(
        self,
        interface: str,
        out_file: str,
        *,
        channel: str | None = None,
        bssid: str | None = None,
        attack_filter: list[str] | None = None,
        duration: int | None = None,
    ) -> ProcResult:
        """Capture PMKIDs / EAPOL with hcxdumptool.

        attack filters: 1=PMKID request, 2=EAPOL (passive), 3=EAPOL via deauth.
        ``-o`` writes pcapng; ``-W``/``-w`` write hashcat 22000 lines.
        """
        args = [self.path, "-o", out_file]
        if channel is not None:
            args += ["-c", channel]
        if bssid is not None:
            args += ["--filtermode=2", "--filterlist_ap=" + bssid, "--filtermode=1"]
        if attack_filter:
            args += ["--attack_mode=" + ",".join(attack_filter)]
        # Write the 22000 hash lines alongside the pcapng.
        args += ["-W", out_file + ".22000"]
        if duration is not None:
            args += ["-t", str(duration)]
        args.append(interface)
        return run(args, timeout=(duration or 300) + 30, check=False)


class Hcxpcapngtool(Tool):
    name = TOOL_HCXPCAPNGTOOL

    def convert(self, capture_file: str, out_file: str) -> ProcResult:
        """Convert a pcapng capture to hashcat 22000 format, reporting PMKID/EAPOL."""
        return run(
            [self.path, "-o", out_file, capture_file],
            timeout=120,
            check=False,
        )


class Hcxlabtool(Tool):
    name = TOOL_HCXLABTOOL

    def convert(self, capture_file: str, out_file: str) -> ProcResult:
        return run([self.path, "-o", out_file, capture_file], timeout=120, check=False)


class Hcxpsktool(Tool):
    name = TOOL_HCXPSCKTOOL

    def convert(self, capture_file: str, out_file: str) -> ProcResult:
        return run([self.path, "-o", out_file, capture_file], timeout=120, check=False)
