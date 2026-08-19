"""Capture session — runs airodump-ng / hcxdumptool in the background.

A ``CaptureSession`` owns one long-running capture process and gives the engine
a deterministic handle to (a) know it is running and (b) stop it cleanly. No
capture state is ever inferred from partial output.
"""

from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from ..constants import CAPTURES_DIR, TOOL_AIRODUMP_NG, TOOL_HCXDUMPTOOL
from ..exceptions import CaptureError
from ..tools.registry import ToolRegistry

log = logging.getLogger("handshaker.capturer")


@dataclass
class CaptureSession:
    """Handle to a running capture process."""

    interface: str
    bssid: str
    out_prefix: str
    process: subprocess.Popen
    engine: str          # "airodump" | "hcxdumptool"
    started_at: float

    @property
    def alive(self) -> bool:
        return self.process.poll() is None

    def stop(self) -> None:
        """Stop the capture process gracefully (SIGINT then SIGKILL)."""
        if self.process.poll() is not None:
            return
        self.process.send_signal(2)  # SIGINT — makes airodump flush its file
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


class Capturer:
    def __init__(self, registry: ToolRegistry, config: dict) -> None:
        self.registry = registry
        self.config = config
        CAPTURES_DIR.mkdir(parents=True, exist_ok=True)

    def start(
        self,
        interface: str,
        bssid: str,
        channel: int,
        *,
        engine: str | None = None,
        essid: str = "",
    ) -> CaptureSession:
        """Start capturing for a specific BSSID on a specific channel."""
        engine = engine or ("hcxdumptool" if self.registry.has(TOOL_HCXDUMPTOOL) else "airodump")
        stamp = int(time.time())
        prefix = f"{CAPTURES_DIR}/{bssid.replace(':', '')}_{essid or 'target'}_{stamp}"

        if engine == "hcxdumptool" and self.registry.has(TOOL_HCXDUMPTOOL):
            return self._start_hcx(interface, bssid, channel, prefix)
        if self.registry.has(TOOL_AIRODUMP_NG):
            return self._start_airodump(interface, bssid, channel, prefix)
        raise CaptureError("Neither hcxdumptool nor airodump-ng is available for capture.")

    def _start_hcx(self, interface: str, bssid: str, channel: int, prefix: str) -> CaptureSession:
        tool = self.registry.hcxdumptool()
        attack_filter = self.config["capture"].get("hcxdumptool_attack") or ["1", "2"]
        out = f"{prefix}.pcapng"
        cmd = [
            tool.path, "-o", out, "-c", str(channel),
            "--filtermode=2", "--filterlist_ap=" + bssid,
            "--attack_mode=" + ",".join(attack_filter),
            "-W", f"{prefix}.22000",
            interface,
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log.info("hcxdumptool capture started for %s (ch=%d)", bssid, channel)
        return CaptureSession(interface, bssid, prefix, proc, "hcxdumptool", time.time())

    def _start_airodump(self, interface: str, bssid: str, channel: int, prefix: str) -> CaptureSession:
        tool = self.registry.airodump()
        cmd = [
            tool.path, interface, "-w", prefix,
            "--band", "abg", "-c", str(channel),
            "--bssid", bssid,
            "--output-format", "pcap,cap,csv",
            "--write-interval", "1",
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log.info("airodump-ng capture started for %s (ch=%d)", bssid, channel)
        return CaptureSession(interface, bssid, prefix, proc, "airodump", time.time())

    @staticmethod
    def output_files(session: CaptureSession) -> list[Path]:
        """List the capture files produced so far (that actually exist)."""
        base = Path(session.out_prefix)
        patterns = [base.with_suffix(".pcapng"), base.with_suffix(".cap"),
                    Path(str(base) + "-01.cap"), Path(str(base) + "-01.pcapng"),
                    Path(str(base) + ".pcapng")]
        found: list[Path] = []
        for p in patterns:
            if p.exists() and p.stat().st_size > 0:
                found.append(p)
        return found
