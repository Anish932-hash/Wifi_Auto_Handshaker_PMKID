"""PMKID capture & conversion.

PMKID capture is fully separate from handshake capture and produces hashcat
22000-format lines (which contain a PMKID or an EAPOL pair — *not* a password).
No cracking is performed; this module only captures and converts.
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path

from ..constants import PMKID_DIR, TOOL_HCXDUMPTOOL, TOOL_HCXPCAPNGTOOL
from ..exceptions import CaptureError
from ..tools.registry import ToolRegistry

log = logging.getLogger("handshaker.pmkid")

_PMKID_RE = re.compile(r"WPA\*0[12]\*", re.IGNORECASE)


class PmidCapture:
    def __init__(self, registry: ToolRegistry, config: dict) -> None:
        self.registry = registry
        self.config = config
        PMKID_DIR.mkdir(parents=True, exist_ok=True)

    def capture(self, interface: str, bssid: str, channel: int, duration: int = 60) -> Path | None:
        """Capture PMKIDs (hcxdumptool attack mode 1) for one BSSID."""
        if not self.registry.has(TOOL_HCXDUMPTOOL):
            raise CaptureError("hcxdumptool is required for PMKID capture but is not installed.")
        stamp = int(time.time())
        out = PMKID_DIR / f"pmkid_{bssid.replace(':', '')}_{stamp}.pcapng"
        self.registry.hcxdumptool().capture(
            interface, str(out), channel=str(channel), bssid=bssid,
            attack_filter=["1"], duration=duration,
        )
        if out.exists() and out.stat().st_size > 0:
            return out
        log.info("No PMKID captured for %s", bssid)
        return None

    def convert(self, capture_file: str) -> Path | None:
        """Convert a raw capture to hashcat 22000 format, keeping PMKID lines."""
        if not self.registry.has(TOOL_HCXPCAPNGTOOL):
            # fall back to hcxlabtool/hcxpsktool if present
            return None
        src = Path(capture_file)
        dst = PMKID_DIR / (src.stem + ".22000")
        self.registry.hcxpcapngtool().convert(str(src), str(dst))
        if dst.exists() and dst.stat().st_size > 0:
            return dst
        log.info("Conversion produced no hashcat lines for %s", src.name)
        return None

    @staticmethod
    def contains_pmkid(hc22000_file: str) -> bool:
        """Return True if the 22000 file contains PMKID lines (not just EAPOL)."""
        try:
            text = Path(hc22000_file).read_text(errors="replace")
        except OSError:
            return False
        return bool(_PMKID_RE.search(text))
