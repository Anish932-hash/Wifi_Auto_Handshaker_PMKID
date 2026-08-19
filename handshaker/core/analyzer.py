"""Capture analysis for strategic decision-making (via Wireshark/tshark).

The engine uses this module to understand a target's real behaviour — is the
AP actually sending beacons? are clients active? is there PMKID chatter? — so
deauth is timed and aimed rather than sprayed blindly.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..tools.registry import ToolRegistry

log = logging.getLogger("handshaker.analyzer")


@dataclass
class CaptureAnalysis:
    """Measured facts about a capture (empty where not measured)."""

    bssid: str
    eapol_count: int = 0
    beacon_count: int = 0
    probe_req_count: int = 0
    data_count: int = 0
    client_macs: set[str] = field(default_factory=set)

    @property
    def clients_active(self) -> bool:
        return bool(self.client_macs)

    def summary(self) -> str:
        return (
            f"bssid={self.bssid} eapol={self.eapol_count} beacons={self.beacon_count} "
            f"probes={self.probe_req_count} data={self.data_count} "
            f"clients={sorted(self.client_macs)}"
        )


class Analyzer:
    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def analyze(self, capture_file: str, bssid: str) -> CaptureAnalysis:
        """Analyze a capture with tshark; returns measured facts only."""
        a = CaptureAnalysis(bssid=bssid)
        if not self.registry.has("tshark"):
            log.warning("tshark unavailable; analysis skipped.")
            return a

        tshark = self.registry.tshark()
        a.eapol_count = tshark.frame_count(capture_file, "wlan_rsna_eapol")
        a.beacon_count = tshark.frame_count(
            capture_file, f"wlan.fc.type_subtype == 0x08 && wlan.bssid == {bssid}"
        )
        a.probe_req_count = tshark.frame_count(capture_file, "wlan.fc.type_subtype == 0x04")
        a.data_count = tshark.frame_count(capture_file, "wlan.fc.type == 2")

        # Clients = distinct stations that transmitted toward this BSSID.
        a.client_macs = self._client_macs(capture_file, bssid)
        return a

    def _client_macs(self, capture_file: str, bssid: str) -> set[str]:
        """Distinct station MACs observed communicating with the target BSSID."""
        from ..utils.proc import run

        out = run(
            [
                self.registry.tshark().path,
                "-r", capture_file,
                "-Y", f"wlan.bssid == {bssid} && wlan.sa",
                "-T", "fields", "-e", "wlan.sa",
            ],
            timeout=120, check=False,
        )
        clients: set[str] = set()
        for line in out.stdout.splitlines():
            mac = line.strip().lower()
            if mac and mac != bssid.lower():
                clients.add(mac)
        return clients
