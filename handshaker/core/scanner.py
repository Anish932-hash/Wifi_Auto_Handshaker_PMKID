"""WiFi scanner — discovers nearby APs and their clients via airodump-ng.

Scan results are parsed from airodump-ng's CSV output with strict parsers that
yield ``None`` on malformed rows. The downstream strategist therefore only ever
sees *measured* APs, never fabricated ones.
"""

from __future__ import annotations

import csv
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..constants import BAND_2G, BAND_5G, TOOL_AIRODUMP_NG
from ..exceptions import CaptureError
from ..tools.registry import ToolRegistry
from ..utils.proc import run
from ..utils.validation import parse_channel, parse_int, parse_mac, parse_signal_dbm

log = logging.getLogger("handshaker.scanner")


@dataclass
class AccessPoint:
    """A measured access point (fields are exactly what airodump reported)."""

    bssid: str
    first_seen: str = ""
    last_seen: str = ""
    channel: int = 0
    speed: int = 0
    privacy: str = ""
    cipher: str = ""
    auth: str = ""
    power: int = -100
    beacons: int = 0
    ivs: int = 0
    lan_ip: str = ""
    id_len: int = 0
    essid: str = ""
    key: str = ""

    @property
    def band(self) -> str:
        if 1 <= self.channel <= 14:
            return BAND_2G
        if 36 <= self.channel <= 177:
            return BAND_5G
        return BAND_5G  # 6GHz channels are uncommon in airodump; fall back 5G

    @property
    def is_wpa(self) -> bool:
        return "WPA" in self.privacy.upper() or "WPA" in self.auth.upper()

    @property
    def security_label(self) -> str:
        auth = self.auth.upper()
        if "WPA3" in auth:
            return "WPA3"
        if "WPA2" in auth:
            return "WPA2"
        if "WPA" in auth:
            return "WPA"
        if "WEP" in self.privacy.upper():
            return "WEP"
        return "OPN"

    def summary(self) -> str:
        return (
            f"{self.bssid}  ch={self.channel}  sig={self.power}dBm  "
            f"sec={self.security_label}  clients={0}  '{self.essid}'"
        )


@dataclass
class Client:
    """A measured station (client) associated with an AP."""

    station_mac: str
    bssid: str
    power: int = -100
    packets: int = 0
    probed_essids: str = ""


@dataclass
class ScanResult:
    """Full result of one scan pass."""

    aps: dict[str, AccessPoint] = field(default_factory=dict)
    clients: dict[str, Client] = field(default_factory=dict)
    started_at: float = 0.0
    duration: float = 0.0

    def clients_of(self, bssid: str) -> list[Client]:
        return [c for c in self.clients.values() if c.bssid == bssid]


class Scanner:
    def __init__(self, registry: ToolRegistry, config: dict) -> None:
        self.registry = registry
        self.config = config

    def scan(self, interface: str, duration: int | None = None) -> ScanResult:
        """Run airodump-ng for ``duration`` seconds and parse the results."""
        if not self.registry.has(TOOL_AIRODUMP_NG):
            raise CaptureError("airodump-ng is required for scanning but is not installed.")

        dwell = duration if duration is not None else int(self.config["scan"]["dwell"])
        prefix = f"/tmp/handshaker_scan_{int(time.time())}"
        bands = self.config["scan"]["bands"]
        band_flag = _band_flag(bands)

        log.info("Scanning for %ss (band=%s)...", dwell, band_flag)
        run(
            [self.registry.airodump().path, interface, "-w", prefix,
             "--band", band_flag, "--output-format", "csv"],
            timeout=dwell + 15,
            check=False,
        )

        result = self._parse(prefix, dwell)
        self._cleanup(prefix)
        result.duration = time.time() - result.started_at
        return result

    # ------------------------------------------------------------------ #
    def _parse(self, prefix: str, dwell: int) -> ScanResult:
        result = ScanResult(started_at=time.time())
        csv_path = Path(f"{prefix}-01.csv")
        if not csv_path.exists():
            # airodump sometimes names the first file without -01.
            csv_path = Path(f"{prefix}.csv")
        if not csv_path.exists():
            log.warning("No scan CSV produced at %s", prefix)
            return result

        aps: dict[str, AccessPoint] = {}
        clients: dict[str, Client] = {}
        section: str | None = None

        with csv_path.open(newline="", errors="replace") as fh:
            reader = csv.reader(fh)
            for row in reader:
                if not row:
                    continue
                joined = ",".join(row)
                if joined.startswith("BSSID"):
                    section = "ap"
                    continue
                if joined.startswith("Station MAC"):
                    section = "client"
                    continue
                if section == "ap":
                    ap = _parse_ap_row(row)
                    if ap:
                        aps[ap.bssid] = ap
                elif section == "client":
                    cli = _parse_client_row(row)
                    if cli:
                        clients[cli.station_mac] = cli

        result.aps = aps
        result.clients = clients
        return result

    @staticmethod
    def _cleanup(prefix: str) -> None:
        for suffix in (".csv", "-01.csv", "-01.cap", "-01.kismet.csv",
                       "-01.kismet.netxml", ".cap", ".netxml", ".kismet.csv"):
            p = Path(f"{prefix}{suffix}")
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass


def _band_flag(bands: list[str]) -> str:
    flags = ""
    if "2.4GHz" in bands:
        flags += "bg"
    if "5GHz" in bands:
        flags += "a"
    if "6GHz" in bands:
        flags += "x"
    return flags or "abg"


def _parse_ap_row(row: list[str]) -> AccessPoint | None:
    # airodump CSV columns (typical):
    # BSSID, First time, Last time, channel, Speed, Privacy, Cipher, Auth, Power,
    # # beacons, # IV, LAN IP, ID-length, ESSID, Key
    if len(row) < 15:
        return None
    bssid = parse_mac(row[0])
    if not bssid:
        return None
    channel = parse_channel(row[3]) or 0
    return AccessPoint(
        bssid=bssid,
        first_seen=row[1].strip(),
        last_seen=row[2].strip(),
        channel=channel,
        speed=parse_int(row[4]) or 0,
        privacy=row[5].strip(),
        cipher=row[6].strip(),
        auth=row[7].strip(),
        power=parse_signal_dbm(row[8]) or -100,
        beacons=parse_int(row[9]) or 0,
        ivs=parse_int(row[10]) or 0,
        lan_ip=row[11].strip(),
        id_len=parse_int(row[12]) or 0,
        essid=row[13].strip(),
        key=row[14].strip() if len(row) > 14 else "",
    )


def _parse_client_row(row: list[str]) -> Client | None:
    # Station MAC, First time, Last time, Power, # packets, BSSID, Probed ESSIDs
    if len(row) < 6:
        return None
    station = parse_mac(row[0])
    bssid = parse_mac(row[5]) if row[5].strip() != "(not associated)" else None
    if not station:
        return None
    return Client(
        station_mac=station,
        bssid=bssid or "",
        power=parse_signal_dbm(row[3]) or -100,
        packets=parse_int(row[4]) or 0,
        probed_essids=row[6] if len(row) > 6 else "",
    )
