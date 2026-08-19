"""Autonomous capture engine — orchestrates scan -> target -> deauth -> capture
-> verify -> learn in a closed loop.

The engine is deterministic at every step and keeps a hard separation between:

* **facts** (measured by tools) and
* **decisions** (made by the strategist from those facts).

It also enforces the authorization gate: capture/deauth will not start unless
the operator has explicitly acknowledged authorized use.
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..constants import (
    EXIT_AUTH_DENIED,
    EXIT_CAPTURE_FAILED,
    EXIT_NOT_ROOT,
    EXIT_NO_ADAPTER,
    EXIT_OK,
    EXIT_VERIFY_FAILED,
    HANDSHAKES_DIR,
    QUARANTINE_DIR,
)
from ..exceptions import (
    AdapterError,
    AuthorizationDeniedError,
    NoAdapterError,
    NotRootError,
)
from ..learning.state import ActionKey, LearningStore
from ..nim.client import NimClient
from ..tools.registry import ToolRegistry
from .adapter import AdapterManager
from .analyzer import Analyzer
from .capturer import Capturer
from .deauth import Deauther
from .pmkid import PmidCapture
from .scanner import AccessPoint, Scanner
from .strategist import Strategist
from .verifier import HandshakeVerifier

log = logging.getLogger("handshaker.engine")

_CONSENT_MARKER = Path("/tmp/.handshaker_authorized")


@dataclass
class RunStats:
    """Truthful summary of one autonomous run."""

    targets_scanned: int = 0
    targets_attacked: int = 0
    handshakes_captured: int = 0
    handshakes_rejected: int = 0
    pmkids_captured: int = 0
    failures: list[str] = field(default_factory=list)
    verified_files: list[str] = field(default_factory=list)


class Engine:
    def __init__(self, config: dict) -> None:
        self.config = config
        overrides = config["tools"].get("overrides", {})
        self.registry = ToolRegistry(overrides)
        self.adapter = AdapterManager(self.registry)
        self.scanner = Scanner(self.registry, config)
        self.capturer = Capturer(self.registry, config)
        self.verifier = HandshakeVerifier(self.registry, config)
        self.deauther = Deauther(self.registry, config)
        self.analyzer = Analyzer(self.registry)
        self.pmkid = PmidCapture(self.registry, config)
        self.store = LearningStore(
            path=None, decay=float(config["learning"]["decay"])
        )
        self.strategist = Strategist(self.registry, self.store, config)
        self.nim = NimClient(config)

        for d in (HANDSHAKES_DIR, QUARANTINE_DIR):
            d.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Safety gates
    # ------------------------------------------------------------------ #
    def check_root(self) -> None:
        if self.config["general"]["require_root"] and os.geteuid() != 0:
            raise NotRootError(
                "Capture, monitor mode, and deauth require root privileges. "
                "Re-run with `sudo`."
            )

    def require_authorization(self) -> None:
        """Interactive authorization gate. Fails closed unless the operator
        explicitly confirms authorized use."""
        if not self.config["general"]["consent_required"]:
            return
        if _CONSENT_MARKER.exists():
            return
        print("=" * 72)
        print(" AUTHORIZATION REQUIRED")
        print("=" * 72)
        print(
            " This tool captures WiFi 4-way handshakes and PMKIDs and performs\n"
            " deauthentication attacks. These actions are ILLEGAL against\n"
            " networks you do not own or lack explicit written permission to test.\n\n"
            " You may only use this tool on networks you own or are explicitly\n"
            " authorized to audit. You are solely responsible for lawful use.\n"
        )
        try:
            answer = input(
                "Type YES to confirm you have authorization to test the target\n"
                "network(s), or anything else to abort: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            raise AuthorizationDeniedError("No authorization confirmation given.")
        if answer != "YES":
            raise AuthorizationDeniedError("Authorization denied by operator.")
        _CONSENT_MARKER.touch()
        print("Authorization acknowledged. Proceeding.\n")

    def tool_report(self) -> dict[str, object]:
        """Report which Kali tools are present/missing (honest environment view)."""
        return {
            "available": sorted(self.registry.paths),
            "missing": self.registry.missing(),
        }

    # ------------------------------------------------------------------ #
    # One-shot operations (used by CLI subcommands)
    # ------------------------------------------------------------------ #
    def scan(self, interface: str, duration: int | None = None):
        return self.scanner.scan(interface, duration)

    def verify(self, capture_file: str):
        return self.verifier.verify_file(capture_file)

    def enforce_verification(self, capture_file: str):
        """Verify a file and, if it is NOT a genuine 4-way handshake, delete it."""
        report = self.verifier.verify_file(capture_file)
        if report.passed:
            return report, False
        if self.config["verify"]["delete_on_fail"]:
            if self.config["verify"]["quarantine_before_delete"]:
                dst = QUARANTINE_DIR / Path(capture_file).name
                shutil.move(capture_file, dst)
                log.info("quarantined non-handshake capture -> %s", dst)
                dst.unlink(missing_ok=True)  # delete after quarantine
            else:
                Path(capture_file).unlink(missing_ok=True)
            log.warning("DELETED %s: %s", Path(capture_file).name, report.reason)
        return report, True

    # ------------------------------------------------------------------ #
    # Full autonomous loop
    # ------------------------------------------------------------------ #
    def run_auto(self, interface: str, scan_duration: int | None = None) -> RunStats:
        self.check_root()
        self.require_authorization()
        self.adapter.unblock_rfkill()

        stats = RunStats()
        mon_iface = interface

        # 1) Prepare adapter (monitor mode + injection check).
        try:
            mon_iface = self.adapter.enable_monitor(interface)
        except AdapterError as exc:
            stats.failures.append(str(exc))
            return stats

        if self.config["adapter"]["check_injection"]:
            self.adapter.check_injection(mon_iface)

        # 2) Scan.
        scan = self.scanner.scan(mon_iface, scan_duration)
        stats.targets_scanned = len(scan.aps)
        if not scan.aps:
            log.warning("No APs found during scan.")
            self._cleanup_adapter(interface, mon_iface)
            return stats

        targets = self.strategist.prioritize(scan)
        log.info("Prioritized %d target(s): %s",
                 len(targets), [t.essid or t.bssid for t in targets])

        # Optional NIM hint (validated, never authoritative).
        nim_hint = self.nim.suggest_strategy(self._context(scan)) if self.nim.available else None

        candidates = self.strategist.candidate_actions()
        if not candidates:
            log.error("No deauth tools installed (need aireplay-ng/mdk4/bettercap).")
            self._cleanup_adapter(interface, mon_iface)
            return stats

        # 3) Per-target loop.
        for ap in targets:
            self._process_target(mon_iface, ap, scan, candidates, nim_hint, stats)

        self.store.save()
        self._cleanup_adapter(interface, mon_iface)
        return stats

    # ------------------------------------------------------------------ #
    def _process_target(self, mon_iface, ap, scan, candidates, nim_hint, stats) -> None:
        stats.targets_attacked += 1
        self.store.ensure_ap(ap.bssid, essid=ap.essid, channel=ap.channel,
                             security=ap.security_label)

        # Choose a deauth action (learning-driven, or NIM-hinted burst).
        decision = self.strategist.choose_action(ap.bssid, candidates)
        action = decision.action
        if nim_hint and nim_hint.burst_size:
            action = ActionKey(action.tool, nim_hint.burst_size, action.reason)
        log.info("Target %s: %s", ap.essid or ap.bssid, decision.reason)

        # (Optional) prefer PMKID capture first.
        if self.config["pmkid"]["enabled"] and (nim_hint and nim_hint.prefer_pmkid):
            self._try_pmkid(mon_iface, ap, stats)

        # Start capture.
        try:
            session = self.capturer.start(mon_iface, ap.bssid, ap.channel,
                                          essid=ap.essid)
        except Exception as exc:  # noqa: BLE001 - record, don't abort the loop
            stats.failures.append(f"capture start {ap.bssid}: {exc}")
            self.store.record(ap.bssid, action, success=False)
            return

        # Deauth campaign (strategic bursts).
        client = None
        clients = scan.clients_of(ap.bssid)
        if clients:
            client = clients[0].station_mac
        try:
            self.deauther.attack(mon_iface, ap.bssid, action, client=client)
        except Exception as exc:  # noqa: BLE001
            stats.failures.append(f"deauth {ap.bssid}: {exc}")

        time.sleep(2)
        session.stop()

        # Verify and enforce.
        success = False
        files = self.capturer.output_files(session)
        if not files:
            stats.failures.append(f"no capture output for {ap.bssid}")
        for f in files:
            report, deleted = self.enforce_verification(str(f))
            if report.passed:
                stats.handshakes_captured += 1
                stats.verified_files.append(str(f))
                dst = HANDSHAKES_DIR / f.name
                shutil.move(str(f), dst)
                success = True
            else:
                stats.handshakes_rejected += 1

        # Learn from the *verified* outcome only.
        self.store.record(ap.bssid, action, success=success)
        if success:
            log.info("✓ Handshake verified & stored for %s", ap.essid or ap.bssid)
        else:
            log.info("✗ No verified handshake for %s (learning from failure)", ap.essid or ap.bssid)

        # PMKID attempt (independent of handshake result).
        if self.config["pmkid"]["enabled"] and not (nim_hint and nim_hint.prefer_pmkid):
            self._try_pmkid(mon_iface, ap, stats)

    def _try_pmkid(self, mon_iface: str, ap: AccessPoint, stats: RunStats) -> None:
        try:
            cap = self.pmkid.capture(mon_iface, ap.bssid, ap.channel, duration=45)
            if cap:
                converted = self.pmkid.convert(str(cap))
                if converted:
                    stats.pmkids_captured += 1
                    log.info("PMKID captured for %s -> %s", ap.essid or ap.bssid, converted)
        except Exception as exc:  # noqa: BLE001
            stats.failures.append(f"pmkid {ap.bssid}: {exc}")

    def _context(self, scan) -> dict:
        """Build the measured context handed to NIM (facts only)."""
        aps = [
            {
                "bssid": a.bssid, "essid": a.essid, "channel": a.channel,
                "security": a.security_label, "signal": a.power,
                "clients": len(scan.clients_of(a.bssid)),
            }
            for a in list(scan.aps.values())[:20]
        ]
        return {"aps": aps, "tools": sorted(self.registry.paths)}

    def _cleanup_adapter(self, interface: str, mon_iface: str) -> None:
        if self.config["adapter"]["reset_on_exit"]:
            try:
                self.adapter.reset(mon_iface)
            except Exception as exc:  # noqa: BLE001
                log.warning("Adapter reset failed: %s", exc)


def exit_code_for(stats: RunStats, exception: Exception | None) -> int:
    if exception is not None:
        if isinstance(exception, NotRootError):
            return EXIT_NOT_ROOT
        if isinstance(exception, AuthorizationDeniedError):
            return EXIT_AUTH_DENIED
        if isinstance(exception, NoAdapterError):
            return EXIT_NO_ADAPTER
        return EXIT_CAPTURE_FAILED
    if stats.handshakes_captured > 0 or stats.pmkids_captured > 0:
        return EXIT_OK
    return EXIT_VERIFY_FAILED
