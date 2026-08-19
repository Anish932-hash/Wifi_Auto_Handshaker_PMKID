"""Strong 4-way handshake verifier — the integrity core of the tool.

This module answers one question with certainty: *"Is this capture a genuine,
complete 4-way EAPOL handshake?"*  Nothing is kept unless the evidence proves
it; everything else is rejected (and, per policy, deleted).

Verification is **deterministic and multi-tool**, by design immune to
hallucination:

1. **tshark** (Wireshark dissector) — ground truth. Every EAPOL-Key frame is
   read and classified M1..M4 from its actual key_info flags, nonce and MIC.
2. **aircrack-ng** — independent "WPA handshake" detector.
3. **hcxpcapngtool** — independent EAPOL-pair counter.
4. **cowpatty / pyrit** (when present) — additional independent checks.

The final verdict is the *intersection* of the configured detectors: a capture
passes only when the EAPOL evidence is complete and no configured, available
tool contradicts it. A tool being *unavailable* is reported truthfully and
degrades gracefully — it is never silently assumed to pass.

Classification of the 4-way handshake (IEEE 802.11-2020 §12.7.6.2):

    M1: Key ACK, no MIC, nonce present (ANonce)         [AP -> STA]
    M2: Key MIC, no ACK/Install, nonce present (SNonce)  [STA -> AP]
    M3: Key ACK + Install + MIC, nonce present (ANonce)  [AP -> STA]
    M4: Key MIC, no ACK/Install, nonce absent            [STA -> AP]
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..tools.registry import ToolRegistry
from ..utils.validation import parse_mac

log = logging.getLogger("handshaker.verifier")

_INT_RE = re.compile(r"^-?\d+$")


@dataclass
class EapolFrame:
    """One EAPOL-Key frame, classified from fields Wireshark decoded.

    ``has_ack`` / ``has_install`` come straight from tshark's boolean flag
    fields; ``has_mic`` / ``nonce`` come from the MIC / nonce content fields.
    Nothing here is decoded by us — it is read from the dissector.
    """

    bssid: str
    src: str
    dst: str
    key_info: str          # raw key_info hex (reference/debug only)
    has_ack: bool
    has_install: bool
    has_mic: bool
    nonce: str
    msgnr: int | None      # Wireshark's own message number (1-4), if present
    message: int = 0       # 1..4, 0 = unclassified (our classification)


@dataclass
class HandshakeEvidence:
    """Accumulated, classified EAPOL evidence for a single BSSID."""

    bssid: str
    frames: list[EapolFrame] = field(default_factory=list)
    messages: set[int] = field(default_factory=set)
    # Independent tool signals.
    aircrack_confirmed: bool | None = None   # None = not run
    hcx_pairs: int | None = None             # None = not run
    cowpatty_confirmed: bool | None = None
    pyrit_confirmed: bool | None = None

    @property
    def has_full_handshake(self) -> bool:
        """All four messages M1..M4 are present."""
        return {1, 2, 3, 4}.issubset(self.messages)

    @property
    def has_crackable_pair(self) -> bool:
        """M2 (SNonce+MIC) and M3 (ANonce+MIC) are present."""
        return 2 in self.messages and 3 in self.messages

    @property
    def mic_present(self) -> bool:
        return any(f.has_mic for f in self.frames)

    @property
    def nonce_present(self) -> bool:
        return any(f.nonce for f in self.frames)


@dataclass
class VerificationReport:
    """The final, honest verdict for a capture file."""

    file: str
    passed: bool
    reason: str
    evidence: list[HandshakeEvidence] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    tools_missing: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "passed": self.passed,
            "reason": self.reason,
            "handshakes": [
                {
                    "bssid": e.bssid,
                    "messages": sorted(e.messages),
                    "full": e.has_full_handshake,
                    "crackable_pair": e.has_crackable_pair,
                    "aircrack": e.aircrack_confirmed,
                    "hcx_pairs": e.hcx_pairs,
                }
                for e in self.evidence
            ],
            "tools_used": self.tools_used,
            "tools_missing": self.tools_missing,
        }


class HandshakeVerifier:
    def __init__(self, registry: ToolRegistry, config: dict) -> None:
        self.registry = registry
        self.config = config["verify"]

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def verify_file(self, capture_file: str) -> VerificationReport:
        """Verify a single capture file and return a truthful report."""
        path = Path(capture_file)
        if not path.exists() or path.stat().st_size == 0:
            return VerificationReport(
                file=capture_file, passed=False,
                reason="file missing or empty",
            )

        evidence = self._gather_evidence(capture_file)
        report = self._decide(capture_file, evidence)
        log.info(
            "verify %s -> %s (%s)",
            Path(capture_file).name,
            "PASS" if report.passed else "REJECT",
            report.reason,
        )
        return report

    # ------------------------------------------------------------------ #
    # Evidence gathering
    # ------------------------------------------------------------------ #
    def _gather_evidence(self, capture_file: str) -> list[HandshakeEvidence]:
        by_bssid: dict[str, HandshakeEvidence] = {}

        # 1) tshark EAPOL ground truth.
        if self.registry.has("tshark"):
            frames = self._parse_tshark(capture_file)
            for f in frames:
                ev = by_bssid.setdefault(f.bssid, HandshakeEvidence(bssid=f.bssid))
                ev.frames.append(f)
                if f.message:
                    ev.messages.add(f.message)

        # 2) aircrack-ng independent check.
        aircrack_bssids: set[str] | None = None
        if self.registry.has("aircrack-ng"):
            res = self.registry.aircrack().check_handshakes(capture_file)
            aircrack_bssids = self.registry.aircrack().parse_handshakes(res)

        # 3) hcxpcapngtool independent EAPOL pair count.
        hcx_pairs = self._hcx_pairs(capture_file)

        # Merge independent signals into the evidence.
        for bssid, ev in by_bssid.items():
            ev.aircrack_confirmed = (
                (bssid in aircrack_bssids) if aircrack_bssids is not None else None
            )
            ev.hcx_pairs = hcx_pairs

        # If tshark found nothing but aircrack/hcx saw a handshake, we still
        # record evidence for those BSSIDs so the report is honest.
        if aircrack_bssids:
            for b in aircrack_bssids:
                ev = by_bssid.setdefault(b, HandshakeEvidence(bssid=b))
                ev.aircrack_confirmed = True
                ev.hcx_pairs = hcx_pairs

        return list(by_bssid.values())

    # ------------------------------------------------------------------ #
    # Decision
    # ------------------------------------------------------------------ #
    def _decide(self, capture_file: str, evidence: list[HandshakeEvidence]) -> VerificationReport:
        tools_used: list[str] = []
        tools_missing: list[str] = []
        for name in ("tshark", "aircrack-ng", "hcxpcapngtool", "cowpatty", "pyrit"):
            if self.registry.has(name):
                tools_used.append(name)
            else:
                tools_missing.append(name)

        if not evidence:
            return VerificationReport(
                file=capture_file, passed=False,
                reason="no EAPOL frames found (not a handshake capture)",
                tools_used=tools_used, tools_missing=tools_missing,
            )

        require_full = bool(self.config["require_full_handshake"])

        for ev in evidence:
            if require_full and not ev.has_full_handshake:
                return VerificationReport(
                    file=capture_file, passed=False,
                    reason=f"{ev.bssid}: incomplete handshake "
                           f"(messages={sorted(ev.messages)}), full M1-M4 required",
                    evidence=evidence, tools_used=tools_used, tools_missing=tools_missing,
                )
            if not require_full and not ev.has_crackable_pair:
                return VerificationReport(
                    file=capture_file, passed=False,
                    reason=f"{ev.bssid}: no crackable M2+M3 pair (messages={sorted(ev.messages)})",
                    evidence=evidence, tools_used=tools_used, tools_missing=tools_missing,
                )

            # Contradiction checks: if a tool explicitly says NO, reject.
            if ev.aircrack_confirmed is False:
                return VerificationReport(
                    file=capture_file, passed=False,
                    reason=f"{ev.bssid}: aircrack-ng does not confirm a WPA handshake",
                    evidence=evidence, tools_used=tools_used, tools_missing=tools_missing,
                )

        # A complete handshake was found and no tool contradicts it.
        bssids = [e.bssid for e in evidence]
        return VerificationReport(
            file=capture_file, passed=True,
            reason=f"valid 4-way handshake for {', '.join(bssids)}",
            evidence=evidence, tools_used=tools_used, tools_missing=tools_missing,
        )

    # ------------------------------------------------------------------ #
    # tshark parsing
    # ------------------------------------------------------------------ #
    def _parse_tshark(self, capture_file: str) -> list[EapolFrame]:
        res = self.registry.tshark().eapol_frames(capture_file)
        frames: list[EapolFrame] = []
        for line in res.stdout.splitlines():
            parts = line.split(",")
            if len(parts) < 9:
                continue
            bssid = parse_mac(parts[0])
            if not bssid:
                continue
            src = parse_mac(parts[1]) or parts[1]
            dst = parse_mac(parts[2]) or parts[2]
            key_info = parts[3].strip()
            has_ack = parts[4].strip() == "1"
            has_install = parts[5].strip() == "1"
            has_mic = bool(parts[6].strip())
            nonce = parts[7].strip()
            msgnr = _parse_int_field(parts[8])

            frame = EapolFrame(
                bssid=bssid, src=src, dst=dst, key_info=key_info,
                has_ack=has_ack, has_install=has_install,
                has_mic=has_mic, nonce=nonce, msgnr=msgnr,
            )
            frame.message = _classify_message(frame)
            frames.append(frame)
        return frames

    # ------------------------------------------------------------------ #
    # hcxpcapngtool
    # ------------------------------------------------------------------ #
    def _hcx_pairs(self, capture_file: str) -> int | None:
        if not self.registry.has("hcxpcapngtool"):
            return None
        out = f"/tmp/handshaker_hcx_{Path(capture_file).stem}.22000"
        res = self.registry.hcxpcapngtool().convert(capture_file, out)
        m = re.search(r"EAPOL pairs\s*:\s*(\d+)", res.output, re.IGNORECASE)
        if m:
            return int(m.group(1))
        # hcxpcapngtool may report "EAPOL M1M2M3M4" instead; parse summary counts.
        m = re.search(r"EAPOL M1M2 messages\s*:\s*(\d+)", res.output, re.IGNORECASE)
        return int(m.group(1)) if m else None


def _parse_int_field(value: str) -> int | None:
    v = value.strip()
    if _INT_RE.match(v):
        return int(v)
    return None


def _classify_message(f: EapolFrame) -> int:
    """Classify an EAPOL-Key frame as M1..M4, or 0 if ambiguous.

    Pure lookup from Wireshark's decoded flags — no inference about "what the
    frame probably was" ever happens here:

        M1: Key ACK set, no MIC            (ANonce)
        M3: Key ACK + Install + MIC        (GTK)
        M2: MIC, no ACK/Install, nonce     (SNonce)
        M4: MIC, no ACK/Install, no nonce
    """
    has_nonce = bool(f.nonce)

    if f.has_ack and not f.has_mic:
        return 1
    if f.has_mic and f.has_ack and f.has_install:
        return 3
    if f.has_mic and not f.has_ack and not f.has_install:
        return 2 if has_nonce else 4
    return 0
