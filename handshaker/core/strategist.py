"""Strategist — decides *what* to attack and *how*, grounded in measurement.

The strategist is deterministic and evidence-based:

* Targets are prioritized from the *actual* scan (signal, WPA suite, client
  count) — never guessed.
* Deauth actions are chosen only from tools the registry proves are installed,
  via the adaptive bandit policy (bounded exploration).
* Every decision carries a rationale string for auditability.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..constants import SECURITY_WEP, SECURITY_OPEN, WPA_SUITES
from ..learning.model import ActionPolicy, PolicyDecision
from ..learning.state import ActionKey, LearningStore
from ..tools.registry import ToolRegistry
from .scanner import AccessPoint, ScanResult

log = logging.getLogger("handshaker.strategist")


@dataclass
class TargetPlan:
    """A prioritized target and its chosen deauth action."""

    ap: AccessPoint
    priority: float
    decision: PolicyDecision | None = None
    reasons: list[str] = field(default_factory=list)


class Strategist:
    def __init__(
        self,
        registry: ToolRegistry,
        store: LearningStore,
        config: dict,
    ) -> None:
        self.registry = registry
        self.config = config
        learn_cfg = config["learning"]
        self.policy = ActionPolicy(
            store,
            exploration=float(learn_cfg["exploration"]),
            min_observations=int(learn_cfg["min_observations"]),
        )

    # ------------------------------------------------------------------ #
    # Target prioritization
    # ------------------------------------------------------------------ #
    def prioritize(self, scan: ScanResult) -> list[AccessPoint]:
        """Rank in-scope APs into an ordered target list."""
        tg = self.config["targets"]
        wpa_only = bool(self.config["capture"]["wpa_only"])
        min_signal = int(self.config["scan"]["min_signal"])
        exclude = {b.lower() for b in tg.get("exclude", [])}

        explicit_bssids = {b.lower() for b in tg.get("bssid", [])}
        explicit_essids = [e.lower() for e in tg.get("essid", [])]
        explicit_channels = {int(c) for c in tg.get("channel", [])}

        candidates: list[AccessPoint] = []
        for ap in scan.aps.values():
            if ap.bssid.lower() in exclude:
                continue
            if wpa_only and ap.security_label in (SECURITY_WEP, SECURITY_OPEN):
                continue
            if ap.security_label not in WPA_SUITES and ap.security_label not in (SECURITY_WEP, SECURITY_OPEN):
                # Unknown suite: only proceed if not wpa_only (report truthfully).
                if wpa_only:
                    continue
            if ap.power < min_signal:
                continue
            if explicit_bssids and ap.bssid.lower() not in explicit_bssids:
                continue
            if explicit_essids and ap.essid.lower() not in explicit_essids:
                continue
            if explicit_channels and ap.channel not in explicit_channels:
                continue
            candidates.append(ap)

        # Score: stronger signal, more clients, WPA2/3 over WPA, explicit targets first.
        def score(ap: AccessPoint) -> tuple[float, int]:
            clients = len(scan.clients_of(ap.bssid))
            explicit_bonus = 100.0 if ap.bssid.lower() in explicit_bssids else 0.0
            suite_bonus = {"WPA3": 20.0, "WPA2": 15.0, "WPA": 5.0}.get(ap.security_label, 0.0)
            s = (
                explicit_bonus
                + suite_bonus
                + max(0, ap.power + 100)          # 0..100 from signal
                + min(clients, 10) * 3            # clients make handshake capture easier
            )
            return (s, -abs(ap.power))

        candidates.sort(key=score, reverse=True)
        max_targets = int(tg.get("max_targets", 0) or 0)
        if max_targets > 0:
            candidates = candidates[:max_targets]
        return candidates

    # ------------------------------------------------------------------ #
    # Deauth action selection
    # ------------------------------------------------------------------ #
    def candidate_actions(self) -> list[ActionKey]:
        """All deauth actions the *installed* toolset can perform."""
        tools = self.config["deauth"]["tools"]
        bursts = _burst_options(int(self.config["deauth"]["burst_size"]))
        reasons = [int(r) for r in self.config["deauth"]["reason_codes"]]
        actions: list[ActionKey] = []
        for tool in tools:
            if not self.registry.has(tool):
                log.debug("deauth tool %s not installed; skipped", tool)
                continue
            for burst in bursts:
                for reason in reasons:
                    actions.append(ActionKey(tool=tool, burst=burst, reason=reason))
        return actions

    def choose_action(self, bssid: str, candidates: list[ActionKey]) -> PolicyDecision:
        return self.policy.choose(bssid, candidates)


def _burst_options(base: int) -> list[int]:
    """Generate a small, ordered set of burst sizes around ``base``.

    This gives the bandit meaningful variation to learn from without exploding
    the action space.
    """
    if base <= 0:
        base = 10
    options = {base, base * 2, max(1, base // 2)}
    return sorted(options)
