"""Persistent learning state: per-AP profiles of measured outcomes.

The store is a plain JSON file keyed by BSSID. Every entry is a *measured*
fact (what tool, what burst, did we get a verified handshake, when). There is
no derived "score" stored — scores are recomputed on demand by the policy layer.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..constants import LEARNING_DIR
from ..exceptions import LearningStateError

_STATE_FILE = LEARNING_DIR / "state.json"


@dataclass(frozen=True)
class ActionKey:
    """The identity of a deauth action that was tried."""

    tool: str
    burst: int
    reason: int

    @property
    def id(self) -> str:
        return f"{self.tool}|{self.burst}|{self.reason}"


class LearningStore:
    """Thread-safe append-only record of measured capture outcomes."""

    def __init__(self, path: Path | None = None, decay: float = 0.95) -> None:
        self.path = path or _STATE_FILE
        self.decay = decay
        # RLock: record() -> ensure_ap() re-enters the lock on the same thread.
        self._lock = threading.RLock()
        self._data: dict[str, Any] = {"version": 1, "aps": {}}
        self._load()

    # ------------------------------------------------------------------ #
    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text())
            if isinstance(raw, dict) and isinstance(raw.get("aps"), dict):
                self._data = raw
        except (json.JSONDecodeError, OSError) as exc:
            raise LearningStateError(f"Corrupt learning state {self.path}: {exc}") from exc

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        with self._lock:
            tmp.write_text(json.dumps(self._data, indent=2))
            tmp.replace(self.path)

    # ------------------------------------------------------------------ #
    def ensure_ap(self, bssid: str, *, essid: str = "", channel: int = 0,
                  security: str = "") -> None:
        with self._lock:
            ap = self._data["aps"].setdefault(bssid, {
                "essid": essid, "channel": channel, "security": security,
                "actions": [],
            })
            # Update static metadata when we learn better values.
            if essid:
                ap["essid"] = essid
            if channel:
                ap["channel"] = channel
            if security:
                ap["security"] = security

    def record(self, bssid: str, action: ActionKey, success: bool) -> None:
        """Record a measured outcome. ``success`` must be backed by verification."""
        with self._lock:
            self.ensure_ap(bssid)
            ap = self._data["aps"][bssid]
            ap["actions"].append({
                "tool": action.tool,
                "burst": action.burst,
                "reason": action.reason,
                "success": bool(success),
                "ts": time.time(),
            })

    def profile(self, bssid: str) -> dict[str, Any] | None:
        with self._lock:
            ap = self._data["aps"].get(bssid)
            return dict(ap) if ap else None

    def actions_for(self, bssid: str) -> list[dict[str, Any]]:
        ap = self.profile(bssid)
        return ap.get("actions", []) if ap else []

    # ------------------------------------------------------------------ #
    # Recomputed statistics (never stored; derived fresh on every call).
    # ------------------------------------------------------------------ #
    def action_stats(self, bssid: str, *, now: float | None = None) -> dict[str, dict[str, float]]:
        """Return {action_id: {trials, wins, rate}} with time-decayed weights.

        Older observations contribute less weight, so stale data does not
        dominate. This is the only place success rates are computed.
        """
        now = now if now is not None else time.time()
        stats: dict[str, dict[str, float]] = {}
        for act in self.actions_for(bssid):
            aid = f"{act['tool']}|{act['burst']}|{act['reason']}"
            age = max(0.0, now - float(act.get("ts", now)))
            weight = self.decay ** (age / 60.0)  # decay per minute
            s = stats.setdefault(aid, {"trials": 0.0, "wins": 0.0, "rate": 0.0})
            s["trials"] += weight
            if act.get("success"):
                s["wins"] += weight
        for s in stats.values():
            s["rate"] = (s["wins"] / s["trials"]) if s["trials"] > 0 else 0.0
        return stats
