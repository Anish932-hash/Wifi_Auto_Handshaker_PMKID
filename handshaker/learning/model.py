"""Action policy: epsilon-greedy bandit over *tried* deauth actions.

Anti-hallucination guarantees baked into this class:

* An action is only ever *selected* if it has been tried at least once (or is
  the bounded exploration pick). Untried actions have no success rate and are
  never "assumed" to be good.
* Success rates are recomputed from raw, decayed measurements on every call.
* ``min_observations`` gates exploitation: until we have enough evidence, the
  policy stays near-uniform (honest uncertainty) rather than jumping to a
  conclusion from a single lucky trial.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass

from .state import ActionKey, LearningStore


@dataclass
class PolicyDecision:
    """A chosen deauth action plus the (honest) rationale behind it."""

    action: ActionKey
    exploration: bool
    reason: str


class ActionPolicy:
    def __init__(
        self,
        store: LearningStore,
        *,
        exploration: float = 0.25,
        min_observations: int = 2,
        seed: int | None = None,
    ) -> None:
        self.store = store
        self.exploration = exploration
        self.min_observations = min_observations
        self._rng = random.Random(seed)

    def available_actions(self, bssid: str) -> list[ActionKey]:
        """Every action that has been recorded for this BSSID (deduplicated)."""
        seen: set[str] = set()
        out: list[ActionKey] = []
        for act in self.store.actions_for(bssid):
            key = ActionKey(act["tool"], int(act["burst"]), int(act["reason"]))
            if key.id not in seen:
                seen.add(key.id)
                out.append(key)
        return out

    def choose(self, bssid: str, candidate_actions: list[ActionKey]) -> PolicyDecision:
        """Choose a deauth action.

        ``candidate_actions`` is the set the caller is *willing and able* to
        perform (e.g. only tools actually installed). The policy never returns
        an action outside this set.
        """
        if not candidate_actions:
            raise ValueError("choose() requires at least one candidate action")

        stats = self.store.action_stats(bssid, now=time.time())
        total_trials = sum(s["trials"] for s in stats.values())

        # Honest uncertainty: not enough evidence yet -> uniform random.
        if total_trials < self.min_observations:
            action = self._rng.choice(candidate_actions)
            return PolicyDecision(
                action=action, exploration=True,
                reason=f"insufficient evidence ({total_trials:.1f} weighted trials); exploring",
            )

        # Explore with probability `exploration`.
        if self._rng.random() < self.exploration:
            action = self._rng.choice(candidate_actions)
            return PolicyDecision(action=action, exploration=True, reason="epsilon-greedy exploration")

        # Exploit: best observed success rate among the candidate actions.
        best: ActionKey | None = None
        best_rate = -1.0
        for action in candidate_actions:
            rate = stats.get(action.id, {}).get("rate", 0.0)
            if rate > best_rate:
                best_rate = rate
                best = action
        if best is None:
            best = self._rng.choice(candidate_actions)
        return PolicyDecision(
            action=best, exploration=False,
            reason=f"exploiting best observed rate {best_rate:.2f}",
        )

    def best_action(self, bssid: str, candidate_actions: list[ActionKey]) -> ActionKey | None:
        """Deterministic best observed action (for reporting), or None."""
        stats = self.store.action_stats(bssid, now=time.time())
        best: ActionKey | None = None
        best_rate = -1.0
        for action in candidate_actions:
            rate = stats.get(action.id, {}).get("rate", 0.0)
            if rate > best_rate:
                best_rate = rate
                best = action
        return best
