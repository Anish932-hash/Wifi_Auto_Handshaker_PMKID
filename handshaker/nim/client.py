"""NVIDIA NIM chat-completions client for *optional* strategy suggestions.

Uses the standard ``urllib`` stdlib so there is no hard dependency on an SDK.
The API key is read from the ``NIM_API_KEY`` environment variable first, then
from config — never hard-coded, never stored in the repo.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("handshaker.nim")

_DEFAULT_URL = "https://integrate.api.nvidia.com/v1"


@dataclass
class NimConfig:
    enabled: bool = False
    api_key: str | None = None
    base_url: str = _DEFAULT_URL
    model: str | None = None
    timeout: int = 20
    max_suggestions: int = 8


@dataclass
class StrategySuggestion:
    """A validated strategy hint. Every field is schema-checked & clamped."""

    deauth_tool: str | None = None
    burst_size: int | None = None
    dwell_seconds: int | None = None
    prefer_pmkid: bool | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    rejected: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return all(v is None for v in (self.deauth_tool, self.burst_size,
                                       self.dwell_seconds, self.prefer_pmkid))


class NimClient:
    """Minimal, dependency-free NIM client with hard output validation."""

    def __init__(self, config: dict | None = None) -> None:
        cfg = (config or {}).get("nim", {}) or {}
        self.cfg = NimConfig(
            enabled=bool(cfg.get("enabled")),
            api_key=cfg.get("api_key") or os.environ.get("NIM_API_KEY"),
            base_url=cfg.get("base_url") or _DEFAULT_URL,
            model=cfg.get("model"),
            timeout=int(cfg.get("timeout", 20)),
            max_suggestions=int(cfg.get("max_suggestions", 8)),
        )

    @property
    def available(self) -> bool:
        return self.cfg.enabled and bool(self.cfg.api_key) and bool(self.cfg.model)

    def suggest_strategy(self, context: dict[str, Any]) -> StrategySuggestion:
        """Ask NIM for a strategy hint. Returns an empty suggestion on any
        failure — failures are logged truthfully, never masked."""
        if not self.available:
            return StrategySuggestion()

        prompt = self._build_prompt(context)
        payload = {
            "model": self.cfg.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a WiFi security-audit strategy assistant. "
                        "Return ONLY strict JSON with optional keys: "
                        "deauth_tool (one of: aireplay-ng, mdk4, bettercap), "
                        "burst_size (int 1..100), dwell_seconds (int 5..300), "
                        "prefer_pmkid (bool). Do not invent BSSIDs, passwords, "
                        "or results. Do not claim a handshake was captured."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.0,
            "max_tokens": 256,
        }
        try:
            text = self._post(payload)
            return self._parse(text)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
                json.JSONDecodeError, ValueError, OSError) as exc:
            log.warning("NIM suggestion failed (%s); proceeding independently", exc)
            return StrategySuggestion()

    # ------------------------------------------------------------------ #
    def _post(self, payload: dict[str, Any]) -> str:
        req = urllib.request.Request(
            self.cfg.base_url.rstrip("/") + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.cfg.api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.cfg.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"]

    @staticmethod
    def _build_prompt(context: dict[str, Any]) -> str:
        return (
            "Given this measured scan context, suggest a deauth/capture strategy "
            "as strict JSON only.\nContext (all values are measured, trust them):\n"
            + json.dumps(context, indent=2)
        )

    @staticmethod
    def _parse(text: str) -> StrategySuggestion:
        """Parse & validate NIM output. Anything malformed is rejected field-by-field."""
        # Tolerate fenced code blocks.
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if cleaned.lower().startswith("json"):
                cleaned = cleaned[4:]
        cleaned = cleaned.strip()

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            # Attempt to extract the first JSON object.
            import re
            m = re.search(r"\{.*\}", cleaned, re.DOTALL)
            if not m:
                return StrategySuggestion()
            try:
                data = json.loads(m.group(0))
            except json.JSONDecodeError:
                return StrategySuggestion()

        if not isinstance(data, dict):
            return StrategySuggestion()

        sug = StrategySuggestion(raw=data)
        allowed_tools = {"aireplay-ng", "mdk4", "bettercap"}

        tool = data.get("deauth_tool")
        if isinstance(tool, str) and tool in allowed_tools:
            sug.deauth_tool = tool
        elif tool is not None:
            sug.rejected.append(f"deauth_tool={tool!r}")

        burst = data.get("burst_size")
        if isinstance(burst, int) and 1 <= burst <= 100:
            sug.burst_size = burst
        elif burst is not None:
            sug.rejected.append(f"burst_size={burst!r}")

        dwell = data.get("dwell_seconds")
        if isinstance(dwell, int) and 5 <= dwell <= 300:
            sug.dwell_seconds = dwell
        elif dwell is not None:
            sug.rejected.append(f"dwell_seconds={dwell!r}")

        pmkid = data.get("prefer_pmkid")
        if isinstance(pmkid, bool):
            sug.prefer_pmkid = pmkid
        elif pmkid is not None:
            sug.rejected.append(f"prefer_pmkid={pmkid!r}")

        return sug
