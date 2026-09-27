from __future__ import annotations

import argparse
from dataclasses import dataclass, field

from .message import Message
from .records import CanFrame


@dataclass
class Filters:
    ids: set[int] = field(default_factory=set)
    nodes: set[int] = field(default_factory=set)
    services: set[str] = field(default_factory=set)
    channels: set[str] = field(default_factory=set)
    errors_only: bool = False
    time_range: tuple[float | None, float | None] = (None, None)

    def __post_init__(self) -> None:
        self.services = {s.lower() for s in self.services}

    def matches(self, msg: Message, t0: float | None, absolute: bool = False) -> bool:
        if self.channels and msg.channel not in self.channels:
            return False
        if self.services and msg.name.lower() not in self.services:
            return False
        if self.errors_only and not msg.has_errors:
            return False
        if self.ids and not any(isinstance(s, CanFrame) and s.id in self.ids for s in msg.sources):
            return False
        if self.nodes:
            node = msg.get("node")
            if node is None or node.value not in self.nodes:
                return False
        lo, hi = self.time_range
        if lo is not None or hi is not None:
            if msg.start is None:
                return False
            t = msg.start if absolute or t0 is None else msg.start - t0
            if (lo is not None and t < lo) or (hi is not None and t > hi):
                return False
        return True


def int_set(text: str) -> set[int]:
    try:
        return {int(part, 0) for part in text.split(",") if part.strip()}
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"expected comma-separated integers (decimal or 0x-prefixed), got {text!r}") from None


def csv_set(text: str) -> set[str]:
    return {part.strip() for part in text.split(",") if part.strip()}


def time_range(text: str) -> tuple[float | None, float | None]:
    start, sep, end = text.partition(":")
    try:
        if not sep:
            raise ValueError
        return (float(start) if start else None, float(end) if end else None)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected START:END in seconds, got {text!r}") from None
