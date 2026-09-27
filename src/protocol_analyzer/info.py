from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .records import CanFrame
from .sources import open_capture


@dataclass
class CaptureInfo:
    records: int = 0
    first: float | None = None
    last: float | None = None
    channels: Counter = field(default_factory=Counter)  # Records per Channel
    can_ids: Counter = field(default_factory=Counter)  # frames per CAN id, error frames excluded
    error_frames: int = 0
    uart_bytes: Counter = field(default_factory=Counter)  # bytes per UART Channel


def capture_info(path: str | Path) -> CaptureInfo:
    info = CaptureInfo()
    for record in open_capture(path):
        info.records += 1
        info.channels[record.channel] += 1
        if record.timestamp is not None:
            info.first = record.timestamp if info.first is None else min(info.first, record.timestamp)
            info.last = record.timestamp if info.last is None else max(info.last, record.timestamp)
        if isinstance(record, CanFrame):
            if record.is_error:
                info.error_frames += 1
            else:
                info.can_ids[record.id] += 1
        else:
            info.uart_bytes[record.channel] += len(record.data)
    return info


def format_info(info: CaptureInfo) -> str:
    lines = [f"records:  {info.records}"]
    if info.first is not None and info.last is not None:
        lines.append(f"time:     {info.first:.6f} .. {info.last:.6f} ({info.last - info.first:.6f} s)")
    channels = ", ".join(f"{ch} ({n})" for ch, n in sorted(info.channels.items()))
    lines.append(f"channels: {channels or 'none'}")
    if info.can_ids:
        lines.append("CAN ids:")
        lines += [f"  0x{can_id:03X}  {n}" for can_id, n in sorted(info.can_ids.items())]
    if info.error_frames:
        lines.append(f"error frames: {info.error_frames}")
    lines += [f"UART {ch}: {n} bytes" for ch, n in sorted(info.uart_bytes.items())]
    return "\n".join(lines)
