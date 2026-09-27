from __future__ import annotations

from pathlib import Path
from typing import Iterator

from ..errors import CaptureError
from ..records import Record
from .can_files import read_can_capture
from .uart_files import read_uart_capture

CAN_SUFFIXES = {".log", ".asc"}
UART_SUFFIXES = {".bin", ".hex", ".txt"}


def capture_kind(path: str | Path) -> str:
    suffix = Path(path).suffix.lower()
    if suffix in CAN_SUFFIXES:
        return "can"
    if suffix in UART_SUFFIXES:
        return "uart"
    known = ", ".join(sorted(CAN_SUFFIXES | UART_SUFFIXES))
    raise CaptureError(f"{path}: unknown capture type '{suffix}' (expected one of {known})")


def open_capture(path: str | Path) -> Iterator[Record]:
    p = Path(path)
    kind = capture_kind(p)
    if not p.is_file():
        raise CaptureError(f"{p}: no such file")
    return read_can_capture(p) if kind == "can" else read_uart_capture(p)
