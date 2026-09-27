from __future__ import annotations

from pathlib import Path
from typing import Iterator

from ..errors import CaptureError
from ..records import UartChunk

RAW_CHANNEL = "uart0"
CHUNK_SIZE = 4096


def read_uart_capture(path: Path) -> Iterator[UartChunk]:
    if path.suffix.lower() == ".bin":
        return _read_bin(path)
    return _read_hex(path)


def _read_bin(path: Path) -> Iterator[UartChunk]:
    offset = 0
    with path.open("rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            yield UartChunk(None, RAW_CHANNEL, offset, chunk)
            offset += len(chunk)


def _read_hex(path: Path) -> Iterator[UartChunk]:
    offsets: dict[str, int] = {}
    with path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            text = line.split("#", 1)[0].strip()
            if not text:
                continue
            parts = text.split()
            where = f"{path.name}:{lineno}"
            if len(parts) < 3:
                raise CaptureError(f"{where}: expected '<seconds> <channel> <hex bytes>'")
            try:
                timestamp = float(parts[0])
            except ValueError:
                raise CaptureError(f"{where}: bad timestamp {parts[0]!r}") from None
            try:
                data = bytes.fromhex("".join(parts[2:]))
            except ValueError:
                raise CaptureError(f"{where}: bad hex bytes") from None
            channel = parts[1]
            offset = offsets.get(channel, 0)
            offsets[channel] = offset + len(data)
            yield UartChunk(timestamp, channel, offset, data)
