from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CanFrame:
    timestamp: float | None
    channel: str
    id: int
    data: bytes = b""
    dlc: int = 0
    is_extended: bool = False
    is_remote: bool = False
    is_fd: bool = False
    brs: bool = False
    esi: bool = False
    is_error: bool = False


@dataclass(frozen=True)
class UartChunk:
    timestamp: float | None  # None for captures without timestamps (raw .bin)
    channel: str
    offset: int  # byte offset of data[0] within this Channel's stream
    data: bytes


Record = CanFrame | UartChunk
