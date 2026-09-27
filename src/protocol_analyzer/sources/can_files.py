from __future__ import annotations

from pathlib import Path
from typing import Iterator

import can

from ..errors import CaptureError
from ..records import CanFrame


def read_can_capture(path: Path) -> Iterator[CanFrame]:
    is_asc = path.suffix.lower() == ".asc"
    reader = can.ASCReader if is_asc else can.CanutilsLogReader
    try:
        for msg in reader(str(path)):
            yield CanFrame(
                timestamp=msg.timestamp,
                channel=_channel(msg.channel, is_asc),
                id=msg.arbitration_id,
                data=bytes(msg.data),
                dlc=msg.dlc,
                is_extended=msg.is_extended_id,
                is_remote=msg.is_remote_frame,
                is_fd=msg.is_fd,
                brs=msg.bitrate_switch,
                esi=msg.error_state_indicator,
                is_error=msg.is_error_frame,
            )
    except (ValueError, IndexError, KeyError) as exc:
        raise CaptureError(f"{path}: malformed capture: {exc}") from exc


def _channel(channel: object, is_asc: bool) -> str:
    if channel is None:  # python-can drops the channel of candump error frames
        return "?"
    if is_asc:  # python-can makes ASC channels 0-based; show them as written in the file
        return str(int(channel) + 1)
    return str(channel)
