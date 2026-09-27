from __future__ import annotations

from ..message import Field, Message
from ..records import CanFrame
from .base import Item


def frame_message(frame: CanFrame) -> Message:
    """The frame layer: one CanFrame as a Message, nothing interpreted."""
    msg = Message("can", "data", frame.channel, start=frame.timestamp, end=frame.timestamp,
                  sources=[frame])
    if frame.is_error:
        msg.name = "error_frame"
        msg.summary = "error frame"
        msg.error("CAN error frame")
        return msg
    id_text = f"{frame.id:08X}" if frame.is_extended else f"{frame.id:03X}"
    flags = [name for name, on in (("ext", frame.is_extended), ("rtr", frame.is_remote),
                                   ("fd", frame.is_fd), ("brs", frame.brs), ("esi", frame.esi)) if on]
    msg.fields = [Field("id", frame.id, label=id_text), Field("dlc", frame.dlc)]
    if flags:
        msg.fields.append(Field("flags", ",".join(flags)))
    if frame.is_remote:
        msg.name = "remote"
        body = "RTR"
    else:
        msg.name = "fd" if frame.is_fd else "data"
        msg.fields.append(Field("data", frame.data, raw=frame.data))
        body = " ".join(f"{b:02X}" for b in frame.data)
    msg.summary = f"{id_text} [{frame.dlc}] {body}".rstrip()
    shown = [f for f in flags if f != "rtr"]
    if shown:
        msg.summary += f"  ({','.join(shown)})"
    check_frame(frame, msg)
    return msg


def check_frame(frame: CanFrame, msg: Message) -> None:
    """Attach Diagnostics for frames no CAN controller could have sent (lenient capture parsers pass them)."""
    if frame.is_error:
        return
    bits, limit = (29, 0x1FFFFFFF) if frame.is_extended else (11, 0x7FF)
    if frame.id > limit:
        msg.error(f"id 0x{frame.id:X} does not fit in {bits} bits")
    n = len(frame.data)
    if frame.is_fd:
        if n > 64:
            msg.error(f"CAN FD frame carries {n} bytes (max 64)")
    elif frame.is_remote:
        if frame.dlc > 8:
            msg.warn(f"remote frame with dlc {frame.dlc} (max 8)")
    elif n > 8:
        msg.error(f"classic CAN frame carries {n} bytes (max 8)")
    elif frame.dlc != n:
        msg.warn(f"dlc {frame.dlc} but {n} data bytes")


class CanDecoder:
    def feed(self, item: Item) -> list[Item]:
        if isinstance(item, CanFrame):
            return [frame_message(item)]
        if isinstance(item, Message):
            return [item]
        return []

    def flush(self) -> list[Item]:
        return []
