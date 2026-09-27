from __future__ import annotations

from datetime import datetime, timedelta

from ..decoders.base import Item
from ..decoders.can import frame_message
from ..message import Field, Message
from ..records import CanFrame
from .cobid import classify
from .tables import ERROR_REGISTER_BITS, NMT_COMMANDS, NMT_STATES, emcy_text

_CANOPEN_EPOCH = datetime(1984, 1, 1)


def canopen_message(frame: CanFrame, name: str, node: int | None, fields: list[Field]) -> Message:
    head = [Field("node", node)] if node is not None else []
    return Message("canopen", name, frame.channel, start=frame.timestamp, end=frame.timestamp,
                   fields=head + fields, sources=[frame])


def _raw(data: bytes) -> Field:
    return Field("data", data, raw=data)


class CanopenDecoder:
    def feed(self, item: Item) -> list[Item]:
        if isinstance(item, Message):
            return [item]
        if not isinstance(item, CanFrame):
            return []
        if item.is_error or item.is_extended:
            return [frame_message(item)]
        service, node = classify(item.id)
        if service == "unknown":
            return [frame_message(item)]
        if item.is_remote:
            name = "node_guard_request" if service == "heartbeat" else f"{service}_rtr"
            return [canopen_message(item, name, node, [])]
        return self._decode(service, node, item)

    def flush(self) -> list[Item]:
        return []

    def _decode(self, service: str, node: int | None, frame: CanFrame) -> list[Message]:
        if service == "nmt":
            return [self._nmt(frame)]
        if service == "sync":
            return [self._sync(frame)]
        if service == "time":
            return [self._time(frame)]
        if service == "emcy":
            return [self._emcy(node, frame)]
        if service == "heartbeat":
            return [self._heartbeat(node, frame)]
        if service in ("sdo_tx", "sdo_rx"):
            return [canopen_message(frame, "sdo", node, [_raw(frame.data)])]
        if service == "lss":
            return [canopen_message(frame, "lss", None, [_raw(frame.data)])]
        return [self._pdo(service, node, frame)]

    def _nmt(self, frame: CanFrame) -> Message:
        d = frame.data
        if len(d) < 2:
            m = canopen_message(frame, "nmt", None, [_raw(d)])
            m.error(f"NMT needs 2 bytes, got {len(d)}")
            return m
        cs, target = d[0], d[1]
        m = canopen_message(frame, "nmt", None, [
            Field("command", cs, label=NMT_COMMANDS.get(cs)),
            Field("target", target, label="all" if target == 0 else None),
        ])
        if cs not in NMT_COMMANDS:
            m.warn(f"unknown NMT command 0x{cs:02X}")
        return m

    def _sync(self, frame: CanFrame) -> Message:
        d = frame.data
        m = canopen_message(frame, "sync", None, [Field("counter", d[0])] if d else [])
        if len(d) > 1:
            m.warn(f"SYNC carries at most 1 byte, got {len(d)}")
        return m

    def _time(self, frame: CanFrame) -> Message:
        d = frame.data
        if len(d) < 6:
            m = canopen_message(frame, "time", None, [_raw(d)])
            m.error(f"TIME needs 6 bytes, got {len(d)}")
            return m
        ms = int.from_bytes(d[0:4], "little") & 0x0FFFFFFF
        days = int.from_bytes(d[4:6], "little")
        when = _CANOPEN_EPOCH + timedelta(days=days, milliseconds=ms)
        return canopen_message(frame, "time", None, [Field("time", when.isoformat(timespec="milliseconds"))])

    def _emcy(self, node: int | None, frame: CanFrame) -> Message:
        d = frame.data
        if len(d) < 3:
            m = canopen_message(frame, "emcy", node, [_raw(d)])
            m.error(f"EMCY needs 8 bytes, got {len(d)}")
            return m
        code = int.from_bytes(d[0:2], "little")
        register = d[2]
        bits = [name for bit, name in ERROR_REGISTER_BITS.items() if register >> bit & 1]
        m = canopen_message(frame, "emcy", node, [
            Field("code", code, label=f"0x{code:04X} {emcy_text(code)}"),
            Field("register", register, label=",".join(bits) or "none"),
            Field("manufacturer", d[3:8], raw=d[3:8]),
        ])
        if len(d) != 8:
            m.warn(f"EMCY should be 8 bytes, got {len(d)}")
        return m

    def _heartbeat(self, node: int | None, frame: CanFrame) -> Message:
        d = frame.data
        if len(d) != 1:
            m = canopen_message(frame, "heartbeat", node, [_raw(d)])
            m.error(f"heartbeat needs 1 byte, got {len(d)}")
            return m
        state = d[0] & 0x7F
        fields = [Field("state", state, label=NMT_STATES.get(state))]
        if d[0] & 0x80:
            fields.append(Field("toggle", 1))
        m = canopen_message(frame, "heartbeat", node, fields)
        if state not in NMT_STATES:
            m.warn(f"unknown NMT state 0x{state:02X}")
        return m

    def _pdo(self, service: str, node: int | None, frame: CanFrame) -> Message:
        return canopen_message(frame, service, node, [_raw(frame.data)])
