from __future__ import annotations

from dataclasses import dataclass, field

from ..message import Field, Message
from ..records import CanFrame
from .eds import ObjectDictionary
from .tables import sdo_abort_text


@dataclass
class _Transfer:
    kind: str  # "download" (client writes) | "upload" (client reads)
    index: int
    subindex: int
    size: int | None
    toggle: int = 0
    data: bytearray = field(default_factory=bytearray)
    frames: list[CanFrame] = field(default_factory=list)


def _mux(d: bytes) -> tuple[int, int]:
    return int.from_bytes(d[1:3], "little"), d[3]


class SdoTracker:
    """Decodes SDO frames per node and reassembles segmented transfers. Block transfer is v2."""

    def __init__(self, ods: dict[int, ObjectDictionary] | None = None) -> None:
        self._ods = ods or {}
        self._transfers: dict[int, _Transfer] = {}

    def decode(self, frame: CanFrame, node: int, request: bool) -> list[Message]:
        msg = Message("canopen", "sdo", frame.channel, start=frame.timestamp, end=frame.timestamp,
                      sources=[frame],
                      fields=[Field("node", node), Field("dir", "request" if request else "response")])
        d = frame.data
        if len(d) != 8:
            msg.fields.append(Field("data", d, raw=d))
            msg.error(f"SDO frame must be 8 bytes, got {len(d)}")
            return [msg]
        cs = d[0] >> 5
        return self._request(cs, node, frame, msg) if request else self._response(cs, node, frame, msg)

    # --- client -> server (0x600 + node) ---
    def _request(self, cs: int, node: int, frame: CanFrame, msg: Message) -> list[Message]:
        d = frame.data
        if cs == 1:
            return self._initiate(msg, node, frame, "download")
        if cs == 2:
            msg.fields.append(Field("command", "initiate_upload"))
            msg.fields += self._object(node, *_mux(d))
            return [msg]
        if cs == 0:
            return self._segment(msg, node, frame, "download")
        if cs == 3:
            msg.fields += [Field("command", "upload_segment"), Field("toggle", (d[0] >> 4) & 1)]
            return [msg]
        if cs == 4:
            return self._abort(msg, node, frame)
        return self._other(msg, cs)

    # --- server -> client (0x580 + node) ---
    def _response(self, cs: int, node: int, frame: CanFrame, msg: Message) -> list[Message]:
        d = frame.data
        if cs == 3:
            msg.fields.append(Field("command", "initiate_download"))
            msg.fields += self._object(node, *_mux(d))
            return [msg]
        if cs == 1:
            msg.fields += [Field("command", "download_segment"), Field("toggle", (d[0] >> 4) & 1)]
            return [msg]
        if cs == 2:
            return self._initiate(msg, node, frame, "upload")
        if cs == 0:
            return self._segment(msg, node, frame, "upload")
        if cs == 4:
            return self._abort(msg, node, frame)
        return self._other(msg, cs)

    def _initiate(self, msg: Message, node: int, frame: CanFrame, kind: str) -> list[Message]:
        """Initiate download request or initiate upload response: same byte layout."""
        d = frame.data
        index, subindex = _mux(d)
        n, e, s = (d[0] >> 2) & 3, (d[0] >> 1) & 1, d[0] & 1
        msg.fields.append(Field("command", f"initiate_{kind}"))
        msg.fields += self._object(node, index, subindex)
        if self._transfers.pop(node, None) is not None:
            msg.warn(f"previous SDO transfer on node {node} abandoned")
        if e:
            msg.fields.append(self._value(node, index, subindex, d[4:8 - n] if s else d[4:8]))
        else:
            size = int.from_bytes(d[4:8], "little") if s else None
            if size is not None:
                msg.fields.append(Field("size", size))
            self._transfers[node] = _Transfer(kind, index, subindex, size, frames=[frame])
        return [msg]

    def _segment(self, msg: Message, node: int, frame: CanFrame, kind: str) -> list[Message]:
        d = frame.data
        t, n, c = (d[0] >> 4) & 1, (d[0] >> 1) & 7, d[0] & 1
        segment = d[1:8 - n]
        msg.fields += [Field("command", f"{kind}_segment"), Field("toggle", t),
                       Field("data", segment, raw=segment)]
        if c:
            msg.fields.append(Field("last", True))
        transfer = self._transfers.get(node)
        if transfer is None or transfer.kind != kind:
            msg.warn(f"SDO {kind} segment without an active transfer")
            return [msg]
        if t != transfer.toggle:
            msg.error(f"toggle bit {t}, expected {transfer.toggle}")
        transfer.toggle = t ^ 1
        transfer.data += segment
        transfer.frames.append(frame)
        if not c:
            return [msg]
        del self._transfers[node]
        return [msg, self._completed(node, transfer, frame)]

    def _completed(self, node: int, transfer: _Transfer, last: CanFrame) -> Message:
        data = bytes(transfer.data)
        m = Message("canopen", "sdo_transfer", last.channel, start=transfer.frames[0].timestamp,
                    end=last.timestamp, sources=list(transfer.frames),
                    fields=[Field("node", node), Field("kind", transfer.kind)]
                    + self._object(node, transfer.index, transfer.subindex)
                    + [Field("size", len(data)), self._value(node, transfer.index, transfer.subindex, data)])
        if transfer.size is not None and transfer.size != len(data):
            m.warn(f"announced {transfer.size} bytes, transferred {len(data)}")
        return m

    def _abort(self, msg: Message, node: int, frame: CanFrame) -> list[Message]:
        d = frame.data
        code = int.from_bytes(d[4:8], "little")
        msg.fields.append(Field("command", "abort"))
        msg.fields += self._object(node, *_mux(d))
        msg.fields.append(Field("abort_code", code, label=f"0x{code:08X} {sdo_abort_text(code)}"))
        msg.warn(f"SDO abort: {sdo_abort_text(code)}")
        self._transfers.pop(node, None)
        return [msg]

    def _other(self, msg: Message, cs: int) -> list[Message]:
        data = msg.sources[0].data
        msg.fields += [Field("command", cs), Field("data", data, raw=data)]
        if cs in (5, 6):
            msg.warn("SDO block transfer is not decoded yet")
        else:
            msg.error(f"invalid SDO command specifier {cs}")
        return [msg]

    # Extension points: Task 8 names objects and decodes values from an EDS.
    def _object(self, node: int, index: int, subindex: int) -> list[Field]:
        fields = [Field("index", index, label=f"0x{index:04X}"), Field("subindex", subindex)]
        od = self._ods.get(node)
        name = od.name(index, subindex) if od is not None else None
        if name:
            fields.append(Field("object", name))
        return fields

    def _value(self, node: int, index: int, subindex: int, data: bytes) -> Field:
        od = self._ods.get(node)
        value = od.decode(index, subindex, data) if od is not None else None
        return Field("data", data if value is None else value, raw=data)
