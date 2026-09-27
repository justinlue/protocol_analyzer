from __future__ import annotations

import bisect

from ..decoders.base import Item
from ..errors import CaptureError
from ..message import Field, Message
from ..output import format_fields
from ..records import UartChunk
from .crc import CrcParams, crc
from .definition import Definition, FieldSpec
from .payload import decode_fields, number_field


class UartDecoder:
    """Frames one UART Channel's byte stream with a Definition and decodes each UART frame (DESIGN §6.3)."""

    def __init__(self, definition: Definition):
        self.defn = definition
        self._buf = bytearray()
        self._base = 0  # stream offset of _buf[0]
        self._chunks: list[UartChunk] = []  # chunks overlapping the buffer, oldest first
        self._offsets: list[int] = []  # their start offsets, for bisect
        self._channel = ""
        self._last_time: float | None = None  # timestamp of the latest chunk's first byte
        self._junk = bytearray()  # pending unframed bytes
        self._junk_start = 0
        self._junk_times: tuple[float | None, float | None] = (None, None)
        self._reported_until = 0  # stream offsets below this were already shown in a failed frame
        self._prefix_at: dict[str, int] = {}
        pos = 0
        for spec in definition.prefix:
            self._prefix_at[spec.name] = pos
            pos += spec.num.size

    # --- Decoder protocol ---
    def feed(self, item: Item) -> list[Item]:
        if isinstance(item, Message):
            return [item]
        if not isinstance(item, UartChunk):
            return []
        out: list[Item] = []
        if self.defn.gap_ms is not None:
            out += self._check_gap(item)
        self._channel = item.channel
        self._chunks.append(item)
        self._offsets.append(item.offset)
        self._buf += item.data
        self._last_time = item.timestamp
        out += self._scan()
        return out

    def flush(self) -> list[Item]:
        out: list[Item] = self._scan("capture ends in the middle of a frame") if self._buf else []
        return out + self._flush_junk()

    # --- framing ---
    def _check_gap(self, chunk: UartChunk) -> list[Message]:
        if chunk.timestamp is None:
            raise CaptureError(f"Definition {self.defn.path.name} uses gap_ms, which needs a timestamped capture")
        if self._last_time is None or not self._buf:
            return []
        if (chunk.timestamp - self._last_time) * 1000 <= self.defn.gap_ms:
            return []
        return self._scan("frame interrupted by an idle gap") + self._flush_junk()

    def _scan(self, final: str | None = None) -> list[Message]:
        """Frame as much of the buffer as possible.

        With `final` (end of capture, idle gap) incomplete candidates are reported as truncated
        and scanning continues past them, so complete frames behind a false sync are recovered.
        """
        d = self.defn
        out: list[Message] = []
        while self._buf:
            i = self._buf.find(d.sync_bytes)
            if i < 0:
                keep = 0 if final else len(d.sync_bytes) - 1  # a sync may straddle the next chunk
                self._skip(max(0, len(self._buf) - keep))
                break
            if i:
                self._skip(i)
            complete = len(self._buf) >= d.prefix_size
            if complete:
                length = self._prefix_value(d.length)
                if d.length.max is not None and length > d.length.max:
                    self._skip(1)  # false sync: the length cannot be real
                    continue
                total = d.prefix_size + length + d.suffix_size
                complete = len(self._buf) >= total
            if not complete:
                if final is None:
                    break
                if self._base < self._reported_until:
                    self._skip(1)  # its bytes are already shown in an earlier failed frame
                    continue
                out += self._flush_junk()
                out.append(self._truncated(final))
                self._reported_until = self._base + len(self._buf)
                self._skip(1)
                continue
            msg, ok = self._decode_frame(bytes(self._buf[:total]), length)
            if not ok and self._base < self._reported_until:
                self._skip(1)  # a failed candidate inside bytes an earlier failed frame already shows
                continue
            out += self._flush_junk()
            out.append(msg)
            if ok:
                self._consume(total)
            else:
                self._reported_until = max(self._reported_until, self._base + total)
                self._skip(1)
        return out

    def _prefix_value(self, spec: FieldSpec) -> int:
        at = self._prefix_at[spec.name]
        return spec.num.unpack(bytes(self._buf[at:at + spec.num.size]))

    def _consume(self, n: int) -> None:
        del self._buf[:n]
        self._base += n
        while len(self._offsets) > 1 and self._offsets[1] <= self._base:
            self._chunks.pop(0)
            self._offsets.pop(0)

    def _skip(self, n: int) -> None:
        """Move n bytes from the buffer into the pending unframed run, unless already reported."""
        if n <= 0:
            return
        fresh_from = min(n, max(0, self._reported_until - self._base))
        if fresh_from < n:
            if not self._junk:
                self._junk_start = self._base + fresh_from
                self._junk_times = (self._time_at(self._junk_start), None)
            self._junk += self._buf[fresh_from:n]
            self._junk_times = (self._junk_times[0], self._time_at(self._base + n - 1))
        self._consume(n)

    def _time_at(self, offset: int) -> float | None:
        i = bisect.bisect_right(self._offsets, offset) - 1
        return self._chunks[max(i, 0)].timestamp

    def _message(self, name: str, start: int, size: int, fields: list[Field]) -> Message:
        end = start + size - 1
        i0 = max(bisect.bisect_right(self._offsets, start) - 1, 0)
        i1 = max(bisect.bisect_right(self._offsets, end) - 1, 0)
        return Message(self.defn.protocol, name, self._channel, start=self._time_at(start),
                       end=self._time_at(end), offset=start, fields=fields, sources=self._chunks[i0:i1 + 1])

    def _truncated(self, reason: str) -> Message:
        raw = bytes(self._buf)
        m = self._message("truncated", self._base, len(raw), [Field("data", raw, raw=raw)])
        m.error(reason)
        return m

    def _flush_junk(self) -> list[Message]:
        if not self._junk:
            return []
        raw = bytes(self._junk)
        m = Message(self.defn.protocol, "unframed", self._channel, start=self._junk_times[0],
                    end=self._junk_times[1], offset=self._junk_start, fields=[Field("data", raw, raw=raw)])
        m.warn(f"{len(raw)} bytes outside any frame")
        self._junk.clear()
        return [m]

    # --- frame decoding ---
    def _decode_frame(self, frame: bytes, length: int) -> tuple[Message, bool]:
        d = self.defn
        fields: list[Field] = []
        spans: dict[str, tuple[int, int]] = {}
        values: dict[str, int] = {}
        payload = b""
        pos = 0
        for spec in d.frame:
            size = length if spec is d.payload else spec.num.size
            raw = frame[pos:pos + size]
            spans[spec.name] = (pos, pos + size)
            if spec is d.payload:
                payload = raw
            else:
                values[spec.name] = spec.num.unpack(raw)
                fields.append(self._header_field(spec, raw))
            pos += size
        msg = self._message("frame", self._base, len(frame), fields)
        ok = self._check_crc(msg, frame, spans, values)
        if ok:
            data = self._decode_payload(msg, values, payload)
        else:
            msg.name = "bad_frame"
            data = Field(d.payload.name, payload, raw=payload)
        fields.insert(len(d.prefix), data)
        shown = [f for name in d.show for f in fields if f.name == name]
        msg.summary = format_fields(shown + (data.children if data.value is None else [data]))
        return msg, ok

    def _header_field(self, spec: FieldSpec, raw: bytes) -> Field:
        f = number_field(spec, spec.name, raw)
        if spec.role in ("sync", "crc"):
            f.label = f"0x{f.value:0{2 * len(raw)}X}"
        return f

    def _check_crc(self, msg: Message, frame: bytes, spans: dict[str, tuple[int, int]],
                   values: dict[str, int]) -> bool:
        spec = self.defn.crc_field
        if spec is None:
            return True
        covered = frame[spans[spec.covers[0]][0]:spans[spec.covers[1]][1]]
        try:
            expected = crc(covered, spec.crc) if isinstance(spec.crc, CrcParams) else spec.crc(covered)
        except Exception as exc:  # user hook
            msg.error(f"CRC hook failed: {exc}")
            return False
        if not isinstance(expected, int) or isinstance(expected, bool):
            msg.error(f"CRC hook returned {expected!r}, not an integer")
            return False
        got = values[spec.name]
        if got != expected:
            width = 2 * spec.num.size
            msg.error(f"CRC mismatch: frame has 0x{got:0{width}X}, {spec.algo} gives 0x{expected:0{width}X}")
            return False
        return True

    def _decode_payload(self, msg: Message, values: dict[str, int], payload: bytes) -> Field:
        d = self.defn
        raw_data = Field(d.payload.name, payload, raw=payload)
        cmd_id = values[d.payload.dispatch]
        command, variant = d.select(cmd_id, values)
        msg.name = command.name if command else f"cmd_0x{cmd_id:02X}"
        if d.versions is not None and values["version"] not in d.versions:
            msg.warn(f"unknown protocol version {values['version']}")
            return raw_data
        if command is None:
            msg.warn(f"unknown command 0x{cmd_id:02X}")
            return raw_data
        if variant is None:
            msg.warn(f"no variant of {command.name} matches this frame")
            return raw_data
        children, used, problem = decode_fields(variant.fields, payload, d.types)
        if problem is not None:
            msg.error(f"definition error in {command.name}: {problem}")
        elif used < len(payload):
            rest = payload[used:]
            children.append(Field("_trailing", rest, raw=rest))
            msg.warn(f"{len(rest)} trailing data bytes not in the {command.name} layout")
        return Field(d.payload.name, None, raw=payload, children=children)
