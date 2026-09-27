from __future__ import annotations

from typing import Protocol

from ..message import Message
from ..records import Record

Item = Record | Message


class Decoder(Protocol):
    """A stateful stream processor for one protocol layer.

    feed() returns Messages it does not handle unchanged and [] for Records it does not handle.
    """

    def feed(self, item: Item) -> list[Item]: ...

    def flush(self) -> list[Item]: ...


class DecoderStack:
    """Decoders bound to one Channel, each consuming the output of the one below."""

    def __init__(self, decoders: list[Decoder]):
        if not decoders:
            raise ValueError("a Decoder stack needs at least one Decoder")
        self.decoders = decoders

    def feed(self, record: Record) -> list[Message]:
        return self._through(0, [record])

    def flush(self) -> list[Message]:
        out: list[Message] = []
        for i, decoder in enumerate(self.decoders):
            out += self._through(i + 1, decoder.flush())
        return out

    def _through(self, start: int, items: list[Item]) -> list[Message]:
        for decoder in self.decoders[start:]:
            items = [out for item in items for out in decoder.feed(item)]
        return [item for item in items if isinstance(item, Message)]
