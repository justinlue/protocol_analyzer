from __future__ import annotations

from typing import Iterator

from .decoders.base import DecoderStack
from .message import Message
from .errors import SessionError
from .registry import build_decoder, decoder_info
from .session import Session
from .sources import capture_kind, open_capture


class Analysis:
    """Runs a Session: reads its Capture and feeds each Channel's Records to its Decoder stack."""

    def __init__(self, session: Session):
        self.session = session
        self.t0: float | None = None
        self._stacks: dict[str, DecoderStack | None] = {}

    def validate(self) -> None:
        """Check every binding before reading: decoder kind vs Capture kind, and that each stack builds
        (so a missing Definition or EDS fails even on a Channel that never carries traffic)."""
        kind = capture_kind(self.session.capture)
        for channel, binding in self.session.bindings.items():
            info = decoder_info(binding.decoders[0])
            if info.kind != kind:
                raise SessionError(f"channel {channel}: decoder '{binding.decoders[0]}' reads {info.kind} "
                                   f"Records, but {self.session.capture.name} is a {kind} capture")
            for spec in binding.decoders:
                build_decoder(spec, binding.params, self.session.base_dir)

    def messages(self) -> Iterator[Message]:
        self.validate()
        for record in open_capture(self.session.capture):
            if self.t0 is None and record.timestamp is not None:
                self.t0 = record.timestamp
            stack = self._stack(record.channel)
            if stack is not None:
                yield from stack.feed(record)
        for stack in self._stacks.values():
            if stack is not None:
                yield from stack.flush()

    def _stack(self, channel: str) -> DecoderStack | None:
        if channel not in self._stacks:
            binding = self.session.binding_for(channel)
            self._stacks[channel] = None if binding is None else DecoderStack(
                [build_decoder(spec, binding.params, self.session.base_dir) for spec in binding.decoders])
        return self._stacks[channel]
