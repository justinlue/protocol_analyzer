import pytest

from protocol_analyzer.decoders.base import DecoderStack
from protocol_analyzer.decoders.can import CanDecoder, frame_message
from protocol_analyzer.errors import SessionError
from protocol_analyzer.message import Message
from protocol_analyzer.records import CanFrame, UartChunk
from protocol_analyzer.registry import REGISTRY, build_decoder


def test_data_frame_message():
    m = frame_message(CanFrame(1.0, "can0", 0x181, b"\x01\x02", dlc=2))
    assert (m.protocol, m.name, m.channel, m.start, m.end) == ("can", "data", "can0", 1.0, 1.0)
    assert m.summary == "181 [2] 01 02"
    assert m.get("id").value == 0x181 and m.get("id").label == "181"
    assert m.get("data").value == b"\x01\x02"
    assert m.sources == [CanFrame(1.0, "can0", 0x181, b"\x01\x02", dlc=2)]


def test_extended_remote_and_fd_frames():
    ext = frame_message(CanFrame(0.0, "1", 0x18FEF100, b"\x01\x02", dlc=2, is_extended=True))
    assert ext.summary == "18FEF100 [2] 01 02  (ext)"
    rtr = frame_message(CanFrame(0.0, "1", 0x123, b"", dlc=0, is_remote=True))
    assert rtr.name == "remote" and rtr.summary == "123 [0] RTR" and rtr.get("data") is None
    fd = frame_message(CanFrame(0.0, "1", 0x123, bytes.fromhex("AABBCCDD"), dlc=4, is_fd=True, brs=True))
    assert fd.name == "fd" and fd.summary == "123 [4] AA BB CC DD  (fd,brs)"


def test_error_frame_is_an_error_message():
    m = frame_message(CanFrame(0.0, "?", 0, is_error=True))
    assert m.name == "error_frame" and m.has_errors


def test_can_decoder_passes_messages_through_and_ignores_uart():
    dec = CanDecoder()
    passthrough = Message("x", "y", "c")
    assert dec.feed(passthrough) == [passthrough]
    assert dec.feed(UartChunk(None, "u", 0, b"\x00")) == []
    assert dec.flush() == []


class _Tag:
    """Test decoder: wraps anything it sees in a Message named after itself; emits '<tag>-tail' on flush."""

    def __init__(self, tag):
        self.tag = tag

    def feed(self, item):
        inner = item.name if isinstance(item, Message) else "record"
        return [Message("t", f"{self.tag}({inner})", "c")]

    def flush(self):
        return [Message("t", f"{self.tag}-tail", "c")]


def test_stack_chains_decoders_and_cascades_flush():
    stack = DecoderStack([_Tag("a"), _Tag("b")])
    assert [m.name for m in stack.feed(CanFrame(0.0, "c", 1))] == ["b(a(record))"]
    assert [m.name for m in stack.flush()] == ["b(a-tail)", "b-tail"]


def test_build_decoder():
    assert isinstance(build_decoder("can"), CanDecoder)
    assert "can" in REGISTRY
    with pytest.raises(SessionError, match="unknown decoder 'nope'"):
        build_decoder("nope")


def test_implausible_frames_carry_diagnostics():
    assert frame_message(CanFrame(0.0, "c", 0x800, b"\x00", dlc=1)).has_errors  # 11-bit id overflow
    assert frame_message(CanFrame(0.0, "c", 0x123, b"\x00", dlc=0)).diagnostics  # dlc != data length
    assert frame_message(CanFrame(0.0, "c", 0x123, bytes(11), dlc=11)).has_errors  # classic > 8 bytes
    assert frame_message(CanFrame(0.0, "c", 0x123, b"", dlc=99, is_remote=True)).diagnostics
    assert not frame_message(CanFrame(0.0, "c", 0x123, b"\x01", dlc=1)).diagnostics


def test_canopen_frames_get_the_same_sanity_checks():
    from protocol_analyzer.canopen.decoder import CanopenDecoder
    [m] = CanopenDecoder().feed(CanFrame(0.0, "c", 0x705, b"\x7f", dlc=0))
    assert any("dlc" in d.text for d in m.diagnostics)
