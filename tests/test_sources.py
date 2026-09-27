from pathlib import Path

import pytest

from protocol_analyzer.errors import CaptureError
from protocol_analyzer.sources import capture_kind, open_capture

FIX = Path(__file__).parent / "fixtures"


def test_candump_frames_map_every_field():
    frames = list(open_capture(FIX / "basic.log"))
    assert len(frames) == 8
    nmt = frames[0]
    assert (nmt.timestamp, nmt.channel, nmt.id, nmt.data, nmt.dlc) == (
        1700000000.0, "can0", 0x000, b"\x01\x05", 2)
    ext = frames[4]
    assert ext.id == 0x18FEF100 and ext.is_extended
    rtr = frames[5]
    assert rtr.is_remote and rtr.data == b""
    fd = frames[6]
    assert fd.is_fd and fd.brs and not fd.esi and fd.data == bytes.fromhex("AABBCCDD")
    err = frames[7]
    assert err.is_error and err.channel == "?"


def test_asc_channels_keep_the_numbering_written_in_the_file():
    frames = list(open_capture(FIX / "basic.asc"))
    assert [f.channel for f in frames] == ["1", "1", "2", "1", "1", "1"]
    assert frames[2].is_extended and frames[2].id == 0x18FEF100
    assert frames[3].is_remote
    assert frames[4].is_error
    fd = frames[5]
    assert fd.is_fd and fd.brs and fd.id == 0x181 and fd.data == bytes(range(1, 9))


def test_empty_capture_yields_nothing():
    assert list(open_capture(FIX / "empty.log")) == []


def test_malformed_candump_raises_capture_error_naming_the_file():
    with pytest.raises(CaptureError, match="malformed.log"):
        list(open_capture(FIX / "malformed.log"))


def test_unknown_extension_is_rejected_with_the_supported_list(tmp_path):
    p = tmp_path / "x.pcap"
    p.write_bytes(b"")
    with pytest.raises(CaptureError, match=r"unknown capture type '\.pcap'.*\.asc"):
        open_capture(p)


def test_missing_file_is_a_capture_error(tmp_path):
    with pytest.raises(CaptureError, match="no such file"):
        open_capture(tmp_path / "nope.log")


def test_capture_kind():
    assert capture_kind("a.LOG") == "can"
    assert capture_kind("a.hex") == "uart"


def test_uart_bin_chunks_carry_offsets_not_timestamps(tmp_path):
    payload = bytes(range(256)) * 20  # 5120 bytes → two chunks
    p = tmp_path / "cap.bin"
    p.write_bytes(payload)
    chunks = list(open_capture(p))
    assert [c.offset for c in chunks] == [0, 4096]
    assert all(c.timestamp is None and c.channel == "uart0" for c in chunks)
    assert b"".join(c.data for c in chunks) == payload


def test_uart_hex_lines_track_offsets_per_channel():
    chunks = list(open_capture(FIX / "uart_sample.hex"))
    assert [(c.timestamp, c.channel, c.offset, c.data) for c in chunks] == [
        (0.0001, "rx", 0, b"\xaa\x55\x01"),
        (0.0002, "tx", 0, b"\xaa\x55"),
        (0.0003, "rx", 3, b"\x00\x00\x10"),
    ]


def test_uart_hex_bad_line_reports_file_and_line(tmp_path):
    p = tmp_path / "bad.hex"
    p.write_text("0.1 rx AA\n0.2 rx ZZ\n")
    with pytest.raises(CaptureError, match=r"bad\.hex:2"):
        list(open_capture(p))


def test_uart_hex_tolerates_non_utf8_comments_and_rejects_binary(tmp_path):
    p = tmp_path / "ansi.hex"
    p.write_bytes(b"# temp \xb0C\n0.0 rx aa55\n")
    assert [c.data for c in open_capture(p)] == [b"\xaa\x55"]
    b = tmp_path / "blob.txt"
    b.write_bytes(bytes(range(256)))
    with pytest.raises(CaptureError, match="blob.txt"):
        list(open_capture(b))


def test_asc_without_any_asc_header_is_rejected(tmp_path):
    p = tmp_path / "junk.asc"
    p.write_text("this is garbage\nand more garbage\n")
    with pytest.raises(CaptureError, match="not a Vector ASC file"):
        list(open_capture(p))
