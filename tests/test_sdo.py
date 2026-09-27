from pathlib import Path

from protocol_analyzer.canopen.decoder import CanopenDecoder
from protocol_analyzer.cli import main
from protocol_analyzer.records import CanFrame

FIX = Path(__file__).parent / "fixtures"


def sdo(dec, node, request, hex_data, t=0.0):
    cob = (0x600 if request else 0x580) + node
    return dec.feed(CanFrame(t, "can0", cob, bytes.fromhex(hex_data), dlc=8))


def vals(msg):
    return {f.name: f.value for f in msg.fields}


def warnings(msg):
    return [d.text for d in msg.diagnostics]


def test_expedited_download():
    [m] = sdo(CanopenDecoder(), 5, True, "2318100101020304")
    assert m.name == "sdo"
    assert vals(m) == {"node": 5, "dir": "request", "command": "initiate_download",
                       "index": 0x1018, "subindex": 1, "data": b"\x01\x02\x03\x04"}
    [m2] = sdo(CanopenDecoder(), 5, True, "2B40600006000000")  # n=2: only 2 data bytes
    assert vals(m2)["data"] == b"\x06\x00"


def test_expedited_upload():
    d = CanopenDecoder()
    [req] = sdo(d, 5, True, "4018100100000000")
    assert vals(req)["command"] == "initiate_upload"
    [resp] = sdo(d, 5, False, "4318100178563412")
    assert vals(resp) == {"node": 5, "dir": "response", "command": "initiate_upload",
                          "index": 0x1018, "subindex": 1, "data": b"\x78\x56\x34\x12"}


def _segmented_upload(d, node, text=b"ABCDEFGHIJ"):
    """Upload 0x1008 (device name) of 10 bytes as a 7-byte and a 3-byte segment."""
    out = []
    out += sdo(d, node, True, "4008100000000000")
    out += sdo(d, node, False, "410810000A000000")  # size indicated: 10
    out += sdo(d, node, True, "6000000000000000")
    out += sdo(d, node, False, "00" + text[:7].hex())  # t=0, n=0, c=0
    out += sdo(d, node, True, "7000000000000000")
    out += sdo(d, node, False, "19" + text[7:].hex() + "00000000")  # t=1, n=4, c=1
    return out


def test_segmented_upload_reassembles_into_a_transfer_message():
    out = _segmented_upload(CanopenDecoder(), 5)
    assert [m.name for m in out] == ["sdo"] * 6 + ["sdo_transfer"]
    t = out[-1]
    assert vals(t) == {"node": 5, "kind": "upload", "index": 0x1008, "subindex": 0,
                       "size": 10, "data": b"ABCDEFGHIJ"}
    assert len(t.sources) == 3 and not t.diagnostics


def test_segmented_download():
    d = CanopenDecoder()
    sdo(d, 5, True, "2100200003000000")
    [ack] = sdo(d, 5, False, "6000200000000000")
    assert vals(ack)["command"] == "initiate_download"
    seg, transfer = sdo(d, 5, True, "09AABBCC00000000")
    assert vals(seg)["last"] is True
    assert vals(transfer)["data"] == b"\xaa\xbb\xcc" and vals(transfer)["kind"] == "download"


def test_toggle_error_is_reported():
    d = CanopenDecoder()
    sdo(d, 5, True, "4008100000000000")
    sdo(d, 5, False, "410810000A000000")
    sdo(d, 5, False, "00" + b"ABCDEFG".hex())
    [bad] = sdo(d, 5, False, "00" + b"HIJ".hex() + "00000000")  # toggle should be 1
    assert bad.has_errors and "toggle" in warnings(bad)[0]


def test_interleaved_nodes_keep_separate_state():
    d = CanopenDecoder()
    a, b = [], []
    frames_a = [(True, "4008100000000000"), (False, "410810000A000000"),
                (False, "00" + b"AAAAAAA".hex()), (False, "19" + b"AAA".hex() + "00000000")]
    frames_b = [(True, "4008100000000000"), (False, "4108100004000000"),
                (False, "07" + b"BBBB".hex() + "000000")]  # t=0, n=3, c=1
    for (ra, ha), (rb, hb) in zip(frames_a, frames_b + [(None, None)]):
        a += sdo(d, 5, ra, ha)
        if rb is not None:
            b += sdo(d, 6, rb, hb)
    assert vals(a[-1])["data"] == b"AAAAAAAAAA"
    assert vals(b[-1])["data"] == b"BBBB"


def test_abort_clears_only_that_nodes_transfer():
    d = CanopenDecoder()
    sdo(d, 5, True, "4008100000000000")
    sdo(d, 5, False, "410810000A000000")
    sdo(d, 6, True, "4008100000000000")
    sdo(d, 6, False, "4108100004000000")
    [abort] = sdo(d, 5, True, "8008100000000405")
    assert abort.get("abort_code").label == "0x05040000 SDO protocol timed out"
    assert abort.diagnostics[0].level == "warning"
    [orphan] = sdo(d, 5, False, "00" + b"ABCDEFG".hex())
    assert "without an active transfer" in warnings(orphan)[0]
    seg, transfer = sdo(d, 6, False, "07" + b"BBBB".hex() + "000000")
    assert vals(transfer)["data"] == b"BBBB"


def test_protocol_irregularities():
    d = CanopenDecoder()
    [short] = d.feed(CanFrame(0.0, "can0", 0x605, b"\x40\x00", dlc=2))
    assert short.has_errors and "8 bytes" in short.diagnostics[0].text
    sdo(d, 5, True, "4008100000000000")
    sdo(d, 5, False, "410810000A000000")
    [restart] = sdo(d, 5, False, "410810000A000000")
    assert "abandoned" in warnings(restart)[0]
    [block] = sdo(d, 5, True, "C000000000000000")
    assert "block transfer" in warnings(block)[0]
    [invalid] = sdo(d, 5, True, "E000000000000000")
    assert invalid.has_errors


def test_announced_size_mismatch_warns():
    d = CanopenDecoder()
    sdo(d, 5, True, "4008100000000000")
    sdo(d, 5, False, "410810000A000000")  # announces 10
    _, transfer = sdo(d, 5, False, "07" + b"ABCD".hex() + "000000")  # delivers 4, last
    assert "announced 10 bytes, transferred 4" in warnings(transfer)


def test_cli_shows_sdo_from_fixture(capsys):
    assert main(["decode", str(FIX / "basic.log"), "--decoder", "canopen", "--service", "sdo"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2
    assert lines[1].endswith("data=01 02 03 04")


def test_transfer_open_at_end_of_capture_is_reported():
    d = CanopenDecoder()
    sdo(d, 5, True, "4008100000000000")
    sdo(d, 5, False, "410810000A000000")
    sdo(d, 5, False, "00" + b"ABCDEFG".hex())
    [m] = d.flush()
    assert m.name == "sdo_transfer" and m.has_errors
    assert "incomplete at end of capture" in m.diagnostics[0].text and "7 of 10 bytes" in m.diagnostics[0].text
    assert d.flush() == []
