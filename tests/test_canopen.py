from pathlib import Path

import pytest

from protocol_analyzer.canopen.cobid import classify
from protocol_analyzer.canopen.decoder import CanopenDecoder
from protocol_analyzer.cli import main
from protocol_analyzer.records import CanFrame
from protocol_analyzer.registry import build_decoder

FIX = Path(__file__).parent / "fixtures"


def dec(can_id, hex_data="", **kw):
    data = bytes.fromhex(hex_data)
    out = CanopenDecoder().feed(CanFrame(1.0, "can0", can_id, data, dlc=len(data), **kw))
    assert len(out) == 1
    return out[0]


def values(msg):
    return {f.name: (f.label if f.label is not None else f.value) for f in msg.fields}


@pytest.mark.parametrize("can_id, expected", [
    (0x000, ("nmt", None)), (0x080, ("sync", None)), (0x085, ("emcy", 5)), (0x100, ("time", None)),
    (0x185, ("tpdo1", 5)), (0x205, ("rpdo1", 5)), (0x285, ("tpdo2", 5)), (0x485, ("tpdo4", 5)),
    (0x505, ("rpdo4", 5)), (0x585, ("sdo_tx", 5)), (0x605, ("sdo_rx", 5)), (0x705, ("heartbeat", 5)),
    (0x77F, ("heartbeat", 127)), (0x7E4, ("lss", None)), (0x7E5, ("lss", None)),
    (0x180, ("unknown", None)), (0x7F0, ("unknown", None)), (0x800, ("unknown", None)),
])
def test_classify(can_id, expected):
    assert classify(can_id) == expected


def test_nmt():
    m = dec(0x000, "0105")
    assert (m.protocol, m.name) == ("canopen", "nmt")
    assert values(m) == {"command": "start", "target": 5}
    assert values(dec(0x000, "8100")) == {"command": "reset_node", "target": "all"}
    assert dec(0x000, "01").has_errors


def test_heartbeat_and_node_guarding():
    assert values(dec(0x705, "7F")) == {"node": 5, "state": "pre-operational"}
    assert values(dec(0x705, "00"))["state"] == "boot-up"
    assert values(dec(0x705, "85")) == {"node": 5, "state": "operational", "toggle": 1}
    assert dec(0x705, "03").diagnostics[0].level == "warning"
    assert dec(0x705, is_remote=True).name == "node_guard_request"


def test_emcy():
    m = dec(0x085, "1081110000000000")
    assert values(m)["code"] == "0x8110 CAN overrun (objects lost)"
    assert values(m)["register"] == "generic,communication"
    assert values(dec(0x085, "1023040000000000"))["code"] == "0x2310 Current, device output side"
    assert values(dec(0x085, "0000000000000000"))["code"] == "0x0000 error reset / no error"
    assert dec(0x085, "10").has_errors


def test_sync_and_time():
    assert values(dec(0x080)) == {}
    assert values(dec(0x080, "07")) == {"counter": 7}
    assert values(dec(0x100, "E80300000100")) == {"time": "1984-01-02T00:00:01.000"}


def test_pdo_without_mapping_is_raw():
    m = dec(0x185, "0102")
    assert m.name == "tpdo1" and values(m) == {"node": 5, "data": b"\x01\x02"}


def test_non_canopen_frames_fall_back_to_the_frame_layer():
    assert dec(0x18FEF100, "01", is_extended=True).protocol == "can"
    assert dec(0x7F0, "01").protocol == "can"
    assert CanopenDecoder().feed(CanFrame(0.0, "?", 0, is_error=True))[0].name == "error_frame"


def test_registered_and_usable_from_cli(capsys):
    assert isinstance(build_decoder("canopen"), CanopenDecoder)
    assert main(["decode", str(FIX / "basic.log"), "--decoder", "canopen", "--service", "heartbeat"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1 and lines[0].endswith("node=5 state=pre-operational")
