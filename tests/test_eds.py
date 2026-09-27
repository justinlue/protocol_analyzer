import struct
from pathlib import Path

import pytest

from protocol_analyzer.canopen.decoder import CanopenDecoder
from protocol_analyzer.canopen.eds import decode_value, load_eds
from protocol_analyzer.cli import main
from protocol_analyzer.errors import EdsError
from protocol_analyzer.records import CanFrame

FIX = Path(__file__).parent / "fixtures"
EDS = FIX / "node5.eds"


def test_names_values_and_types():
    od = load_eds(EDS, 5)
    assert od.name(0x1018, 1) == "Identity object.Vendor-ID"
    assert od.name(0x6041, 0) == "Statusword"
    assert od.name(0x6041, 1) is None
    assert od.name(0x9999, 0) is None
    assert od.value(0x1018, 1) == 0x12345678
    assert od.decode(0x1008, 0, b"drive\x00") == "drive"
    assert od.decode(0x1018, 0, b"\x01\x00\x00\x00") == 1  # UNSIGNED8 from a 4-byte expedited SDO


def test_decode_value_types():
    assert decode_value(0x0004, b"\x18\xfc\xff\xff") == -1000
    assert decode_value(0x0007, b"\x78\x56\x34\x12") == 0x12345678
    assert decode_value(0x0008, struct.pack("<f", 1.5)) == 1.5
    assert decode_value(0x0001, b"\x01") is True
    assert decode_value(0x0006, b"\x01") is None  # too short for UNSIGNED16
    assert decode_value(0x0017, b"\x01") is None  # unsupported type
    assert decode_value(None, b"\x01") is None


def test_nodeid_substitution_and_dcf_parameter_value(tmp_path):
    p = tmp_path / "n.dcf"
    p.write_text("[1800sub1]\nParameterName=COB-ID\nDataType=0x0007\nDefaultValue=$NODEID+0x180\n"
                 "[1A00sub0]\nParameterName=Count\nDataType=0x0005\nDefaultValue=3\nParameterValue=1\n")
    od = load_eds(p, 5)
    assert od.value(0x1800, 1) == 0x185
    assert od.value(0x1A00, 0) == 1


def test_bad_eds_files(tmp_path):
    with pytest.raises(EdsError, match="cannot read EDS"):
        load_eds(tmp_path / "missing.eds", 5)
    empty = tmp_path / "empty.eds"
    empty.write_text("[FileInfo]\nFileName=empty.eds\n")
    with pytest.raises(EdsError, match="no object dictionary entries"):
        load_eds(empty, 5)
    broken = tmp_path / "broken.eds"
    broken.write_text("no section header\n")
    with pytest.raises(EdsError, match="not a valid EDS"):
        load_eds(broken, 5)


def test_sdo_uses_the_nodes_object_dictionary():
    d = CanopenDecoder({5: load_eds(EDS, 5)})
    [m] = d.feed(CanFrame(0.0, "can0", 0x585, bytes.fromhex("4318100178563412"), dlc=8))
    assert m.get("object").value == "Identity object.Vendor-ID"
    assert m.get("data").value == 0x12345678 and m.get("data").raw == b"\x78\x56\x34\x12"
    [other] = d.feed(CanFrame(0.0, "can0", 0x586, bytes.fromhex("4318100178563412"), dlc=8))
    assert other.get("object") is None and other.get("data").value == b"\x78\x56\x34\x12"


def test_cli_eds_flag(capsys):
    argv = ["decode", str(FIX / "basic.log"), "--decoder", "canopen", "--eds", f"5={EDS}", "--service", "sdo"]
    assert main(argv) == 0
    last = capsys.readouterr().out.splitlines()[-1]
    assert "object=Identity object.Highest sub-index supported" in last and last.endswith("data=1")
    assert main(["decode", str(FIX / "basic.log"), "--decoder", "canopen", "--eds", "5=missing.eds"]) == 2
    assert "cannot read EDS" in capsys.readouterr().err
