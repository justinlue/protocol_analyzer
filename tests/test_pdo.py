from pathlib import Path

from protocol_analyzer.canopen.decoder import CanopenDecoder
from protocol_analyzer.canopen.eds import load_eds
from protocol_analyzer.canopen.pdo import MapEntry, decode_pdo, pdo_mapping
from protocol_analyzer.cli import main
from protocol_analyzer.records import CanFrame

FIX = Path(__file__).parent / "fixtures"
EDS = FIX / "node5.eds"
OD = load_eds(EDS, 5)


def feed(can_id, hex_data, ods=None):
    data = bytes.fromhex(hex_data)
    [m] = CanopenDecoder({5: OD} if ods is None else ods).feed(
        CanFrame(0.0, "can0", can_id, data, dlc=len(data)))
    return m


def test_mapping_from_eds():
    assert pdo_mapping(OD, "tpdo1") == [MapEntry(0x6041, 0, 16), MapEntry(0x606C, 0, 32), MapEntry(0x2001, 1, 8)]
    assert pdo_mapping(OD, "rpdo1") == [MapEntry(0x6040, 0, 16)]
    assert pdo_mapping(OD, "tpdo2") == []
    assert pdo_mapping(OD, "tpdo3") is None


def test_tpdo_decodes_named_typed_objects():
    m = feed(0x185, "3706" "18FCFFFF" "05")
    assert [(f.name, f.value) for f in m.fields] == [
        ("node", 5), ("Statusword", 0x0637), ("Velocity actual value", -1000), ("Drive flags.Fault bits", 5)]
    assert not m.diagnostics


def test_bit_packed_entries():
    fields, bits = decode_pdo(OD, [MapEntry(0x2001, 1, 4), MapEntry(0x2001, 1, 4)], b"\x35")
    assert [f.value for f in fields] == [5, 3] and bits == 8
    assert fields[0].raw == b""  # not byte-aligned: no raw slice


def test_short_and_long_pdos():
    short = feed(0x185, "3706")
    assert short.has_errors and "mapping needs 7" in short.diagnostics[0].text
    assert [f.missing for f in short.fields[1:]] == [False, True, True]
    long = feed(0x205, "0F000000")
    assert long.get("Controlword").value == 15
    assert "2 bytes beyond the mapping" in long.diagnostics[0].text


def test_empty_mapping_and_no_eds():
    assert "no mapped objects" in feed(0x285, "01").diagnostics[0].text
    raw = feed(0x185, "3706", ods={})
    assert raw.get("data").value == b"\x37\x06" and not raw.diagnostics


def test_cli_decodes_pdo_with_eds(capsys, tmp_path):
    cap = tmp_path / "pdo.log"
    cap.write_text("(1.000000) can0 185#370618FCFFFF05\n")
    assert main(["decode", str(cap), "--decoder", "canopen", "--eds", f"5={EDS}"]) == 0
    assert "Velocity actual value=-1000" in capsys.readouterr().out


def test_zero_length_mapping_entry_is_flagged_not_a_crash(tmp_path):
    eds = tmp_path / "z.eds"
    eds.write_text("[1A00]\nParameterName=TPDO1 mapping\n[1A00sub0]\nDataType=0x0005\nDefaultValue=1\n"
                   "[1A00sub1]\nDataType=0x0007\nDefaultValue=0x606C0000\n"
                   "[606C]\nParameterName=Velocity\nDataType=0x0004\n")
    m = feed(0x185, "01", ods={5: load_eds(eds, 5)})
    assert any("length 0" in d.text for d in m.diagnostics)
