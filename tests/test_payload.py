import struct
from pathlib import Path

import pytest

from protocol_analyzer.uart.definition import FieldSpec, load_definition, numeric_type
from protocol_analyzer.uart.payload import decode_fields

DEFN = load_definition(Path(__file__).parent.parent / "defs" / "example_uart.yaml")
MOTOR = bytes([1, 0x8D]) + struct.pack("<hHBf", -1500, 150, 65, 1500.0)


def layout(cmd_id, **header):
    return DEFN.select(cmd_id, header)[1].fields


def decode(specs, data):
    return decode_fields(specs, data, DEFN.types)


def by_name(fields):
    return {f.name: f for f in fields}


def test_enum_bits_scale_offset_float():
    fields, used, problem = decode(layout(2), MOTOR)
    assert problem is None and used == len(MOTOR)
    f = by_name(fields)
    assert (f["state"].value, f["state"].label) == (1, "running")
    assert {c.name: c.value for c in f["flags"].children} == {
        "enabled": True, "reverse": False, "mode": 3, "fault": True}
    assert (f["speed"].value, f["speed"].unit) == (-1500, "rpm")
    assert f["current"].value == pytest.approx(1.5) and f["current"].raw == b"\x96\x00"
    assert f["temperature"].value == 25 and isinstance(f["temperature"].value, int)
    assert f["setpoint"].value == 1500.0


def test_array_of_structs_counted_by_an_earlier_field():
    data = bytes([2]) + bytes([1]) + struct.pack("<h", 215) + bytes([2]) + struct.pack("<h", -50)
    fields, used, problem = decode(layout(3), data)
    readings = by_name(fields)["readings"]
    assert problem is None and used == len(data)
    assert [c.name for c in readings.children] == ["[0]", "[1]"]
    first, second = (by_name(c.children) for c in readings.children)
    assert first["channel"].value == 1 and first["raw"].value == pytest.approx(21.5)
    assert second["raw"].value == pytest.approx(-5.0) and second["raw"].unit == "°C"
    empty, _, _ = decode(layout(3), bytes([0]))
    assert by_name(empty)["readings"].children == []


def test_inline_enum_and_rest_string():
    data = bytes([2]) + struct.pack("<I", 1234) + b"hello"
    f = by_name(decode(layout(4), data)[0])
    assert f["level"].label == "warn" and f["timestamp_ms"].value == 1234 and f["text"].value == "hello"


def test_fixed_string_strips_padding_and_variant_layout():
    data = bytes([1, 2]) + struct.pack("<H", 300) + b"SN-0001".ljust(16, b"\x00")
    f = by_name(decode(layout(1, src_module=0x10), data)[0])
    assert (f["fw_major"].value, f["build"].value, f["serial"].value) == (1, 300, "SN-0001")


def test_array_until_end_of_data():
    fields, used, problem = decode(layout(5), struct.pack("<3H", 1, 2, 3))
    assert [c.value for c in fields[0].children] == [1, 2, 3] and problem is None
    fields, used, problem = decode(layout(5), struct.pack("<3H", 1, 2, 3) + b"\x04")
    assert fields[0].children[-1].missing and "more than the 7 data bytes" in problem


def test_short_data_marks_the_rest_missing():
    fields, used, problem = decode(layout(2), MOTOR[:3])
    assert [f.missing for f in fields] == [False, False, True, True, True, True]
    assert used == 2 and "'speed'" in problem


def test_trailing_bytes_are_left_unconsumed():
    _, used, problem = decode(layout(2), MOTOR + b"\x01\x02")
    assert used == len(MOTOR) and problem is None


def test_strz_bytes_sized_by_field_and_hooks():
    u1 = numeric_type("u1")
    specs = [FieldSpec("name", type="strz"), FieldSpec("n", type="u1", num=u1),
             FieldSpec("blob", type="bytes", size="n"),
             FieldSpec("h", hook=lambda d: (d[0] * 2, 1))]
    fields, used, problem = decode(specs, b"ab\x00\x02\xaa\xbb\x05")
    assert [f.value for f in fields] == ["ab", 2, b"\xaa\xbb", 10] and used == 7 and problem is None
    _, _, problem = decode(specs[:1], b"ab")
    assert "no zero terminator" in problem
    _, _, problem = decode([FieldSpec("h", hook=lambda d: d[5])], b"\x01")
    assert "hook for field 'h' failed" in problem
