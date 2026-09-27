import copy
from pathlib import Path

import pytest
import yaml

from protocol_analyzer.errors import DefinitionError
from protocol_analyzer.uart.crc import PRESETS
from protocol_analyzer.uart.definition import load_definition, numeric_type

EXAMPLE = Path(__file__).parent.parent / "defs" / "example_uart.yaml"

MINIMAL = {
    "protocol": "t",
    "frame": [
        {"name": "sync", "type": "u1", "role": "sync", "value": 0x7E},
        {"name": "cmd", "type": "u1"},
        {"name": "len", "type": "u1", "role": "length", "of": "data"},
        {"name": "data", "role": "payload", "dispatch": "cmd"},
    ],
    "commands": {1: {"name": "ping", "fields": []}},
}


def write(tmp_path, doc):
    p = tmp_path / "def.yaml"
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    return p


def test_numeric_type():
    assert numeric_type("u2le").fmt == "<H"
    assert numeric_type("s4be").fmt == ">i"
    assert numeric_type("f4").fmt == "<f" and not numeric_type("f4").is_int
    assert numeric_type("u1").size == 1
    assert numeric_type("u3") is None and numeric_type("bytes") is None


def test_example_definition_loads():
    d = load_definition(EXAMPLE)
    assert d.protocol == "example_uart" and d.versions == [1]
    assert d.sync_bytes == b"\xaa\x55"
    assert (d.prefix_size, d.suffix_size) == (11, 2)
    assert d.length.max == 1024 and d.payload.dispatch == "cmd_id"
    assert d.crc_field.crc == PRESETS["crc16_modbus"] and d.crc_field.covers == ("version", "data")
    assert d.show == ["src_module", "dst_module"]
    assert sorted(d.commands) == [1, 2, 3, 4, 5]
    assert d.frame[3].enum[0x10] == "MotorCtrl"
    flags = d.commands[2].variants[0].fields[1]
    assert flags.bits == {"enabled": (0, 0), "reverse": (1, 1), "mode": (2, 4), "fault": (7, 7)}
    readings = d.commands[3].variants[0].fields[1]
    assert (readings.type, readings.count) == ("channel_reading", "count")


def test_select_variants():
    d = load_definition(EXAMPLE)
    cmd, request = d.select(1, {"src_module": 0x01})
    assert cmd.name == "get_info" and request.when == {"src_module": 1} and request.fields == []
    _, response = d.select(1, {"src_module": 0x10})
    assert [f.name for f in response.fields] == ["fw_major", "fw_minor", "build", "serial"]
    assert d.select(0x99, {}) == (None, None)


def _mutate(path, value):
    """MINIMAL with the value at `path` (keys/indexes) replaced, appended (list index == len) or deleted (None)."""
    doc = copy.deepcopy(MINIMAL)
    target = doc
    for key in path[:-1]:
        target = target[key]
    last = path[-1]
    if value is None:
        del target[last]
    elif isinstance(target, list) and last == len(target):
        target.append(value)
    else:
        target[last] = value
    return doc


SYNC, CMD, LEN, DATA = MINIMAL["frame"]

BAD = [
    (("protocol",), None, "protocol: required"),
    (("framing",), 1, r"unknown key\(s\) framing"),
    (("frame",), [CMD, SYNC, LEN, DATA], "first frame field must have role: sync"),
    (("frame", 2), {"name": "len", "type": "u1"}, "needs a field with role: length"),
    (("frame", 2, "of"), "cmd", "must name the payload field 'data'"),
    (("frame", 3, "dispatch"), "nope", "dispatch: must name a frame field before the payload"),
    (("frame", 0, "value"), 0x1FF, "does not fit"),
    (("frame", 1, "type"), "bytes", "need an integer type"),
    (("frame", 2, "unit"), "B", "unit does not apply to a field with role length"),
    (("frame", 4), {"name": "crc", "type": "u2le", "role": "crc", "algo": "nope", "covers": ["cmd", "data"]},
     "unknown crc algorithm 'nope'"),
    (("frame", 4), {"name": "crc", "type": "u1", "role": "crc", "algo": "crc16_modbus", "covers": ["cmd", "data"]},
     "crc16_modbus is 16 bits"),
    (("frame", 4), {"name": "crc", "type": "u2le", "role": "crc", "algo": "crc16_modbus", "covers": ["data", "cmd"]},
     "covers"),
    (("versions",), [1], "needs a frame field named 'version'"),
    (("commands", 1, "fields"), [{"name": "x", "type": "u3"}], "unknown type 'u3'"),
    (("commands", 1, "fields"), [{"name": "x", "type": "f4", "bits": {"a": 0}}], "bits needs an integer type"),
    (("commands", 1, "fields"), [{"name": "x", "type": "bytes", "scale": 2}], "only apply to numeric types"),
    (("commands", 1, "fields"), [{"name": "x", "type": "bytes"}], "needs a size"),
    (("commands", 1, "fields"), [{"name": "x", "type": "bytes", "size": "n"}, {"name": "n", "type": "u1"}],
     "earlier integer field"),
    (("commands", 1, "fields"), [{"name": "x", "type": "u1", "count": "eos"}, {"name": "y", "type": "u1"}],
     "must be the last field"),
    (("commands", 1, "fields"), [{"name": "x", "type": "u1", "enum": "nope"}], "unknown enum 'nope'"),
    (("commands", 1, "fields"), [{"name": "x", "type": "u1", "typo": 1}], r"unknown key\(s\) typo"),
    (("commands", 1), {"name": "p", "variants": [{"fields": []}, {"when": {"cmd": 1}, "fields": []}]},
     "must be last"),
    (("commands", 1), {"name": "p", "variants": [{"when": {"cmd": "PING"}, "fields": []}]},
     "'PING' is not a name in cmd's enum"),
    (("commands", 1), {"name": "p", "variants": [{"when": {"data": 1}, "fields": []}]}, "is not a frame field"),
    (("commands", 1), {"name": "p"}, "exactly one of 'fields' or 'variants'"),
    (("commands", 1, "fields"), [{"name": "x", "hook": "missing.py:f"}], "not found"),
]


@pytest.mark.parametrize("path, value, match", BAD)
def test_invalid_definitions_name_the_problem(tmp_path, path, value, match):
    with pytest.raises(DefinitionError, match=match):
        load_definition(write(tmp_path, _mutate(path, value)))


def test_unreadable_and_invalid_yaml(tmp_path):
    with pytest.raises(DefinitionError, match="cannot read definition"):
        load_definition(tmp_path / "missing.yaml")
    (tmp_path / "bad.yaml").write_text("frame: [unclosed\n")
    with pytest.raises(DefinitionError, match="invalid YAML"):
        load_definition(tmp_path / "bad.yaml")


def test_hooks_load_relative_to_the_definition(tmp_path):
    (tmp_path / "hooks.py").write_text(
        "def sum8(data):\n    return sum(data) & 0xFF\n\n"
        "def tlv(data):\n    return data[1:1 + data[0]].hex(), 1 + data[0]\n")
    doc = _mutate(("frame", 4), {"name": "crc", "type": "u1", "role": "crc", "hook": "hooks.py:sum8",
                                 "covers": ["cmd", "data"]})
    doc["commands"][1]["fields"] = [{"name": "tlv", "hook": "hooks.py:tlv"}]
    d = load_definition(write(tmp_path, doc))
    assert d.crc_field.crc(b"\x01\x02") == 3
    assert d.commands[1].variants[0].fields[0].hook(b"\x02\xab\xcd") == ("abcd", 3)
    doc["commands"][1]["fields"] = [{"name": "tlv", "hook": "hooks.py:nope"}]
    with pytest.raises(DefinitionError, match="has no function 'nope'"):
        load_definition(write(tmp_path, doc))


def test_non_utf8_definition_is_a_definition_error(tmp_path):
    p = tmp_path / "ansi.yaml"
    p.write_bytes(yaml.safe_dump(MINIMAL).encode() + b"description: \xb0C\n")
    with pytest.raises(DefinitionError, match="not UTF-8"):
        load_definition(p)


def test_signed_length_field_is_rejected(tmp_path):
    with pytest.raises(DefinitionError, match="unsigned"):
        load_definition(write(tmp_path, _mutate(("frame", 2, "type"), "s1")))


def test_self_containing_type_is_rejected(tmp_path):
    doc = copy.deepcopy(MINIMAL)
    doc["types"] = {"node": [{"name": "y", "type": "node"}]}
    with pytest.raises(DefinitionError, match="contains itself"):
        load_definition(write(tmp_path, doc))


def test_hook_fields_take_count(tmp_path):
    (tmp_path / "hooks.py").write_text("def pair(data):\n    return data[:2].hex(), 2\n")
    doc = copy.deepcopy(MINIMAL)
    doc["commands"][1]["fields"] = [{"name": "p", "hook": "hooks.py:pair", "count": "eos"}]
    d = load_definition(write(tmp_path, doc))
    assert d.commands[1].variants[0].fields[0].count == "eos"


def test_show_cannot_name_the_payload_field(tmp_path):
    doc = copy.deepcopy(MINIMAL)
    doc["show"] = ["cmd", "data"]
    with pytest.raises(DefinitionError, match="payload"):
        load_definition(write(tmp_path, doc))
