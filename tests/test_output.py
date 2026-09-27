import json

from protocol_analyzer.message import Field, Message
from protocol_analyzer.output import format_fields, format_value, jsonl_line, table_line


def test_format_value_variants():
    assert format_value(Field("x", 5)) == "5"
    assert format_value(Field("x", 1.50, unit="A")) == "1.5 A"
    assert format_value(Field("x", 1, label="running")) == "running"
    assert format_value(Field("x", b"\x01\xab")) == "01 AB"
    assert format_value(Field("x", True)) == "true"
    assert format_value(Field("x", missing=True)) == "<missing>"
    group = Field("r", None, children=[Field("a", 1), Field("b", 2, unit="°C")])
    assert format_value(group) == "{a=1 b=2 °C}"
    assert format_value(Field("empty", None)) == "{}"


def test_format_fields_joins_name_value_pairs():
    assert format_fields([Field("node", 5), Field("state", 5, label="operational")]) == \
        "node=5 state=operational"


def test_table_line_relative_time_and_diagnostics():
    m = Message("can", "data", "can0", start=10.5, summary="181 [1] 01")
    m.warn("odd")
    assert table_line(m, t0=10.0).split() == [
        "0.500000", "can0", "can", "data", "181", "[1]", "01", "!warning:", "odd"]
    assert table_line(m, t0=10.0, absolute=True).split()[0] == "10.500000"


def test_table_line_without_timestamp_shows_offset():
    m = Message("u", "frame", "uart0", offset=42, fields=[Field("a", 1)])
    assert table_line(m, t0=None).split()[0] == "@42"
    assert table_line(m, t0=None).endswith("a=1")


def test_jsonl_line_round_trips_the_field_tree():
    m = Message("u", "cmd", "rx", start=2.0, offset=0, fields=[
        Field("data", None, raw=b"\x01", children=[Field("v", 1, raw=b"\x01", unit="V")]),
        Field("gone", missing=True),
    ])
    m.error("bad")
    d = json.loads(jsonl_line(m, t0=1.0))
    assert d["time"] == 1.0 and d["offset"] == 0
    assert d["fields"] == [
        {"name": "data", "raw": "01", "children": [{"name": "v", "value": 1, "unit": "V", "raw": "01"}]},
        {"name": "gone", "missing": True},
    ]
    assert d["diagnostics"] == [{"level": "error", "text": "bad"}]
