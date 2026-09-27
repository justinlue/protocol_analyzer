from protocol_analyzer.message import Diagnostic, Field, Message
from protocol_analyzer.records import CanFrame


def test_get_returns_top_level_field_by_name():
    m = Message("can", "data", "can0", fields=[Field("id", 0x181), Field("dlc", 2)])
    assert m.get("dlc").value == 2
    assert m.get("nope") is None


def test_warn_and_error_append_diagnostics_in_order():
    m = Message("can", "data", "can0")
    m.warn("odd")
    assert not m.has_errors
    m.error("bad")
    assert m.has_errors
    assert m.diagnostics == [Diagnostic("warning", "odd"), Diagnostic("error", "bad")]


def test_field_child_lookup():
    f = Field("flags", 0x81, children=[Field("enabled", True), Field("fault", True)])
    assert f.child("fault").value is True
    assert f.child("missing") is None


def test_records_compare_by_value():
    a = CanFrame(1.0, "can0", 0x181, b"\x01", dlc=1)
    assert a == CanFrame(1.0, "can0", 0x181, b"\x01", dlc=1)
