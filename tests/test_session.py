from pathlib import Path

import pytest

from protocol_analyzer.analysis import Analysis
from protocol_analyzer.errors import SessionError
from protocol_analyzer.session import ANY_CHANNEL, Binding, Session, load_session, session_from_args

FIX = Path(__file__).parent / "fixtures"


def test_flags_default_to_can_decoder_for_can_captures():
    s = session_from_args(FIX / "basic.log")
    assert s.binding_for("can0") == Binding(["can"], {})


def test_uart_capture_requires_a_decoder():
    with pytest.raises(SessionError, match="uart:<definition.yaml>"):
        session_from_args("x.hex")


def test_eds_flags_parse_into_node_map():
    s = session_from_args("x.log", "canopen", ["5=a.eds", "0x10=b.eds"])
    assert s.bindings[ANY_CHANNEL].params == {"eds": {5: "a.eds", 16: "b.eds"}}


@pytest.mark.parametrize("bad", ["5", "x=a.eds", "0=a.eds", "128=a.eds", "5="])
def test_bad_eds_flag(bad):
    with pytest.raises(SessionError, match="NODE=PATH"):
        session_from_args("x.log", "canopen", [bad])


def test_eds_needs_canopen():
    with pytest.raises(SessionError, match="--eds only applies"):
        session_from_args("x.log", "can", ["5=a.eds"])


def test_load_session_resolves_paths_relative_to_the_file(tmp_path):
    (tmp_path / "s.yaml").write_text(
        "capture: bus.asc\n"
        "channels:\n"
        "  1: {decoder: canopen, eds: {5: node5.eds}}\n"
        "  '*': {decoder: [can]}\n")
    s = load_session(tmp_path / "s.yaml")
    assert s.capture == tmp_path / "bus.asc" and s.base_dir == tmp_path
    assert s.binding_for("1") == Binding(["canopen"], {"eds": {5: "node5.eds"}})
    assert s.binding_for("2") == Binding(["can"], {})


@pytest.mark.parametrize("text, match", [
    ("channels: {1: {decoder: can}}\n", "needs a 'capture'"),
    ("capture: a.log\n", "non-empty 'channels'"),
    ("capture: a.log\nchannels: {1: {eds: {}}}\n", r"channels\.1: needs a 'decoder'"),
    ("capture: a.log\nchannels: {1: {decoder: 5}}\n", "expected a decoder name"),
    ("capture: a.log\nchannels: {1: {decoder: canopen, eds: {x: a.eds}}}\n", "node id"),
    ("capture: [unclosed\n", "invalid YAML"),
])
def test_bad_session_files(tmp_path, text, match):
    (tmp_path / "s.yaml").write_text(text)
    with pytest.raises(SessionError, match=match):
        load_session(tmp_path / "s.yaml")


def test_analysis_sets_t0_before_yielding_and_skips_unbound_channels():
    s = Session(FIX / "basic.log", {"can0": Binding(["can"])})
    a = Analysis(s)
    it = a.messages()
    first = next(it)
    assert a.t0 == 1700000000.0 and first.name == "data"
    rest = list(it)
    assert len(rest) == 6  # 8 frames, minus the first, minus the error frame on channel "?"


def test_non_utf8_session_file_is_a_session_error(tmp_path):
    (tmp_path / "s.yaml").write_bytes(b"\xff\xfecapture: a.log\n")
    with pytest.raises(SessionError, match="not UTF-8"):
        load_session(tmp_path / "s.yaml")


def test_decoder_must_match_the_capture_kind():
    with pytest.raises(SessionError, match="reads uart"):
        list(Analysis(Session(FIX / "basic.log", {ANY_CHANNEL: Binding(["uart:x.yaml"])})).messages())


def test_bindings_are_validated_before_reading_even_an_empty_capture():
    s = session_from_args(FIX / "empty.log", "canopen", ["5=nothere.eds"])
    with pytest.raises(Exception, match="cannot read EDS"):
        list(Analysis(s).messages())


@pytest.mark.parametrize("text, match", [
    ("capture: a.log\nchannels: {1: {decoder: can, edss: {}}}\n", r"unknown key\(s\) edss"),
    ("capture: a.log\nchannels: {1: {decoder: canopen, eds: {200: a.eds}}}\n", "1-127"),
])
def test_session_binding_keys_and_node_ids_are_checked(tmp_path, text, match):
    (tmp_path / "s.yaml").write_text(text)
    with pytest.raises(SessionError, match=match):
        load_session(tmp_path / "s.yaml")
