import dataclasses
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest
from uart_helpers import chunks, make_frame

from protocol_analyzer.cli import main
from protocol_analyzer.errors import CaptureError, SessionError
from protocol_analyzer.registry import build_decoder
from protocol_analyzer.uart.decoder import UartDecoder
from protocol_analyzer.uart.definition import load_definition

EXAMPLE = Path(__file__).parent.parent / "defs" / "example_uart.yaml"
DEFN = load_definition(EXAMPLE)
MOTOR = bytes([1, 0x8D]) + struct.pack("<hHBf", -1500, 150, 65, 1500.0)
MOTOR_FRAME = make_frame(2, MOTOR)


def run(records, defn=DEFN):
    dec = UartDecoder(defn)
    out = []
    for r in records:
        out += dec.feed(r)
    return out + dec.flush()


def names(msgs):
    return [m.name for m in msgs]


def test_valid_frame():
    [m] = run(chunks(MOTOR_FRAME))
    assert (m.protocol, m.name, m.channel, m.offset) == ("example_uart", "motor_status", "rx", 0)
    assert not m.diagnostics
    assert m.summary.startswith("src_module=MCU dst_module=MotorCtrl state=running flags={enabled=true")
    assert "current=1.5 A" in m.summary and "temperature=25 °C" in m.summary
    assert [f.name for f in m.fields] == ["preamble", "version", "setting", "src_module", "dst_module",
                                          "src_trans", "dst_trans", "cmd_id", "data_len", "data", "crc"]
    assert m.get("preamble").label == "0x55AA"


def test_variant_selected_by_header():
    request, response = run(chunks(
        make_frame(1, src=0x01, dst=0x10),
        make_frame(1, bytes([1, 2]) + struct.pack("<H", 300) + b"SN-0001".ljust(16, b"\x00"), src=0x10, dst=0x01)))
    assert request.name == response.name == "get_info"
    assert request.get("data").children == []
    assert "serial=SN-0001" in response.summary


def test_unknown_command_and_version_keep_raw_data():
    [unknown] = run(chunks(make_frame(0x99, b"\x01\x02")))
    assert unknown.name == "cmd_0x99" and unknown.get("data").value == b"\x01\x02"
    assert "unknown command 0x99" in unknown.diagnostics[0].text
    [v2] = run(chunks(make_frame(2, MOTOR, version=2)))
    assert v2.name == "motor_status" and v2.get("data").value == MOTOR
    assert "unknown protocol version 2" in v2.diagnostics[0].text


def test_bad_crc_then_good_frame_without_double_reporting():
    msgs = run(chunks(make_frame(2, MOTOR, bad_crc=True) + MOTOR_FRAME))
    assert names(msgs) == ["bad_frame", "motor_status"]
    assert "CRC mismatch" in msgs[0].diagnostics[0].text and "crc16_modbus" in msgs[0].diagnostics[0].text


def test_unframed_bytes_before_and_after():
    msgs = run(chunks(b"\x01\x02\x03" + MOTOR_FRAME + b"\x07"))
    assert names(msgs) == ["unframed", "motor_status", "unframed"]
    assert msgs[0].get("data").value == b"\x01\x02\x03" and msgs[0].offset == 0
    assert msgs[2].get("data").value == b"\x07" and msgs[2].offset == 3 + len(MOTOR_FRAME)


def test_frame_split_at_every_boundary_decodes_identically():
    [whole] = run(chunks(MOTOR_FRAME))
    for cut in range(1, len(MOTOR_FRAME)):
        msgs = run(chunks(MOTOR_FRAME[:cut], MOTOR_FRAME[cut:]))
        assert [(m.name, m.summary) for m in msgs] == [(whole.name, whole.summary)], cut
    per_byte = run(chunks(*[bytes([b]) for b in MOTOR_FRAME]))
    assert [(m.name, m.summary) for m in per_byte] == [(whole.name, whole.summary)]


def test_sync_bytes_inside_a_payload_are_not_a_frame_start():
    [m] = run(chunks(make_frame(5, struct.pack("<3H", 0x55AA, 1, 2))))
    assert [c.value for c in m.get("data").children[0].children] == [0x55AA, 1, 2]


def test_false_sync_with_impossible_length_becomes_unframed():
    false = b"\xaa\x55" + bytes(7) + b"\xff\xff"  # data_len 65535 > max 1024
    msgs = run(chunks(false + MOTOR_FRAME))
    assert names(msgs) == ["unframed", "motor_status"] and msgs[0].get("data").value == false


def test_false_sync_overlapping_a_real_frame_is_recovered():
    false = b"\xaa\x55" + bytes(9)  # data_len 0: its CRC would be the real frame's sync bytes
    msgs = run(chunks(false + MOTOR_FRAME))
    assert names(msgs) == ["bad_frame", "motor_status"]


def test_layout_mismatch_diagnostics():
    [long] = run(chunks(make_frame(2, MOTOR + b"\x01\x02")))
    assert long.get("data").children[-1].name == "_trailing"
    assert "2 trailing data bytes" in long.diagnostics[0].text and not long.has_errors
    [short] = run(chunks(make_frame(2, MOTOR[:3])))
    assert short.has_errors and "definition error in motor_status" in short.diagnostics[0].text


def test_truncated_at_end_and_recovery_behind_it():
    [cut] = run(chunks(MOTOR_FRAME[:-3]))
    assert cut.name == "truncated" and "capture ends in the middle of a frame" in cut.diagnostics[0].text
    msgs = run(chunks(MOTOR_FRAME[:8] + MOTOR_FRAME))  # the partial frame claims 341 data bytes
    assert names(msgs) == ["truncated", "motor_status"]


def test_timestamps_offsets_and_sources():
    records = chunks(MOTOR_FRAME, MOTOR_FRAME[:4], MOTOR_FRAME[4:], times=[1.0, 2.0, 3.0])
    first, second = run(records)
    assert (first.start, first.end, first.sources) == (1.0, 1.0, [records[0]])
    assert (second.start, second.end, second.offset) == (2.0, 3.0, len(MOTOR_FRAME))
    assert second.sources == records[1:]


def test_idle_gap_abandons_a_partial_frame():
    gapped = dataclasses.replace(DEFN, gap_ms=5)
    msgs = run(chunks(MOTOR_FRAME[:5], MOTOR_FRAME, times=[0.0, 0.1]), gapped)
    assert names(msgs) == ["truncated", "motor_status"]
    assert "idle gap" in msgs[0].diagnostics[0].text
    with pytest.raises(CaptureError, match="needs a timestamped capture"):
        run(chunks(MOTOR_FRAME), gapped)


def test_registry():
    assert isinstance(build_decoder(f"uart:{EXAMPLE}"), UartDecoder)
    with pytest.raises(SessionError, match="needs a Definition"):
        build_decoder("uart")


READINGS_FRAME = make_frame(3, bytes([2, 1]) + struct.pack("<h", 215) + bytes([2]) + struct.pack("<h", -50))


def _capture(tmp_path):
    cap = tmp_path / "cap.hex"
    cap.write_text(f"0.000100 rx {READINGS_FRAME.hex(' ')}\n"
                   f"0.000900 tx {make_frame(1).hex()}\n")  # get_info request: empty layout
    return cap


def test_cli_end_to_end(capsys, tmp_path):
    cap = _capture(tmp_path)
    assert main(["decode", str(cap), "--decoder", f"uart:{EXAMPLE}"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2 and "channel_readings" in lines[0] and "raw=21.5 °C" in lines[0]
    assert main(["decode", str(cap), "--decoder", f"uart:{EXAMPLE}", "--format", "jsonl", "--channel", "tx"]) == 0
    [record] = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert record["name"] == "get_info" and record["time"] == pytest.approx(0.0008)
    assert main(["decoders"]) == 0 and "uart:<definition.yaml>" in capsys.readouterr().out


def test_output_survives_a_non_utf8_stdout(tmp_path):
    cap = _capture(tmp_path)
    env = {**os.environ, "PYTHONIOENCODING": "ascii"}  # stands in for cp1252 and other narrow code pages
    result = subprocess.run([sys.executable, "-m", "protocol_analyzer", "decode", str(cap),
                             "--decoder", f"uart:{EXAMPLE}"], capture_output=True, env=env)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert "raw=21.5 °C" in result.stdout.decode("utf-8")
