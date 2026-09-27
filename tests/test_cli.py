import json
from pathlib import Path

from protocol_analyzer.cli import main

FIX = Path(__file__).parent / "fixtures"
LOG = str(FIX / "basic.log")


def run(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out.splitlines(), err


def test_decode_table(capsys):
    code, lines, _ = run(capsys, "decode", LOG)
    assert code == 0 and len(lines) == 8
    assert lines[0].split() == ["0.000000", "can0", "can", "data", "000", "[2]", "01", "05"]


def test_decode_jsonl_and_abs(capsys):
    code, lines, _ = run(capsys, "decode", LOG, "--format", "jsonl", "--abs")
    first = json.loads(lines[0])
    assert (first["time"], first["channel"], first["protocol"], first["name"]) == (
        1700000000.0, "can0", "can", "data")


def test_decode_filters(capsys):
    assert len(run(capsys, "decode", LOG, "--id", "0x705")[1]) == 1
    assert len(run(capsys, "decode", LOG, "--errors-only")[1]) == 1
    assert len(run(capsys, "decode", LOG, "--time", "0.015:0.035")[1]) == 2
    assert run(capsys, "decode", LOG, "--channel", "can9")[1] == []


def test_info(capsys):
    code, lines, _ = run(capsys, "info", LOG)
    assert code == 0
    assert "records:  8" in lines
    assert "  0x705  1" in lines
    assert "error frames: 1" in lines


def test_decoders_lists_can(capsys):
    code, lines, _ = run(capsys, "decoders")
    assert code == 0 and any(line.startswith("can ") for line in lines)


def test_empty_capture_decodes_to_nothing(capsys):
    assert run(capsys, "decode", str(FIX / "empty.log"))[:2] == (0, [])
    assert "records:  0" in run(capsys, "info", str(FIX / "empty.log"))[1]


def test_bad_inputs_exit_2_with_one_line_error(capsys, tmp_path):
    (tmp_path / "x.pcap").write_bytes(b"")
    cases = [
        (["decode", str(FIX / "malformed.log")], "malformed.log"),
        (["decode", str(tmp_path / "x.pcap")], "unknown capture type"),
        (["decode", str(FIX / "uart_sample.hex")], "UART captures need"),
        (["decode", LOG, "--decoder", "nope"], "unknown decoder"),
        (["decode"], "needs a capture file or --session"),
        (["info", str(tmp_path / "missing.log")], "no such file"),
    ]
    for argv, needle in cases:
        code, out, err = run(capsys, *argv)
        assert code == 2, argv
        assert err.startswith("pa: error:") and needle in err, (argv, err)
        assert "Traceback" not in err


def test_session_file(capsys, tmp_path):
    (tmp_path / "basic.log").write_bytes((FIX / "basic.log").read_bytes())
    (tmp_path / "s.yaml").write_text("capture: basic.log\nchannels:\n  can0: {decoder: can}\n")
    code, lines, _ = run(capsys, "decode", "--session", str(tmp_path / "s.yaml"))
    assert code == 0 and len(lines) == 7  # the error frame's channel "?" is unbound
    code, _, err = run(capsys, "decode", "--session", str(tmp_path / "s.yaml"), "--decoder", "can")
    assert code == 2 and "cannot be combined" in err
