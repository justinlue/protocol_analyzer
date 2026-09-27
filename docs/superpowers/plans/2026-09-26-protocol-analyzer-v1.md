# Protocol Analyzer v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `pa`, a lightweight analyzer that decodes candump/ASC CAN captures (raw frames and CANopen) and UART captures (proprietary protocols framed by YAML Definitions) into Messages printed as a table or JSONL.

**Architecture:** Sources turn a Capture into Records (`CanFrame` / `UartChunk`), each tagged with a Channel. A Session binds each Channel to a Decoder stack of stateful stream processors that turn Records into Messages (field trees plus Diagnostics). The CLI filters Messages and formats them. Protocol logic lives in `canopen/` and `uart/`. Everything else is protocol-agnostic.

**Tech Stack:** Python ≥ 3.11, python-can (candump/ASC readers), PyYAML, pytest, argparse.

**Spec:** `DESIGN.md` (decisions) and `CONTEXT.md` (vocabulary). Read both before starting any task. Use CONTEXT.md terms in code, names and messages.

## Global Constraints

- Python `>=3.11`. The dev machine runs 3.14. Don't use anything removed in 3.14.
- Runtime dependencies are **only** `python-can>=4.4` and `pyyaml>=6`. The test dependency is `pytest>=8`. Add no others.
- Package: distribution `protocol-analyzer`, import package `protocol_analyzer` under `src/`, console script `pa = protocol_analyzer.cli:main`.
- Platform is Windows with Git Bash. Commands in this plan use `.venv/Scripts/python`. Run everything from the repo root `D:\Workshop\protocol_analyzer`.
- All user-facing failures raise a subclass of `protocol_analyzer.errors.PaError`. The CLI prints `pa: error: <text>` to stderr and exits with code 2. No tracebacks for bad input.
- Bad data is never dropped silently. It becomes a Message with a Diagnostic (DESIGN §3.4).
- UART multi-byte values default to little-endian (DESIGN §6.5).
- Commit after every task. End each commit message with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

These inputs are implied by the spec but easy to miss. Each one is pinned by a test in the owning task.

1. **Malformed, empty or unknown captures.** A garbage candump line, a zero-byte file or a `.pcap` must give `pa: error: …` with exit code 2, or empty output with exit code 0 for an empty file. Never a Python traceback. *(Task 2, Task 5)*
2. **Non-UTF-8 stdout on Windows.** `pa decode … > out.txt` under a cp1252 locale, with units like `°C` in the output, must not raise `UnicodeEncodeError`. *(Task 5, Task 13)*
3. **A UART frame split across chunks at every possible boundary, including between the two sync bytes.** It must decode identically to the unsplit frame. *(Task 13)*
4. **Sync bytes inside a valid payload, and a false sync followed by a real frame.** The real frame is recovered, and bytes are not reported twice. *(Task 13)*
5. **Two nodes' SDO segmented transfers interleaved, and an abort in the middle of a transfer.** State is kept per node, and an abort clears that node's transfer without touching the other's. *(Task 7)*

## File Structure

```
pyproject.toml                  package metadata, deps, entry point, pytest config
CLAUDE.md                       commands + layout for agents
src/protocol_analyzer/
  __init__.py
  __main__.py                   `python -m protocol_analyzer` → cli.main
  errors.py                     PaError hierarchy
  records.py                    CanFrame, UartChunk, Record
  message.py                    Field, Diagnostic, Message
  sources/__init__.py           capture_kind(), open_capture()
  sources/can_files.py          candump/ASC via python-can → CanFrame
  sources/uart_files.py         .bin / hex text → UartChunk
  decoders/__init__.py          (empty package marker)
  decoders/base.py              Decoder protocol, DecoderStack
  decoders/can.py               frame_message(), CanDecoder
  registry.py                   decoder registry, build_decoder()
  output.py                     table / JSONL formatting
  filters.py                    Filters + flag parsers
  session.py                    Binding, Session, session_from_args(), load_session()
  analysis.py                   Analysis: runs a Session → Messages
  info.py                       capture_info(), format_info()
  cli.py                        argparse front end
  canopen/__init__.py
  canopen/cobid.py              classify()
  canopen/tables.py             NMT/heartbeat/EMCY/SDO-abort lookup tables
  canopen/sdo.py                SdoTracker (stateful SDO decoding)
  canopen/eds.py                ObjectDictionary, load_eds(), decode_value()
  canopen/pdo.py                pdo_mapping(), decode_pdo()
  canopen/decoder.py            CanopenDecoder
  uart/__init__.py
  uart/crc.py                   CrcParams, PRESETS, crc()
  uart/definition.py            Definition model + load_definition()
  uart/payload.py               decode_fields()
  uart/decoder.py               UartDecoder (framer + frame decoding)
tests/
  fixtures/                     checked-in capture / EDS fixtures
  uart_helpers.py               make_frame() for building valid UART frames
  test_*.py                     one test module per source module
```

---

### Task 1: Project scaffold and core model

**Files:**
- Create: `pyproject.toml`, `.gitignore`, `CLAUDE.md`
- Create: `src/protocol_analyzer/__init__.py`, `src/protocol_analyzer/errors.py`, `src/protocol_analyzer/records.py`, `src/protocol_analyzer/message.py`
- Test: `tests/test_message.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `errors.PaError`, `CaptureError`, `SessionError`, `DefinitionError`, `EdsError` (all subclass `PaError`)
  - `records.CanFrame(timestamp: float|None, channel: str, id: int, data: bytes=b"", dlc: int=0, is_extended=False, is_remote=False, is_fd=False, brs=False, esi=False, is_error=False)` (frozen)
  - `records.UartChunk(timestamp: float|None, channel: str, offset: int, data: bytes)` (frozen)
  - `records.Record = CanFrame | UartChunk`
  - `message.Field(name, value=None, raw=b"", unit=None, label=None, children=[], missing=False)` with `.child(name) -> Field|None`. **Convention:** a group Field (struct or array) has `value=None` and carries `children`. A leaf Field always has a non-None `value`.
  - `message.Diagnostic(level: "warning"|"error", text: str)` (frozen)
  - `message.Message(protocol, name, channel, start=None, end=None, offset=None, fields=[], diagnostics=[], sources=[], summary=None)` with `.get(name)`, `.warn(text)`, `.error(text)`, `.has_errors`

- [ ] **Step 1: Write packaging files**

`pyproject.toml`:
```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "protocol-analyzer"
version = "0.1.0"
description = "Lightweight Sigrok-like analyzer for CAN/CANopen and proprietary UART captures."
requires-python = ">=3.11"
dependencies = ["python-can>=4.4", "pyyaml>=6"]

[project.optional-dependencies]
dev = ["pytest>=8"]

[project.scripts]
pa = "protocol_analyzer.cli:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

`.gitignore`:
```
.venv/
__pycache__/
*.egg-info/
.pytest_cache/
```

`CLAUDE.md`:
```markdown
# CLAUDE.md

Lightweight Sigrok-like protocol analyzer (`pa`): CAN/CANopen from candump/ASC captures, proprietary UART framed by YAML Definitions.

- Design decisions: `DESIGN.md`. Vocabulary: `CONTEXT.md`. Use its terms (Record, Message, Decoder, Definition…) and avoid its `_Avoid_` words.
- Setup: `python -m venv .venv && .venv/Scripts/python -m pip install -e ".[dev]"`
- Tests: `.venv/Scripts/python -m pytest -q`
- Run: `.venv/Scripts/pa decode <capture> [--decoder canopen|uart:<def.yaml>]`
- Layout: `sources/` read Captures into Records; `decoders/`, `canopen/`, `uart/` turn Records into Messages; `session.py`/`analysis.py` wire Channels to Decoder stacks; `cli.py`, `output.py`, `filters.py` are the front end.
- Rules: user-facing failures raise a `PaError` subclass (CLI prints `pa: error:` and exits 2); bad data becomes a Message with Diagnostics, never a silent drop; tests first.
```

- [ ] **Step 2: Create the venv and install dependencies**

Run: `python -m venv .venv && .venv/Scripts/python -m pip install -q "python-can>=4.4" "pyyaml>=6" "pytest>=8"`
Expected: exits 0. The package itself is installed in Step 6, once `src/` exists.

- [ ] **Step 3: Write the failing test**

`tests/test_message.py`:
```python
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
```

- [ ] **Step 4: Run test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/test_message.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'protocol_analyzer'`

- [ ] **Step 5: Write the implementation**

`src/protocol_analyzer/__init__.py`:
```python
"""Lightweight protocol analyzer for CAN/CANopen and proprietary UART captures."""
```

`src/protocol_analyzer/errors.py`:
```python
class PaError(Exception):
    """An error reported to the user as 'pa: error: ...' with exit code 2."""


class CaptureError(PaError):
    """A Capture is missing, of an unsupported type, or malformed."""


class SessionError(PaError):
    """CLI flags or a session file are inconsistent or incomplete."""


class DefinitionError(PaError):
    """A UART Definition is invalid."""


class EdsError(PaError):
    """An EDS/DCF file cannot be read."""
```

`src/protocol_analyzer/records.py`:
```python
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CanFrame:
    timestamp: float | None
    channel: str
    id: int
    data: bytes = b""
    dlc: int = 0
    is_extended: bool = False
    is_remote: bool = False
    is_fd: bool = False
    brs: bool = False
    esi: bool = False
    is_error: bool = False


@dataclass(frozen=True)
class UartChunk:
    timestamp: float | None  # None for captures without timestamps (raw .bin)
    channel: str
    offset: int  # byte offset of data[0] within this Channel's stream
    data: bytes


Record = CanFrame | UartChunk
```

`src/protocol_analyzer/message.py`:
```python
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .records import Record


@dataclass
class Field:
    """A decoded value. Group Fields (structs, arrays) have value None and carry children."""

    name: str
    value: Any = None
    raw: bytes = b""
    unit: str | None = None
    label: str | None = None  # enum name or display text for value
    children: list[Field] = field(default_factory=list)
    missing: bool = False  # the layout expected this field but the data ran out

    def child(self, name: str) -> Field | None:
        return next((c for c in self.children if c.name == name), None)


@dataclass(frozen=True)
class Diagnostic:
    level: str  # "warning" | "error"
    text: str


@dataclass
class Message:
    protocol: str
    name: str
    channel: str
    start: float | None = None
    end: float | None = None
    offset: int | None = None  # byte offset, for captures without timestamps
    fields: list[Field] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    sources: list[Record] = field(default_factory=list)
    summary: str | None = None  # table text; None means "format the fields"

    def get(self, name: str) -> Field | None:
        return next((f for f in self.fields if f.name == name), None)

    def warn(self, text: str) -> None:
        self.diagnostics.append(Diagnostic("warning", text))

    def error(self, text: str) -> None:
        self.diagnostics.append(Diagnostic("error", text))

    @property
    def has_errors(self) -> bool:
        return any(d.level == "error" for d in self.diagnostics)
```

- [ ] **Step 6: Install and run tests**

Run: `.venv/Scripts/python -m pip install -q -e ".[dev]" && .venv/Scripts/python -m pytest tests/test_message.py -v`
Expected: 4 passed

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml .gitignore CLAUDE.md src tests
git commit -m "feat: scaffold package with Record and Message model

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Capture sources (CAN and UART)

**Files:**
- Create: `src/protocol_analyzer/sources/__init__.py`, `sources/can_files.py`, `sources/uart_files.py`
- Create fixtures: `tests/fixtures/basic.log`, `basic.asc`, `malformed.log`, `empty.log`, `uart_sample.hex`
- Test: `tests/test_sources.py`

**Interfaces:**
- Consumes: `CanFrame`, `UartChunk`, `CaptureError` (Task 1).
- Produces:
  - `sources.capture_kind(path) -> "can" | "uart"`. Raises `CaptureError` for unknown suffixes.
  - `sources.open_capture(path) -> Iterator[Record]`. Raises `CaptureError` for a missing file or an unknown type. Malformed content raises `CaptureError` during iteration.
  - `sources.CAN_SUFFIXES = {".log", ".asc"}` and `sources.UART_SUFFIXES = {".bin", ".hex", ".txt"}`.
  - Channel naming:
    - candump uses the interface name (`can0`). python-can drops the channel of candump error frames, so those get `"?"`.
    - ASC uses the channel number **as written in the file** (`"1"`). python-can reports it 0-based, so add 1.
    - Raw `.bin` uses `"uart0"`.
    - Hex text uses the second column.
  - UART hex text format: one chunk per line, `<seconds> <channel> <hex bytes…>`. `#` starts a comment. Hex bytes may be spaced or run together.

Facts checked against python-can 4.6.1: `CanutilsLogReader` raises `ValueError` on a garbage line and skips blank lines. `ASCReader` gives 0-based int channels and relative timestamps. For FD frames, `msg.dlc` is the data length.

- [ ] **Step 1: Create fixtures**

`tests/fixtures/basic.log`:
```
(1700000000.000000) can0 000#0105
(1700000000.010000) can0 705#7F
(1700000000.020000) can0 605#4018100000000000
(1700000000.030000) can0 585#4318100001020304
(1700000000.040000) can0 18FEF100#0102
(1700000000.050000) can0 123#R
(1700000000.060000) can0 123##1AABBCCDD
(1700000000.070000) can0 20000080#0000000000000000
```

`tests/fixtures/basic.asc`:
```
date Sat Sep 26 10:00:00.000 am 2026
base hex  timestamps absolute
internal events logged
Begin Triggerblock Sat Sep 26 10:00:00.000 am 2026
   0.000000 1  000             Rx   d 2 01 05
   0.010000 1  705             Rx   d 1 7F
   0.020000 2  18FEF100x       Rx   d 2 01 02
   0.030000 1  123             Rx   r
   0.040000 1  ErrorFrame
   0.050000 CANFD   1 Rx        181                                   1 0 8  8 01 02 03 04 05 06 07 08   0    0   303000    0     0    0    0    0
End TriggerBlock
```

`tests/fixtures/malformed.log`:
```
(1.000000) can0 123#01
garbage line here
```

`tests/fixtures/empty.log`: a zero-byte file (`: > tests/fixtures/empty.log`).

`tests/fixtures/uart_sample.hex`:
```
# timestamp channel bytes
0.000100 rx AA 55 01
0.000200 tx aa55
0.000300 rx 00 0010   # trailing comment
```

- [ ] **Step 2: Write the failing tests**

`tests/test_sources.py`:
```python
from pathlib import Path

import pytest

from protocol_analyzer.errors import CaptureError
from protocol_analyzer.sources import capture_kind, open_capture

FIX = Path(__file__).parent / "fixtures"


def test_candump_frames_map_every_field():
    frames = list(open_capture(FIX / "basic.log"))
    assert len(frames) == 8
    nmt = frames[0]
    assert (nmt.timestamp, nmt.channel, nmt.id, nmt.data, nmt.dlc) == (
        1700000000.0, "can0", 0x000, b"\x01\x05", 2)
    ext = frames[4]
    assert ext.id == 0x18FEF100 and ext.is_extended
    rtr = frames[5]
    assert rtr.is_remote and rtr.data == b""
    fd = frames[6]
    assert fd.is_fd and fd.brs and not fd.esi and fd.data == bytes.fromhex("AABBCCDD")
    err = frames[7]
    assert err.is_error and err.channel == "?"


def test_asc_channels_keep_the_numbering_written_in_the_file():
    frames = list(open_capture(FIX / "basic.asc"))
    assert [f.channel for f in frames] == ["1", "1", "2", "1", "1", "1"]
    assert frames[2].is_extended and frames[2].id == 0x18FEF100
    assert frames[3].is_remote
    assert frames[4].is_error
    fd = frames[5]
    assert fd.is_fd and fd.brs and fd.id == 0x181 and fd.data == bytes(range(1, 9))


def test_empty_capture_yields_nothing():
    assert list(open_capture(FIX / "empty.log")) == []


def test_malformed_candump_raises_capture_error_naming_the_file():
    with pytest.raises(CaptureError, match="malformed.log"):
        list(open_capture(FIX / "malformed.log"))


def test_unknown_extension_is_rejected_with_the_supported_list(tmp_path):
    p = tmp_path / "x.pcap"
    p.write_bytes(b"")
    with pytest.raises(CaptureError, match=r"unknown capture type '\.pcap'.*\.asc"):
        open_capture(p)


def test_missing_file_is_a_capture_error(tmp_path):
    with pytest.raises(CaptureError, match="no such file"):
        open_capture(tmp_path / "nope.log")


def test_capture_kind():
    assert capture_kind("a.LOG") == "can"
    assert capture_kind("a.hex") == "uart"


def test_uart_bin_chunks_carry_offsets_not_timestamps(tmp_path):
    payload = bytes(range(256)) * 20  # 5120 bytes → two chunks
    p = tmp_path / "cap.bin"
    p.write_bytes(payload)
    chunks = list(open_capture(p))
    assert [c.offset for c in chunks] == [0, 4096]
    assert all(c.timestamp is None and c.channel == "uart0" for c in chunks)
    assert b"".join(c.data for c in chunks) == payload


def test_uart_hex_lines_track_offsets_per_channel():
    chunks = list(open_capture(FIX / "uart_sample.hex"))
    assert [(c.timestamp, c.channel, c.offset, c.data) for c in chunks] == [
        (0.0001, "rx", 0, b"\xaa\x55\x01"),
        (0.0002, "tx", 0, b"\xaa\x55"),
        (0.0003, "rx", 3, b"\x00\x00\x10"),
    ]


def test_uart_hex_bad_line_reports_file_and_line(tmp_path):
    p = tmp_path / "bad.hex"
    p.write_text("0.1 rx AA\n0.2 rx ZZ\n")
    with pytest.raises(CaptureError, match=r"bad\.hex:2"):
        list(open_capture(p))
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_sources.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'protocol_analyzer.sources'`

- [ ] **Step 4: Write the implementation**

`src/protocol_analyzer/sources/__init__.py`:
```python
from __future__ import annotations

from pathlib import Path
from typing import Iterator

from ..errors import CaptureError
from ..records import Record
from .can_files import read_can_capture
from .uart_files import read_uart_capture

CAN_SUFFIXES = {".log", ".asc"}
UART_SUFFIXES = {".bin", ".hex", ".txt"}


def capture_kind(path: str | Path) -> str:
    suffix = Path(path).suffix.lower()
    if suffix in CAN_SUFFIXES:
        return "can"
    if suffix in UART_SUFFIXES:
        return "uart"
    known = ", ".join(sorted(CAN_SUFFIXES | UART_SUFFIXES))
    raise CaptureError(f"{path}: unknown capture type '{suffix}' (expected one of {known})")


def open_capture(path: str | Path) -> Iterator[Record]:
    p = Path(path)
    kind = capture_kind(p)
    if not p.is_file():
        raise CaptureError(f"{p}: no such file")
    return read_can_capture(p) if kind == "can" else read_uart_capture(p)
```

`src/protocol_analyzer/sources/can_files.py`:
```python
from __future__ import annotations

from pathlib import Path
from typing import Iterator

import can

from ..errors import CaptureError
from ..records import CanFrame


def read_can_capture(path: Path) -> Iterator[CanFrame]:
    is_asc = path.suffix.lower() == ".asc"
    reader = can.ASCReader if is_asc else can.CanutilsLogReader
    try:
        for msg in reader(str(path)):
            yield CanFrame(
                timestamp=msg.timestamp,
                channel=_channel(msg.channel, is_asc),
                id=msg.arbitration_id,
                data=bytes(msg.data),
                dlc=msg.dlc,
                is_extended=msg.is_extended_id,
                is_remote=msg.is_remote_frame,
                is_fd=msg.is_fd,
                brs=msg.bitrate_switch,
                esi=msg.error_state_indicator,
                is_error=msg.is_error_frame,
            )
    except (ValueError, IndexError, KeyError) as exc:
        raise CaptureError(f"{path}: malformed capture: {exc}") from exc


def _channel(channel: object, is_asc: bool) -> str:
    if channel is None:  # python-can drops the channel of candump error frames
        return "?"
    if is_asc:  # python-can makes ASC channels 0-based; show them as written in the file
        return str(int(channel) + 1)
    return str(channel)
```

`src/protocol_analyzer/sources/uart_files.py`:
```python
from __future__ import annotations

from pathlib import Path
from typing import Iterator

from ..errors import CaptureError
from ..records import UartChunk

RAW_CHANNEL = "uart0"
CHUNK_SIZE = 4096


def read_uart_capture(path: Path) -> Iterator[UartChunk]:
    if path.suffix.lower() == ".bin":
        return _read_bin(path)
    return _read_hex(path)


def _read_bin(path: Path) -> Iterator[UartChunk]:
    offset = 0
    with path.open("rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            yield UartChunk(None, RAW_CHANNEL, offset, chunk)
            offset += len(chunk)


def _read_hex(path: Path) -> Iterator[UartChunk]:
    offsets: dict[str, int] = {}
    with path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            text = line.split("#", 1)[0].strip()
            if not text:
                continue
            parts = text.split()
            where = f"{path.name}:{lineno}"
            if len(parts) < 3:
                raise CaptureError(f"{where}: expected '<seconds> <channel> <hex bytes>'")
            try:
                timestamp = float(parts[0])
            except ValueError:
                raise CaptureError(f"{where}: bad timestamp {parts[0]!r}") from None
            try:
                data = bytes.fromhex("".join(parts[2:]))
            except ValueError:
                raise CaptureError(f"{where}: bad hex bytes") from None
            channel = parts[1]
            offset = offsets.get(channel, 0)
            offsets[channel] = offset + len(data)
            yield UartChunk(timestamp, channel, offset, data)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/test_sources.py -v`
Expected: 10 passed

- [ ] **Step 6: Commit**

```bash
git add src/protocol_analyzer/sources tests/fixtures tests/test_sources.py
git commit -m "feat: read candump/ASC and UART bin/hex captures into Records

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Decoder stack, CAN frame decoder, registry

**Files:**
- Create: `src/protocol_analyzer/decoders/__init__.py` (empty), `decoders/base.py`, `decoders/can.py`, `src/protocol_analyzer/registry.py`
- Test: `tests/test_decoders.py`

**Interfaces:**
- Consumes: `CanFrame`, `UartChunk`, `Message`, `Field`, `SessionError`.
- Produces:
  - `decoders.base.Item = Record | Message`.
  - `decoders.base.Decoder`, a Protocol with `feed(item: Item) -> list[Item]` and `flush() -> list[Item]`. **Contract:** a Decoder returns Messages it doesn't handle unchanged (`[item]`), and returns `[]` for Records it doesn't handle.
  - `decoders.base.DecoderStack(decoders: list[Decoder])` with `feed(record) -> list[Message]` and `flush() -> list[Message]`.
  - `decoders.can.frame_message(frame: CanFrame) -> Message` (protocol `"can"`; name `data`/`remote`/`fd`/`error_frame`). CANopen reuses it for frames that aren't CANopen.
  - `decoders.can.CanDecoder`.
  - `registry.DecoderInfo(name, usage, description, factory)`, where `factory(arg: str, params: dict, base_dir: Path) -> Decoder`.
  - `registry.REGISTRY: dict[str, DecoderInfo]`.
  - `registry.build_decoder(spec: str, params: dict|None=None, base_dir: Path=Path(".")) -> Decoder`. `spec` is `name` or `name:arg`. An unknown name raises `SessionError`. Later tasks add `canopen` (Task 6) and `uart` (Task 13) entries to `REGISTRY`.

- [ ] **Step 1: Write the failing tests**

`tests/test_decoders.py`:
```python
import pytest

from protocol_analyzer.decoders.base import DecoderStack
from protocol_analyzer.decoders.can import CanDecoder, frame_message
from protocol_analyzer.errors import SessionError
from protocol_analyzer.message import Message
from protocol_analyzer.records import CanFrame, UartChunk
from protocol_analyzer.registry import REGISTRY, build_decoder


def test_data_frame_message():
    m = frame_message(CanFrame(1.0, "can0", 0x181, b"\x01\x02", dlc=2))
    assert (m.protocol, m.name, m.channel, m.start, m.end) == ("can", "data", "can0", 1.0, 1.0)
    assert m.summary == "181 [2] 01 02"
    assert m.get("id").value == 0x181 and m.get("id").label == "181"
    assert m.get("data").value == b"\x01\x02"
    assert m.sources == [CanFrame(1.0, "can0", 0x181, b"\x01\x02", dlc=2)]


def test_extended_remote_and_fd_frames():
    ext = frame_message(CanFrame(0.0, "1", 0x18FEF100, b"\x01\x02", dlc=2, is_extended=True))
    assert ext.summary == "18FEF100 [2] 01 02  (ext)"
    rtr = frame_message(CanFrame(0.0, "1", 0x123, b"", dlc=0, is_remote=True))
    assert rtr.name == "remote" and rtr.summary == "123 [0] RTR" and rtr.get("data") is None
    fd = frame_message(CanFrame(0.0, "1", 0x123, bytes.fromhex("AABBCCDD"), dlc=4, is_fd=True, brs=True))
    assert fd.name == "fd" and fd.summary == "123 [4] AA BB CC DD  (fd,brs)"


def test_error_frame_is_an_error_message():
    m = frame_message(CanFrame(0.0, "?", 0, is_error=True))
    assert m.name == "error_frame" and m.has_errors


def test_can_decoder_passes_messages_through_and_ignores_uart():
    dec = CanDecoder()
    passthrough = Message("x", "y", "c")
    assert dec.feed(passthrough) == [passthrough]
    assert dec.feed(UartChunk(None, "u", 0, b"\x00")) == []
    assert dec.flush() == []


class _Tag:
    """Test decoder: wraps anything it sees in a Message named after itself; emits '<tag>-tail' on flush."""

    def __init__(self, tag):
        self.tag = tag

    def feed(self, item):
        inner = item.name if isinstance(item, Message) else "record"
        return [Message("t", f"{self.tag}({inner})", "c")]

    def flush(self):
        return [Message("t", f"{self.tag}-tail", "c")]


def test_stack_chains_decoders_and_cascades_flush():
    stack = DecoderStack([_Tag("a"), _Tag("b")])
    assert [m.name for m in stack.feed(CanFrame(0.0, "c", 1))] == ["b(a(record))"]
    assert [m.name for m in stack.flush()] == ["b(a-tail)", "b-tail"]


def test_build_decoder():
    assert isinstance(build_decoder("can"), CanDecoder)
    assert "can" in REGISTRY
    with pytest.raises(SessionError, match="unknown decoder 'nope'"):
        build_decoder("nope")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_decoders.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'protocol_analyzer.decoders'`

- [ ] **Step 3: Write the implementation**

`src/protocol_analyzer/decoders/__init__.py`: empty file.

`src/protocol_analyzer/decoders/base.py`:
```python
from __future__ import annotations

from typing import Protocol

from ..message import Message
from ..records import Record

Item = Record | Message


class Decoder(Protocol):
    """A stateful stream processor for one protocol layer.

    feed() returns Messages it does not handle unchanged and [] for Records it does not handle.
    """

    def feed(self, item: Item) -> list[Item]: ...

    def flush(self) -> list[Item]: ...


class DecoderStack:
    """Decoders bound to one Channel, each consuming the output of the one below."""

    def __init__(self, decoders: list[Decoder]):
        if not decoders:
            raise ValueError("a Decoder stack needs at least one Decoder")
        self.decoders = decoders

    def feed(self, record: Record) -> list[Message]:
        return self._through(0, [record])

    def flush(self) -> list[Message]:
        out: list[Message] = []
        for i, decoder in enumerate(self.decoders):
            out += self._through(i + 1, decoder.flush())
        return out

    def _through(self, start: int, items: list[Item]) -> list[Message]:
        for decoder in self.decoders[start:]:
            items = [out for item in items for out in decoder.feed(item)]
        return [item for item in items if isinstance(item, Message)]
```

`src/protocol_analyzer/decoders/can.py`:
```python
from __future__ import annotations

from ..message import Field, Message
from ..records import CanFrame
from .base import Item


def frame_message(frame: CanFrame) -> Message:
    """The frame layer: one CanFrame as a Message, nothing interpreted."""
    msg = Message("can", "data", frame.channel, start=frame.timestamp, end=frame.timestamp,
                  sources=[frame])
    if frame.is_error:
        msg.name = "error_frame"
        msg.summary = "error frame"
        msg.error("CAN error frame")
        return msg
    id_text = f"{frame.id:08X}" if frame.is_extended else f"{frame.id:03X}"
    flags = [name for name, on in (("ext", frame.is_extended), ("rtr", frame.is_remote),
                                   ("fd", frame.is_fd), ("brs", frame.brs), ("esi", frame.esi)) if on]
    msg.fields = [Field("id", frame.id, label=id_text), Field("dlc", frame.dlc)]
    if flags:
        msg.fields.append(Field("flags", ",".join(flags)))
    if frame.is_remote:
        msg.name = "remote"
        body = "RTR"
    else:
        msg.name = "fd" if frame.is_fd else "data"
        msg.fields.append(Field("data", frame.data, raw=frame.data))
        body = " ".join(f"{b:02X}" for b in frame.data)
    msg.summary = f"{id_text} [{frame.dlc}] {body}".rstrip()
    shown = [f for f in flags if f != "rtr"]
    if shown:
        msg.summary += f"  ({','.join(shown)})"
    return msg


class CanDecoder:
    def feed(self, item: Item) -> list[Item]:
        if isinstance(item, CanFrame):
            return [frame_message(item)]
        if isinstance(item, Message):
            return [item]
        return []

    def flush(self) -> list[Item]:
        return []
```

`src/protocol_analyzer/registry.py`:
```python
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .decoders.base import Decoder
from .errors import SessionError

# (argument after "name:", the Binding's params, base dir for relative paths) -> Decoder
Factory = Callable[[str, dict, Path], Decoder]


@dataclass(frozen=True)
class DecoderInfo:
    name: str
    usage: str
    description: str
    factory: Factory


def _can(arg: str, params: dict, base_dir: Path) -> Decoder:
    from .decoders.can import CanDecoder

    return CanDecoder()


REGISTRY: dict[str, DecoderInfo] = {
    "can": DecoderInfo("can", "can", "CAN/CAN-FD frame layer: id, flags, dlc, data", _can),
}


def build_decoder(spec: str, params: dict | None = None, base_dir: Path = Path(".")) -> Decoder:
    name, _, arg = spec.partition(":")
    info = REGISTRY.get(name)
    if info is None:
        known = ", ".join(sorted(REGISTRY))
        raise SessionError(f"unknown decoder '{name}' (available: {known})")
    return info.factory(arg, params or {}, base_dir)
```

Decoder factories import lazily (inside the factory) so that `canopen/` and `uart/` modules can import from `decoders/` without an import cycle through `registry`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/test_decoders.py -v`
Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add src/protocol_analyzer/decoders src/protocol_analyzer/registry.py tests/test_decoders.py
git commit -m "feat: add Decoder stack, CAN frame decoder and decoder registry

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Output formatting and filters

**Files:**
- Create: `src/protocol_analyzer/output.py`, `src/protocol_analyzer/filters.py`
- Test: `tests/test_output.py`, `tests/test_filters.py`

**Interfaces:**
- Consumes: `Message`, `Field`, `Diagnostic`, `CanFrame`.
- Produces:
  - `output.format_value(f: Field) -> str` and `output.format_fields(fields: list[Field]) -> str` (space-separated `name=value`). The UART decoder uses both for its summary.
  - `output.table_line(msg, t0: float|None, absolute=False) -> str` and `output.jsonl_line(msg, t0, absolute=False) -> str`.
  - `output.message_to_dict(msg, t0, absolute=False) -> dict`.
  - `filters.Filters(ids, nodes, services, channels, errors_only, time_range)` with `.matches(msg, t0, absolute=False) -> bool`.
  - argparse type functions `filters.int_set`, `filters.csv_set`, `filters.time_range`. Each raises `argparse.ArgumentTypeError`.
- Time basis (DESIGN §8): relative to `t0` (the first Record's timestamp) unless `absolute`. The `--time` filter uses the same basis as the display. Messages without a timestamp show `@<offset>` and never match a `--time` filter.

- [ ] **Step 1: Write the failing tests**

`tests/test_output.py`:
```python
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
```

`tests/test_filters.py`:
```python
import argparse

import pytest

from protocol_analyzer.filters import Filters, csv_set, int_set, time_range
from protocol_analyzer.message import Field, Message
from protocol_analyzer.records import CanFrame


def _msg(name="sdo", channel="can0", start=10.0, can_id=0x585, node=5):
    return Message("canopen", name, channel, start=start, fields=[Field("node", node)],
                   sources=[CanFrame(start, channel, can_id)])


def test_empty_filters_match_everything():
    assert Filters().matches(_msg(), t0=10.0)


def test_each_filter():
    m = _msg()
    assert Filters(ids={0x585}).matches(m, 10.0)
    assert not Filters(ids={0x181}).matches(m, 10.0)
    assert Filters(nodes={5}).matches(m, 10.0)
    assert not Filters(nodes={6}).matches(m, 10.0)
    assert Filters(services={"SDO"}).matches(m, 10.0)
    assert not Filters(services={"emcy"}).matches(m, 10.0)
    assert not Filters(channels={"can1"}).matches(m, 10.0)
    assert not Filters(errors_only=True).matches(m, 10.0)
    m.error("x")
    assert Filters(errors_only=True).matches(m, 10.0)


def test_time_filter_uses_display_basis():
    m = _msg(start=12.0)
    assert Filters(time_range=(1.5, 3.0)).matches(m, t0=10.0)
    assert not Filters(time_range=(1.5, 3.0)).matches(m, t0=10.0, absolute=True)
    assert Filters(time_range=(11.0, None)).matches(m, t0=10.0, absolute=True)
    untimed = Message("u", "f", "rx", offset=3)
    assert not Filters(time_range=(None, 5.0)).matches(untimed, t0=None)


def test_flag_parsers():
    assert int_set("0x181, 385") == {0x181, 385}
    assert csv_set("sdo,emcy") == {"sdo", "emcy"}
    assert time_range("1.5:3") == (1.5, 3.0)
    assert time_range(":3") == (None, 3.0)
    with pytest.raises(argparse.ArgumentTypeError):
        int_set("0x18G")
    with pytest.raises(argparse.ArgumentTypeError):
        time_range("5")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_output.py tests/test_filters.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'protocol_analyzer.output'` (and `.filters`)

- [ ] **Step 3: Write the implementation**

`src/protocol_analyzer/output.py`:
```python
from __future__ import annotations

import json

from .message import Field, Message


def format_time(msg: Message, t0: float | None, absolute: bool = False) -> str:
    if msg.start is None:
        return f"@{msg.offset}" if msg.offset is not None else "-"
    if absolute or t0 is None:
        return f"{msg.start:.6f}"
    return f"{msg.start - t0:.6f}"


def format_value(f: Field) -> str:
    if f.missing:
        return "<missing>"
    if f.children or f.value is None:
        return "{" + format_fields(f.children) + "}"
    v = f.value
    if f.label is not None:
        text = f.label
    elif isinstance(v, (bytes, bytearray)):
        text = v.hex(" ").upper() if v else "(empty)"
    elif isinstance(v, bool):
        text = "true" if v else "false"
    elif isinstance(v, float):
        text = f"{v:g}"
    else:
        text = str(v)
    return f"{text} {f.unit}" if f.unit else text


def format_fields(fields: list[Field]) -> str:
    return " ".join(f"{f.name}={format_value(f)}" for f in fields)


def details(msg: Message) -> str:
    text = msg.summary if msg.summary is not None else format_fields(msg.fields)
    for d in msg.diagnostics:
        text += f"  !{d.level}: {d.text}"
    return text.strip()


def table_line(msg: Message, t0: float | None, absolute: bool = False) -> str:
    time = format_time(msg, t0, absolute)
    return f"{time:>14}  {msg.channel:<6} {msg.protocol:<11} {msg.name:<20} {details(msg)}".rstrip()


def field_to_dict(f: Field) -> dict:
    d: dict = {"name": f.name}
    if f.missing:
        d["missing"] = True
        return d
    if f.value is not None:
        d["value"] = f.value.hex() if isinstance(f.value, (bytes, bytearray)) else f.value
    if f.label is not None:
        d["label"] = f.label
    if f.unit:
        d["unit"] = f.unit
    if f.raw:
        d["raw"] = f.raw.hex()
    if f.children or f.value is None:
        d["children"] = [field_to_dict(c) for c in f.children]
    return d


def message_to_dict(msg: Message, t0: float | None, absolute: bool = False) -> dict:
    if msg.start is None:
        time = None
    elif absolute or t0 is None:
        time = msg.start
    else:
        time = round(msg.start - t0, 9)
    return {
        "time": time,
        "offset": msg.offset,
        "channel": msg.channel,
        "protocol": msg.protocol,
        "name": msg.name,
        "fields": [field_to_dict(f) for f in msg.fields],
        "diagnostics": [{"level": d.level, "text": d.text} for d in msg.diagnostics],
    }


def jsonl_line(msg: Message, t0: float | None, absolute: bool = False) -> str:
    return json.dumps(message_to_dict(msg, t0, absolute), ensure_ascii=False, default=str)
```

`src/protocol_analyzer/filters.py`:
```python
from __future__ import annotations

import argparse
from dataclasses import dataclass, field

from .message import Message
from .records import CanFrame


@dataclass
class Filters:
    ids: set[int] = field(default_factory=set)
    nodes: set[int] = field(default_factory=set)
    services: set[str] = field(default_factory=set)
    channels: set[str] = field(default_factory=set)
    errors_only: bool = False
    time_range: tuple[float | None, float | None] = (None, None)

    def __post_init__(self) -> None:
        self.services = {s.lower() for s in self.services}

    def matches(self, msg: Message, t0: float | None, absolute: bool = False) -> bool:
        if self.channels and msg.channel not in self.channels:
            return False
        if self.services and msg.name.lower() not in self.services:
            return False
        if self.errors_only and not msg.has_errors:
            return False
        if self.ids and not any(isinstance(s, CanFrame) and s.id in self.ids for s in msg.sources):
            return False
        if self.nodes:
            node = msg.get("node")
            if node is None or node.value not in self.nodes:
                return False
        lo, hi = self.time_range
        if lo is not None or hi is not None:
            if msg.start is None:
                return False
            t = msg.start if absolute or t0 is None else msg.start - t0
            if (lo is not None and t < lo) or (hi is not None and t > hi):
                return False
        return True


def int_set(text: str) -> set[int]:
    try:
        return {int(part, 0) for part in text.split(",") if part.strip()}
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"expected comma-separated integers (decimal or 0x-prefixed), got {text!r}") from None


def csv_set(text: str) -> set[str]:
    return {part.strip() for part in text.split(",") if part.strip()}


def time_range(text: str) -> tuple[float | None, float | None]:
    start, sep, end = text.partition(":")
    try:
        if not sep:
            raise ValueError
        return (float(start) if start else None, float(end) if end else None)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected START:END in seconds, got {text!r}") from None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/test_output.py tests/test_filters.py -v`
Expected: 9 passed

- [ ] **Step 5: Commit**

```bash
git add src/protocol_analyzer/output.py src/protocol_analyzer/filters.py tests/test_output.py tests/test_filters.py
git commit -m "feat: add table/JSONL output and message filters

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Session, Analysis, `pa info`, and the CLI

After this task, `pa decode|info|decoders` works end to end on CAN captures with the `can` decoder.

**Files:**
- Create: `src/protocol_analyzer/session.py`, `analysis.py`, `info.py`, `cli.py`, `__main__.py`
- Test: `tests/test_session.py`, `tests/test_cli.py`

**Interfaces:**
- Consumes: `open_capture`, `capture_kind` (Task 2), `DecoderStack`, `build_decoder`, `REGISTRY` (Task 3), `Filters`, `table_line`, `jsonl_line` and the flag parsers (Task 4), `SessionError`, `PaError`.
- Produces:
  - `session.ANY_CHANNEL = "*"`.
  - `session.Binding(decoders: list[str], params: dict)`. For canopen, `params["eds"]` is `dict[int, str]` (node → path).
  - `session.Session(capture: Path, bindings: dict[str, Binding], base_dir: Path)` with `.binding_for(channel) -> Binding|None`. An exact channel match wins over `"*"`.
  - `session.session_from_args(capture, decoder=None, eds=None) -> Session`.
  - `session.load_session(path) -> Session`. Paths are relative to the session file.
  - `analysis.Analysis(session)` with `.messages() -> Iterator[Message]` and `.t0: float|None`. `t0` is set from the first timestamped Record, before any Message is yielded.
  - `info.capture_info(path) -> CaptureInfo` and `info.format_info(info) -> str`.
  - `cli.main(argv: list[str]|None=None) -> int`.

Session YAML format (DESIGN §7):
```yaml
capture: bus.asc                 # relative to this file
channels:
  "1": {decoder: canopen, eds: {5: node5.eds}}
  "2": {decoder: [can]}          # a list is a Decoder stack, bottom first
  "*": {decoder: can}            # any other channel
```
Channels without a binding (and with no `"*"` binding) are skipped.

- [ ] **Step 1: Write the failing tests**

`tests/test_session.py`:
```python
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
```

`tests/test_cli.py`:
```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_session.py tests/test_cli.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'protocol_analyzer.analysis'` (and `.cli`)

- [ ] **Step 3: Write `session.py`**

`src/protocol_analyzer/session.py`:
```python
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .errors import SessionError
from .sources import capture_kind

ANY_CHANNEL = "*"


@dataclass
class Binding:
    decoders: list[str]  # decoder specs, bottom of the stack first
    params: dict = field(default_factory=dict)


@dataclass
class Session:
    capture: Path
    bindings: dict[str, Binding]
    base_dir: Path = field(default_factory=Path.cwd)  # resolves relative Definition / EDS paths

    def binding_for(self, channel: str) -> Binding | None:
        return self.bindings.get(channel) or self.bindings.get(ANY_CHANNEL)


def session_from_args(capture: str | Path, decoder: str | None = None,
                      eds: list[str] | None = None) -> Session:
    capture = Path(capture)
    if decoder is None:
        if capture_kind(capture) == "uart":
            raise SessionError("UART captures need --decoder uart:<definition.yaml>")
        decoder = "can"
    params: dict = {}
    if eds:
        if decoder.partition(":")[0] != "canopen":
            raise SessionError("--eds only applies to --decoder canopen")
        params["eds"] = dict(_parse_eds_flag(text) for text in eds)
    return Session(capture, {ANY_CHANNEL: Binding([decoder], params)})


def _parse_eds_flag(text: str) -> tuple[int, str]:
    node, sep, path = text.partition("=")
    try:
        node_id = int(node, 0)
    except ValueError:
        node_id = -1
    if not sep or not path or not 1 <= node_id <= 127:
        raise SessionError(f"--eds expects NODE=PATH with NODE 1-127, got {text!r}")
    return node_id, path


def load_session(path: str | Path) -> Session:
    p = Path(path)
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SessionError(f"{p}: cannot read session file: {exc.strerror}") from exc
    except yaml.YAMLError as exc:
        raise SessionError(f"{p}: invalid YAML: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("capture"), str):
        raise SessionError(f"{p}: session file needs a 'capture' path")
    channels = doc.get("channels")
    if not isinstance(channels, dict) or not channels:
        raise SessionError(f"{p}: session file needs a non-empty 'channels' mapping")
    bindings = {str(ch): _binding(p, str(ch), spec) for ch, spec in channels.items()}
    return Session(p.parent / doc["capture"], bindings, base_dir=p.parent)


def _binding(path: Path, channel: str, spec: object) -> Binding:
    where = f"{path}: channels.{channel}"
    if not isinstance(spec, dict) or "decoder" not in spec:
        raise SessionError(f"{where}: needs a 'decoder'")
    decoders = [spec["decoder"]] if isinstance(spec["decoder"], str) else spec["decoder"]
    if not isinstance(decoders, list) or not decoders or not all(isinstance(d, str) for d in decoders):
        raise SessionError(f"{where}.decoder: expected a decoder name or a list of them")
    params = {k: v for k, v in spec.items() if k != "decoder"}
    if "eds" in params:
        eds = params["eds"]
        try:
            if not isinstance(eds, dict):
                raise ValueError
            params["eds"] = {int(str(node), 0): str(eds_path) for node, eds_path in eds.items()}
        except ValueError:
            raise SessionError(f"{where}.eds: expected a mapping of node id to EDS path") from None
    return Binding(decoders, params)
```

- [ ] **Step 4: Write `analysis.py` and `info.py`**

`src/protocol_analyzer/analysis.py`:
```python
from __future__ import annotations

from typing import Iterator

from .decoders.base import DecoderStack
from .message import Message
from .registry import build_decoder
from .session import Session
from .sources import open_capture


class Analysis:
    """Runs a Session: reads its Capture and feeds each Channel's Records to its Decoder stack."""

    def __init__(self, session: Session):
        self.session = session
        self.t0: float | None = None
        self._stacks: dict[str, DecoderStack | None] = {}

    def messages(self) -> Iterator[Message]:
        for record in open_capture(self.session.capture):
            if self.t0 is None and record.timestamp is not None:
                self.t0 = record.timestamp
            stack = self._stack(record.channel)
            if stack is not None:
                yield from stack.feed(record)
        for stack in self._stacks.values():
            if stack is not None:
                yield from stack.flush()

    def _stack(self, channel: str) -> DecoderStack | None:
        if channel not in self._stacks:
            binding = self.session.binding_for(channel)
            self._stacks[channel] = None if binding is None else DecoderStack(
                [build_decoder(spec, binding.params, self.session.base_dir) for spec in binding.decoders])
        return self._stacks[channel]
```

`src/protocol_analyzer/info.py`:
```python
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .records import CanFrame
from .sources import open_capture


@dataclass
class CaptureInfo:
    records: int = 0
    first: float | None = None
    last: float | None = None
    channels: Counter = field(default_factory=Counter)  # Records per Channel
    can_ids: Counter = field(default_factory=Counter)  # frames per CAN id, error frames excluded
    error_frames: int = 0
    uart_bytes: Counter = field(default_factory=Counter)  # bytes per UART Channel


def capture_info(path: str | Path) -> CaptureInfo:
    info = CaptureInfo()
    for record in open_capture(path):
        info.records += 1
        info.channels[record.channel] += 1
        if record.timestamp is not None:
            info.first = record.timestamp if info.first is None else min(info.first, record.timestamp)
            info.last = record.timestamp if info.last is None else max(info.last, record.timestamp)
        if isinstance(record, CanFrame):
            if record.is_error:
                info.error_frames += 1
            else:
                info.can_ids[record.id] += 1
        else:
            info.uart_bytes[record.channel] += len(record.data)
    return info


def format_info(info: CaptureInfo) -> str:
    lines = [f"records:  {info.records}"]
    if info.first is not None and info.last is not None:
        lines.append(f"time:     {info.first:.6f} .. {info.last:.6f} ({info.last - info.first:.6f} s)")
    channels = ", ".join(f"{ch} ({n})" for ch, n in sorted(info.channels.items()))
    lines.append(f"channels: {channels or 'none'}")
    if info.can_ids:
        lines.append("CAN ids:")
        lines += [f"  0x{can_id:03X}  {n}" for can_id, n in sorted(info.can_ids.items())]
    if info.error_frames:
        lines.append(f"error frames: {info.error_frames}")
    lines += [f"UART {ch}: {n} bytes" for ch, n in sorted(info.uart_bytes.items())]
    return "\n".join(lines)
```

- [ ] **Step 5: Write `cli.py` and `__main__.py`**

`src/protocol_analyzer/cli.py`:
```python
from __future__ import annotations

import argparse
import io
import os
import sys

from .analysis import Analysis
from .errors import PaError, SessionError
from .filters import Filters, csv_set, int_set, time_range
from .info import capture_info, format_info
from .output import jsonl_line, table_line
from .registry import REGISTRY
from .session import load_session, session_from_args


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pa", description="Decode CAN/CANopen and proprietary UART captures.")
    sub = parser.add_subparsers(dest="command", required=True)

    d = sub.add_parser("decode", help="decode a capture into messages")
    d.add_argument("capture", nargs="?", help="capture file (.log, .asc, .bin, .hex, .txt)")
    d.add_argument("--decoder", help="decoder spec: can, canopen, uart:<definition.yaml>")
    d.add_argument("--eds", action="append", metavar="NODE=PATH",
                   help="EDS/DCF file for one CANopen node (repeatable)")
    d.add_argument("--session", help="session YAML binding channels to decoders")
    d.add_argument("--format", choices=["table", "jsonl"], default="table")
    d.add_argument("--abs", action="store_true", help="show absolute timestamps")
    d.add_argument("--id", type=int_set, default=set(), help="CAN ids, comma-separated (0x181,0x201)")
    d.add_argument("--node", type=int_set, default=set(), help="CANopen node ids, comma-separated")
    d.add_argument("--service", type=csv_set, default=set(),
                   help="message names, comma-separated (sdo,emcy,get_info)")
    d.add_argument("--channel", type=csv_set, default=set(), help="channels, comma-separated")
    d.add_argument("--errors-only", action="store_true", help="only messages with an error diagnostic")
    d.add_argument("--time", type=time_range, default=(None, None), metavar="START:END",
                   help="time window in seconds, same basis as the display")
    d.set_defaults(func=cmd_decode)

    i = sub.add_parser("info", help="summarize a capture")
    i.add_argument("capture")
    i.set_defaults(func=cmd_info)

    ds = sub.add_parser("decoders", help="list built-in decoders")
    ds.set_defaults(func=cmd_decoders)
    return parser


def cmd_decode(args: argparse.Namespace) -> int:
    if args.session:
        if args.decoder or args.eds:
            raise SessionError("--decoder/--eds cannot be combined with --session")
        session = load_session(args.session)
        if args.capture:
            session.capture = session.base_dir / args.capture
    elif not args.capture:
        raise SessionError("decode needs a capture file or --session")
    else:
        session = session_from_args(args.capture, args.decoder, args.eds)
    filters = Filters(ids=args.id, nodes=args.node, services=args.service, channels=args.channel,
                      errors_only=args.errors_only, time_range=args.time)
    fmt = jsonl_line if args.format == "jsonl" else table_line
    analysis = Analysis(session)
    for msg in analysis.messages():
        if filters.matches(msg, analysis.t0, args.abs):
            print(fmt(msg, analysis.t0, args.abs))
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    print(format_info(capture_info(args.capture)))
    return 0


def cmd_decoders(args: argparse.Namespace) -> int:
    for info in REGISTRY.values():
        print(f"{info.usage:<26} {info.description}")
    return 0


def _utf8_stdout() -> None:
    # A cp1252 console or redirect cannot encode units like °C; never crash on output.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError, io.UnsupportedOperation):
        pass


def main(argv: list[str] | None = None) -> int:
    _utf8_stdout()
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except PaError as exc:
        print(f"pa: error: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:  # output piped into e.g. `head`, which exited early
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
```

`src/protocol_analyzer/__main__.py`:
```python
from .cli import main

raise SystemExit(main())
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest -q`
Expected: all tests pass (Tasks 1–5).

- [ ] **Step 7: Smoke-test the installed command**

Run: `.venv/Scripts/pa decode tests/fixtures/basic.asc && .venv/Scripts/pa info tests/fixtures/basic.asc`
Expected: 6 decoded lines, the last ending `181 [8] 01 02 03 04 05 06 07 08  (fd,brs)`, then an info block listing `channels: 1 (5), 2 (1)`.

- [ ] **Step 8: Commit**

```bash
git add src/protocol_analyzer tests/test_session.py tests/test_cli.py
git commit -m "feat: add sessions, analysis runner and pa decode/info/decoders CLI

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: CANopen decoder: COB-ID classification, NMT, SYNC, TIME, EMCY, heartbeat

**Files:**
- Create: `src/protocol_analyzer/canopen/__init__.py` (empty), `canopen/cobid.py`, `canopen/tables.py`, `canopen/decoder.py`
- Modify: `src/protocol_analyzer/registry.py` (add the `canopen` entry)
- Test: `tests/test_canopen.py`

**Interfaces:**
- Consumes: `CanFrame`, `Message`, `Field`, `frame_message` (Task 3), `Item`.
- Produces:
  - `canopen.cobid.classify(can_id: int) -> tuple[str, int|None]`. The service is one of `nmt sync time emcy tpdo1..4 rpdo1..4 sdo_tx sdo_rx heartbeat lss unknown`, paired with the Node ID (None for broadcast services).
  - `canopen.tables`: `NMT_COMMANDS`, `NMT_STATES`, `ERROR_REGISTER_BITS`, `EMCY_CODES`, `SDO_ABORTS`, `emcy_text(code) -> str`, `sdo_abort_text(code) -> str`.
  - `canopen.decoder.CanopenDecoder()` and `canopen.decoder.canopen_message(frame, name, node, fields) -> Message`. Message names are:
    - `nmt`, `sync`, `time`, `emcy`, `heartbeat`, `node_guard_request`
    - `tpdo1`..`rpdo4`, `lss`
    - `<service>_rtr` for any other remote frame
    - SDO names come in Task 7.
  - Every node-addressed Message has a leading `node` Field, which the `--node` filter uses.
  - Extended-id frames, error frames and ids outside the CANopen map fall back to `frame_message()` (protocol `can`), so nothing is dropped.

- [ ] **Step 1: Write the failing tests**

`tests/test_canopen.py`:
```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_canopen.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'protocol_analyzer.canopen'`

- [ ] **Step 3: Write `cobid.py` and `tables.py`**

`src/protocol_analyzer/canopen/__init__.py`: empty file.

`src/protocol_analyzer/canopen/cobid.py`:
```python
from __future__ import annotations

# Function code (COB-ID & 0x780) -> service, for node-addressed COB-IDs (predefined connection set).
_FUNCTIONS = {
    0x080: "emcy", 0x180: "tpdo1", 0x200: "rpdo1", 0x280: "tpdo2", 0x300: "rpdo2",
    0x380: "tpdo3", 0x400: "rpdo3", 0x480: "tpdo4", 0x500: "rpdo4",
    0x580: "sdo_tx", 0x600: "sdo_rx", 0x700: "heartbeat",
}
_BROADCAST = {0x000: "nmt", 0x080: "sync", 0x100: "time", 0x7E4: "lss", 0x7E5: "lss"}


def classify(can_id: int) -> tuple[str, int | None]:
    """Split an 11-bit COB-ID into (service, Node ID)."""
    if can_id in _BROADCAST:
        return _BROADCAST[can_id], None
    node = can_id & 0x07F
    service = _FUNCTIONS.get(can_id & 0x780)
    if can_id > 0x7FF or node == 0 or service is None:
        return "unknown", None
    return service, node
```

`src/protocol_analyzer/canopen/tables.py`:
```python
from __future__ import annotations

NMT_COMMANDS = {0x01: "start", 0x02: "stop", 0x80: "enter_pre_operational",
                0x81: "reset_node", 0x82: "reset_communication"}

NMT_STATES = {0x00: "boot-up", 0x04: "stopped", 0x05: "operational", 0x7F: "pre-operational"}

ERROR_REGISTER_BITS = {0: "generic", 1: "current", 2: "voltage", 3: "temperature",
                       4: "communication", 5: "device_profile", 7: "manufacturer"}

# CiA 301 emergency error codes; lookup falls back from the exact code to its 0xFF00 and 0xF000 family.
EMCY_CODES = {
    0x1000: "Generic error",
    0x2000: "Current", 0x2100: "Current, device input side", 0x2200: "Current inside the device",
    0x2300: "Current, device output side",
    0x3000: "Voltage", 0x3100: "Mains voltage", 0x3200: "Voltage inside the device", 0x3300: "Output voltage",
    0x4000: "Temperature", 0x4100: "Ambient temperature", 0x4200: "Device temperature",
    0x5000: "Device hardware",
    0x6000: "Device software", 0x6100: "Internal software", 0x6200: "User software", 0x6300: "Data set",
    0x7000: "Additional modules",
    0x8000: "Monitoring", 0x8100: "Communication", 0x8110: "CAN overrun (objects lost)",
    0x8120: "CAN in error passive mode", 0x8130: "Life guard error or heartbeat error",
    0x8140: "Recovered from bus off", 0x8150: "CAN-ID collision", 0x8200: "Protocol error",
    0x8210: "PDO not processed due to length error", 0x8220: "PDO length exceeded",
    0x8230: "DAM MPDO not processed, destination object not available",
    0x8240: "Unexpected SYNC data length", 0x8250: "RPDO timeout",
    0x9000: "External error",
    0xF000: "Additional functions",
    0xFF00: "Device specific",
}

SDO_ABORTS = {
    0x05030000: "Toggle bit not alternated",
    0x05040000: "SDO protocol timed out",
    0x05040001: "Client/server command specifier not valid or unknown",
    0x05040002: "Invalid block size",
    0x05040003: "Invalid sequence number",
    0x05040004: "CRC error",
    0x05040005: "Out of memory",
    0x06010000: "Unsupported access to an object",
    0x06010001: "Attempt to read a write only object",
    0x06010002: "Attempt to write a read only object",
    0x06020000: "Object does not exist in the object dictionary",
    0x06040041: "Object cannot be mapped to the PDO",
    0x06040042: "Number and length of mapped objects would exceed PDO length",
    0x06040043: "General parameter incompatibility",
    0x06040047: "General internal incompatibility in the device",
    0x06060000: "Access failed due to a hardware error",
    0x06070010: "Data type does not match, length of service parameter does not match",
    0x06070012: "Data type does not match, length of service parameter too high",
    0x06070013: "Data type does not match, length of service parameter too low",
    0x06090011: "Sub-index does not exist",
    0x06090030: "Invalid value for parameter",
    0x06090031: "Value of parameter written too high",
    0x06090032: "Value of parameter written too low",
    0x06090036: "Maximum value is less than minimum value",
    0x060A0023: "Resource not available: SDO connection",
    0x08000000: "General error",
    0x08000020: "Data cannot be transferred or stored to the application",
    0x08000021: "Data cannot be transferred or stored because of local control",
    0x08000022: "Data cannot be transferred or stored because of the present device state",
    0x08000023: "Object dictionary dynamic generation failed or no object dictionary present",
    0x08000024: "No data available",
}


def emcy_text(code: int) -> str:
    if code == 0:
        return "error reset / no error"
    for mask in (0xFFFF, 0xFF00, 0xF000):
        key = code & mask
        if key and key in EMCY_CODES:
            return EMCY_CODES[key]
    return "unknown error code"


def sdo_abort_text(code: int) -> str:
    return SDO_ABORTS.get(code, "unknown abort code")
```

- [ ] **Step 4: Write `decoder.py`**

`src/protocol_analyzer/canopen/decoder.py`:
```python
from __future__ import annotations

from datetime import datetime, timedelta

from ..decoders.base import Item
from ..decoders.can import frame_message
from ..message import Field, Message
from ..records import CanFrame
from .cobid import classify
from .tables import ERROR_REGISTER_BITS, NMT_COMMANDS, NMT_STATES, emcy_text

_CANOPEN_EPOCH = datetime(1984, 1, 1)


def canopen_message(frame: CanFrame, name: str, node: int | None, fields: list[Field]) -> Message:
    head = [Field("node", node)] if node is not None else []
    return Message("canopen", name, frame.channel, start=frame.timestamp, end=frame.timestamp,
                   fields=head + fields, sources=[frame])


def _raw(data: bytes) -> Field:
    return Field("data", data, raw=data)


class CanopenDecoder:
    def feed(self, item: Item) -> list[Item]:
        if isinstance(item, Message):
            return [item]
        if not isinstance(item, CanFrame):
            return []
        if item.is_error or item.is_extended:
            return [frame_message(item)]
        service, node = classify(item.id)
        if service == "unknown":
            return [frame_message(item)]
        if item.is_remote:
            name = "node_guard_request" if service == "heartbeat" else f"{service}_rtr"
            return [canopen_message(item, name, node, [])]
        return self._decode(service, node, item)

    def flush(self) -> list[Item]:
        return []

    def _decode(self, service: str, node: int | None, frame: CanFrame) -> list[Message]:
        if service == "nmt":
            return [self._nmt(frame)]
        if service == "sync":
            return [self._sync(frame)]
        if service == "time":
            return [self._time(frame)]
        if service == "emcy":
            return [self._emcy(node, frame)]
        if service == "heartbeat":
            return [self._heartbeat(node, frame)]
        if service in ("sdo_tx", "sdo_rx"):
            return [canopen_message(frame, "sdo", node, [_raw(frame.data)])]
        if service == "lss":
            return [canopen_message(frame, "lss", None, [_raw(frame.data)])]
        return [self._pdo(service, node, frame)]

    def _nmt(self, frame: CanFrame) -> Message:
        d = frame.data
        if len(d) < 2:
            m = canopen_message(frame, "nmt", None, [_raw(d)])
            m.error(f"NMT needs 2 bytes, got {len(d)}")
            return m
        cs, target = d[0], d[1]
        m = canopen_message(frame, "nmt", None, [
            Field("command", cs, label=NMT_COMMANDS.get(cs)),
            Field("target", target, label="all" if target == 0 else None),
        ])
        if cs not in NMT_COMMANDS:
            m.warn(f"unknown NMT command 0x{cs:02X}")
        return m

    def _sync(self, frame: CanFrame) -> Message:
        d = frame.data
        m = canopen_message(frame, "sync", None, [Field("counter", d[0])] if d else [])
        if len(d) > 1:
            m.warn(f"SYNC carries at most 1 byte, got {len(d)}")
        return m

    def _time(self, frame: CanFrame) -> Message:
        d = frame.data
        if len(d) < 6:
            m = canopen_message(frame, "time", None, [_raw(d)])
            m.error(f"TIME needs 6 bytes, got {len(d)}")
            return m
        ms = int.from_bytes(d[0:4], "little") & 0x0FFFFFFF
        days = int.from_bytes(d[4:6], "little")
        when = _CANOPEN_EPOCH + timedelta(days=days, milliseconds=ms)
        return canopen_message(frame, "time", None, [Field("time", when.isoformat(timespec="milliseconds"))])

    def _emcy(self, node: int | None, frame: CanFrame) -> Message:
        d = frame.data
        if len(d) < 3:
            m = canopen_message(frame, "emcy", node, [_raw(d)])
            m.error(f"EMCY needs 8 bytes, got {len(d)}")
            return m
        code = int.from_bytes(d[0:2], "little")
        register = d[2]
        bits = [name for bit, name in ERROR_REGISTER_BITS.items() if register >> bit & 1]
        m = canopen_message(frame, "emcy", node, [
            Field("code", code, label=f"0x{code:04X} {emcy_text(code)}"),
            Field("register", register, label=",".join(bits) or "none"),
            Field("manufacturer", d[3:8], raw=d[3:8]),
        ])
        if len(d) != 8:
            m.warn(f"EMCY should be 8 bytes, got {len(d)}")
        return m

    def _heartbeat(self, node: int | None, frame: CanFrame) -> Message:
        d = frame.data
        if len(d) != 1:
            m = canopen_message(frame, "heartbeat", node, [_raw(d)])
            m.error(f"heartbeat needs 1 byte, got {len(d)}")
            return m
        state = d[0] & 0x7F
        fields = [Field("state", state, label=NMT_STATES.get(state))]
        if d[0] & 0x80:
            fields.append(Field("toggle", 1))
        m = canopen_message(frame, "heartbeat", node, fields)
        if state not in NMT_STATES:
            m.warn(f"unknown NMT state 0x{state:02X}")
        return m

    def _pdo(self, service: str, node: int | None, frame: CanFrame) -> Message:
        return canopen_message(frame, service, node, [_raw(frame.data)])
```

- [ ] **Step 5: Register the decoder**

In `src/protocol_analyzer/registry.py`, add this factory below `_can`:
```python
def _canopen(arg: str, params: dict, base_dir: Path) -> Decoder:
    from .canopen.decoder import CanopenDecoder

    return CanopenDecoder()
```
and add this entry to the `REGISTRY` dict literal after `"can"`:
```python
    "canopen": DecoderInfo("canopen", "canopen [--eds NODE=PATH]",
                           "CANopen: NMT, SYNC, TIME, EMCY, heartbeat, SDO, PDO", _canopen),
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest -q`
Expected: all pass

- [ ] **Step 7: Commit**

```bash
git add src/protocol_analyzer/canopen src/protocol_analyzer/registry.py tests/test_canopen.py
git commit -m "feat: add CANopen decoder for NMT, SYNC, TIME, EMCY and heartbeat

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: CANopen SDO (expedited, segmented, abort)

**Files:**
- Create: `src/protocol_analyzer/canopen/sdo.py`
- Modify: `src/protocol_analyzer/canopen/decoder.py` (route SDO frames to the tracker)
- Test: `tests/test_sdo.py`

**Interfaces:**
- Consumes: `canopen_message` is not used here, because SDO Messages carry a `dir` Field right after `node`. Also consumes `sdo_abort_text`, `CanFrame`, `Message`, `Field`.
- Produces:
  - `canopen.sdo.SdoTracker()` with `decode(frame: CanFrame, node: int, request: bool) -> list[Message]`. `request` is True for COB-ID 0x600+node (client→server).
  - Per-frame Messages are named `sdo`, with Fields `node`, `dir` (`request`/`response`), `command`, and then per command `index`, `subindex`, `data`, `size`, `toggle`, `last`, `abort_code`.
  - A completed segmented transfer additionally yields a Message named `sdo_transfer` with Fields `node`, `kind` (`download`/`upload`), `index`, `subindex`, `size` and `data`. Its sources are every frame of the transfer.
  - Two hook methods that Task 8 overrides: `SdoTracker._object(node, index, subindex) -> list[Field]` and `SdoTracker._value(node, index, subindex, data: bytes) -> Field`.
- Transfer state is keyed by Node ID. An abort clears only that node's transfer. A new initiate while a transfer is active warns "previous SDO transfer on node N abandoned". Block transfer (ccs/scs 5–6) is only flagged, since it is v2 work.

SDO byte-0 layouts (CiA 301) used below:
- initiate: `ccs/scs(3) | x | n(2) | e | s`
- segment: `ccs/scs(3) | t | n(3) | c`
- index is bytes 1–2 little-endian, subindex is byte 3.

- [ ] **Step 1: Write the failing tests**

`tests/test_sdo.py`:
```python
from pathlib import Path

from protocol_analyzer.canopen.decoder import CanopenDecoder
from protocol_analyzer.cli import main
from protocol_analyzer.records import CanFrame

FIX = Path(__file__).parent / "fixtures"


def sdo(dec, node, request, hex_data, t=0.0):
    cob = (0x600 if request else 0x580) + node
    return dec.feed(CanFrame(t, "can0", cob, bytes.fromhex(hex_data), dlc=8))


def vals(msg):
    return {f.name: f.value for f in msg.fields}


def warnings(msg):
    return [d.text for d in msg.diagnostics]


def test_expedited_download():
    [m] = sdo(CanopenDecoder(), 5, True, "2318100101020304")
    assert m.name == "sdo"
    assert vals(m) == {"node": 5, "dir": "request", "command": "initiate_download",
                       "index": 0x1018, "subindex": 1, "data": b"\x01\x02\x03\x04"}
    [m2] = sdo(CanopenDecoder(), 5, True, "2B40600006000000")  # n=2: only 2 data bytes
    assert vals(m2)["data"] == b"\x06\x00"


def test_expedited_upload():
    d = CanopenDecoder()
    [req] = sdo(d, 5, True, "4018100100000000")
    assert vals(req)["command"] == "initiate_upload"
    [resp] = sdo(d, 5, False, "4318100178563412")
    assert vals(resp) == {"node": 5, "dir": "response", "command": "initiate_upload",
                          "index": 0x1018, "subindex": 1, "data": b"\x78\x56\x34\x12"}


def _segmented_upload(d, node, text=b"ABCDEFGHIJ"):
    """Upload 0x1008 (device name) of 10 bytes as a 7-byte and a 3-byte segment."""
    out = []
    out += sdo(d, node, True, "4008100000000000")
    out += sdo(d, node, False, "410810000A000000")  # size indicated: 10
    out += sdo(d, node, True, "6000000000000000")
    out += sdo(d, node, False, "00" + text[:7].hex())  # t=0, n=0, c=0
    out += sdo(d, node, True, "7000000000000000")
    out += sdo(d, node, False, "19" + text[7:].hex() + "00000000")  # t=1, n=4, c=1
    return out


def test_segmented_upload_reassembles_into_a_transfer_message():
    out = _segmented_upload(CanopenDecoder(), 5)
    assert [m.name for m in out] == ["sdo"] * 6 + ["sdo_transfer"]
    t = out[-1]
    assert vals(t) == {"node": 5, "kind": "upload", "index": 0x1008, "subindex": 0,
                       "size": 10, "data": b"ABCDEFGHIJ"}
    assert len(t.sources) == 3 and not t.diagnostics


def test_segmented_download():
    d = CanopenDecoder()
    sdo(d, 5, True, "2100200003000000")
    [ack] = sdo(d, 5, False, "6000200000000000")
    assert vals(ack)["command"] == "initiate_download"
    seg, transfer = sdo(d, 5, True, "09AABBCC00000000")
    assert vals(seg)["last"] is True
    assert vals(transfer)["data"] == b"\xaa\xbb\xcc" and vals(transfer)["kind"] == "download"


def test_toggle_error_is_reported():
    d = CanopenDecoder()
    sdo(d, 5, True, "4008100000000000")
    sdo(d, 5, False, "410810000A000000")
    sdo(d, 5, False, "00" + b"ABCDEFG".hex())
    [bad] = sdo(d, 5, False, "00" + b"HIJ".hex() + "00000000")  # toggle should be 1
    assert bad.has_errors and "toggle" in warnings(bad)[0]


def test_interleaved_nodes_keep_separate_state():
    d = CanopenDecoder()
    a, b = [], []
    frames_a = [(True, "4008100000000000"), (False, "410810000A000000"),
                (False, "00" + b"AAAAAAA".hex()), (False, "19" + b"AAA".hex() + "00000000")]
    frames_b = [(True, "4008100000000000"), (False, "4108100004000000"),
                (False, "07" + b"BBBB".hex() + "000000")]  # t=0, n=3, c=1
    for (ra, ha), (rb, hb) in zip(frames_a, frames_b + [(None, None)]):
        a += sdo(d, 5, ra, ha)
        if rb is not None:
            b += sdo(d, 6, rb, hb)
    assert vals(a[-1])["data"] == b"AAAAAAAAAA"
    assert vals(b[-1])["data"] == b"BBBB"


def test_abort_clears_only_that_nodes_transfer():
    d = CanopenDecoder()
    sdo(d, 5, True, "4008100000000000")
    sdo(d, 5, False, "410810000A000000")
    sdo(d, 6, True, "4008100000000000")
    sdo(d, 6, False, "4108100004000000")
    [abort] = sdo(d, 5, True, "8008100000000405")
    assert abort.get("abort_code").label == "0x05040000 SDO protocol timed out"
    assert abort.diagnostics[0].level == "warning"
    [orphan] = sdo(d, 5, False, "00" + b"ABCDEFG".hex())
    assert "without an active transfer" in warnings(orphan)[0]
    seg, transfer = sdo(d, 6, False, "07" + b"BBBB".hex() + "000000")
    assert vals(transfer)["data"] == b"BBBB"


def test_protocol_irregularities():
    d = CanopenDecoder()
    [short] = d.feed(CanFrame(0.0, "can0", 0x605, b"\x40\x00", dlc=2))
    assert short.has_errors and "8 bytes" in short.diagnostics[0].text
    sdo(d, 5, True, "4008100000000000")
    sdo(d, 5, False, "410810000A000000")
    [restart] = sdo(d, 5, False, "410810000A000000")
    assert "abandoned" in warnings(restart)[0]
    [block] = sdo(d, 5, True, "C000000000000000")
    assert "block transfer" in warnings(block)[0]
    [invalid] = sdo(d, 5, True, "E000000000000000")
    assert invalid.has_errors


def test_announced_size_mismatch_warns():
    d = CanopenDecoder()
    sdo(d, 5, True, "4008100000000000")
    sdo(d, 5, False, "410810000A000000")  # announces 10
    _, transfer = sdo(d, 5, False, "07" + b"ABCD".hex() + "000000")  # delivers 4, last
    assert "announced 10 bytes, transferred 4" in warnings(transfer)


def test_cli_shows_sdo_from_fixture(capsys):
    assert main(["decode", str(FIX / "basic.log"), "--decoder", "canopen", "--service", "sdo"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2
    assert lines[1].endswith("data=01 02 03 04")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_sdo.py -v`
Expected: FAIL with `ModuleNotFoundError`-free assertion failures (e.g. `assert {...} == {...}` diffs showing only `node` and `data`), because SDO frames are still decoded as raw.

- [ ] **Step 3: Write `sdo.py`**

`src/protocol_analyzer/canopen/sdo.py`:
```python
from __future__ import annotations

from dataclasses import dataclass, field

from ..message import Field, Message
from ..records import CanFrame
from .tables import sdo_abort_text


@dataclass
class _Transfer:
    kind: str  # "download" (client writes) | "upload" (client reads)
    index: int
    subindex: int
    size: int | None
    toggle: int = 0
    data: bytearray = field(default_factory=bytearray)
    frames: list[CanFrame] = field(default_factory=list)


def _mux(d: bytes) -> tuple[int, int]:
    return int.from_bytes(d[1:3], "little"), d[3]


class SdoTracker:
    """Decodes SDO frames per node and reassembles segmented transfers. Block transfer is v2."""

    def __init__(self) -> None:
        self._transfers: dict[int, _Transfer] = {}

    def decode(self, frame: CanFrame, node: int, request: bool) -> list[Message]:
        msg = Message("canopen", "sdo", frame.channel, start=frame.timestamp, end=frame.timestamp,
                      sources=[frame],
                      fields=[Field("node", node), Field("dir", "request" if request else "response")])
        d = frame.data
        if len(d) != 8:
            msg.fields.append(Field("data", d, raw=d))
            msg.error(f"SDO frame must be 8 bytes, got {len(d)}")
            return [msg]
        cs = d[0] >> 5
        return self._request(cs, node, frame, msg) if request else self._response(cs, node, frame, msg)

    # --- client -> server (0x600 + node) ---
    def _request(self, cs: int, node: int, frame: CanFrame, msg: Message) -> list[Message]:
        d = frame.data
        if cs == 1:
            return self._initiate(msg, node, frame, "download")
        if cs == 2:
            msg.fields.append(Field("command", "initiate_upload"))
            msg.fields += self._object(node, *_mux(d))
            return [msg]
        if cs == 0:
            return self._segment(msg, node, frame, "download")
        if cs == 3:
            msg.fields += [Field("command", "upload_segment"), Field("toggle", (d[0] >> 4) & 1)]
            return [msg]
        if cs == 4:
            return self._abort(msg, node, frame)
        return self._other(msg, cs)

    # --- server -> client (0x580 + node) ---
    def _response(self, cs: int, node: int, frame: CanFrame, msg: Message) -> list[Message]:
        d = frame.data
        if cs == 3:
            msg.fields.append(Field("command", "initiate_download"))
            msg.fields += self._object(node, *_mux(d))
            return [msg]
        if cs == 1:
            msg.fields += [Field("command", "download_segment"), Field("toggle", (d[0] >> 4) & 1)]
            return [msg]
        if cs == 2:
            return self._initiate(msg, node, frame, "upload")
        if cs == 0:
            return self._segment(msg, node, frame, "upload")
        if cs == 4:
            return self._abort(msg, node, frame)
        return self._other(msg, cs)

    def _initiate(self, msg: Message, node: int, frame: CanFrame, kind: str) -> list[Message]:
        """Initiate download request or initiate upload response: same byte layout."""
        d = frame.data
        index, subindex = _mux(d)
        n, e, s = (d[0] >> 2) & 3, (d[0] >> 1) & 1, d[0] & 1
        msg.fields.append(Field("command", f"initiate_{kind}"))
        msg.fields += self._object(node, index, subindex)
        if self._transfers.pop(node, None) is not None:
            msg.warn(f"previous SDO transfer on node {node} abandoned")
        if e:
            msg.fields.append(self._value(node, index, subindex, d[4:8 - n] if s else d[4:8]))
        else:
            size = int.from_bytes(d[4:8], "little") if s else None
            if size is not None:
                msg.fields.append(Field("size", size))
            self._transfers[node] = _Transfer(kind, index, subindex, size, frames=[frame])
        return [msg]

    def _segment(self, msg: Message, node: int, frame: CanFrame, kind: str) -> list[Message]:
        d = frame.data
        t, n, c = (d[0] >> 4) & 1, (d[0] >> 1) & 7, d[0] & 1
        segment = d[1:8 - n]
        msg.fields += [Field("command", f"{kind}_segment"), Field("toggle", t),
                       Field("data", segment, raw=segment)]
        if c:
            msg.fields.append(Field("last", True))
        transfer = self._transfers.get(node)
        if transfer is None or transfer.kind != kind:
            msg.warn(f"SDO {kind} segment without an active transfer")
            return [msg]
        if t != transfer.toggle:
            msg.error(f"toggle bit {t}, expected {transfer.toggle}")
        transfer.toggle = t ^ 1
        transfer.data += segment
        transfer.frames.append(frame)
        if not c:
            return [msg]
        del self._transfers[node]
        return [msg, self._completed(node, transfer, frame)]

    def _completed(self, node: int, transfer: _Transfer, last: CanFrame) -> Message:
        data = bytes(transfer.data)
        m = Message("canopen", "sdo_transfer", last.channel, start=transfer.frames[0].timestamp,
                    end=last.timestamp, sources=list(transfer.frames),
                    fields=[Field("node", node), Field("kind", transfer.kind)]
                    + self._object(node, transfer.index, transfer.subindex)
                    + [Field("size", len(data)), self._value(node, transfer.index, transfer.subindex, data)])
        if transfer.size is not None and transfer.size != len(data):
            m.warn(f"announced {transfer.size} bytes, transferred {len(data)}")
        return m

    def _abort(self, msg: Message, node: int, frame: CanFrame) -> list[Message]:
        d = frame.data
        code = int.from_bytes(d[4:8], "little")
        msg.fields.append(Field("command", "abort"))
        msg.fields += self._object(node, *_mux(d))
        msg.fields.append(Field("abort_code", code, label=f"0x{code:08X} {sdo_abort_text(code)}"))
        msg.warn(f"SDO abort: {sdo_abort_text(code)}")
        self._transfers.pop(node, None)
        return [msg]

    def _other(self, msg: Message, cs: int) -> list[Message]:
        data = msg.sources[0].data
        msg.fields += [Field("command", cs), Field("data", data, raw=data)]
        if cs in (5, 6):
            msg.warn("SDO block transfer is not decoded yet")
        else:
            msg.error(f"invalid SDO command specifier {cs}")
        return [msg]

    # Extension points: Task 8 names objects and decodes values from an EDS.
    def _object(self, node: int, index: int, subindex: int) -> list[Field]:
        return [Field("index", index, label=f"0x{index:04X}"), Field("subindex", subindex)]

    def _value(self, node: int, index: int, subindex: int, data: bytes) -> Field:
        return Field("data", data, raw=data)
```

Note: `index` is displayed through its label (`0x1018`), while its value stays the int.

- [ ] **Step 4: Route SDO frames to the tracker**

In `src/protocol_analyzer/canopen/decoder.py`:
- add `from .sdo import SdoTracker` to the imports
- add a constructor to `CanopenDecoder`:
```python
    def __init__(self) -> None:
        self._sdo = SdoTracker()
```
- replace the SDO branch in `_decode`
```python
        if service in ("sdo_tx", "sdo_rx"):
            return [canopen_message(frame, "sdo", node, [_raw(frame.data)])]
```
with
```python
        if service in ("sdo_tx", "sdo_rx"):
            return self._sdo.decode(frame, node, request=service == "sdo_rx")
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest -q`
Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add src/protocol_analyzer/canopen tests/test_sdo.py
git commit -m "feat: decode CANopen SDO expedited/segmented transfers and aborts

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: EDS/DCF object dictionary: names and typed SDO values

**Files:**
- Create: `src/protocol_analyzer/canopen/eds.py`, `tests/fixtures/node5.eds`
- Modify: `src/protocol_analyzer/canopen/sdo.py` (constructor, `_object`, `_value`), `canopen/decoder.py` (constructor), `registry.py` (`_canopen` loads EDS files)
- Test: `tests/test_eds.py`

**Interfaces:**
- Consumes: `SdoTracker` (Task 7), `EdsError`, the `params["eds"]: dict[int, str]` Binding param (Task 5).
- Produces:
  - `canopen.eds.OdEntry(name: str, data_type: int|None, default: str|None, value: str|None)`.
  - `canopen.eds.ObjectDictionary` with:
    - `entry(index, subindex) -> OdEntry|None`
    - `name(index, subindex) -> str|None`, formatted `"<object>.<sub>"` for record/array members
    - `value(index, subindex) -> int|None`, where a DCF `ParameterValue` wins over `DefaultValue` and `$NODEID` is substituted
    - `decode(index, subindex, data: bytes) -> object|None`
  - `canopen.eds.load_eds(path, node_id: int) -> ObjectDictionary`. Raises `EdsError`.
  - `canopen.eds.decode_value(data_type: int|None, raw: bytes) -> object|None`.
  - `canopen.eds.SIGNED_TYPES`, `REAL32`, `REAL64`, `BOOLEAN` constants (Task 9 uses them).
  - `SdoTracker(ods: dict[int, ObjectDictionary] | None = None)` and `CanopenDecoder(ods: dict[int, ObjectDictionary] | None = None)`.
  - SDO Messages gain an `object` Field after `subindex` when the node's OD names the object. `data` holds the typed value when the OD knows the type, otherwise the raw bytes.

- [ ] **Step 1: Create the EDS fixture**

`tests/fixtures/node5.eds`:
```ini
[FileInfo]
FileName=node5.eds

[DeviceInfo]
ProductName=Test drive

[1008]
ParameterName=Manufacturer device name
ObjectType=0x7
DataType=0x0009
AccessType=const
DefaultValue=drive

[1018]
ParameterName=Identity object
ObjectType=0x9
SubNumber=2

[1018sub0]
ParameterName=Highest sub-index supported
ObjectType=0x7
DataType=0x0005
AccessType=ro
DefaultValue=1

[1018sub1]
ParameterName=Vendor-ID
ObjectType=0x7
DataType=0x0007
AccessType=ro
DefaultValue=0x12345678

[1600]
ParameterName=RPDO1 mapping parameter
ObjectType=0x9
SubNumber=2

[1600sub0]
ParameterName=Number of mapped objects
DataType=0x0005
DefaultValue=1

[1600sub1]
ParameterName=Mapped object 1
DataType=0x0007
DefaultValue=0x60400010

[1A00]
ParameterName=TPDO1 mapping parameter
ObjectType=0x9
SubNumber=4

[1A00sub0]
ParameterName=Number of mapped objects
DataType=0x0005
DefaultValue=3

[1A00sub1]
ParameterName=Mapped object 1
DataType=0x0007
DefaultValue=0x60410010

[1A00sub2]
ParameterName=Mapped object 2
DataType=0x0007
DefaultValue=0x606C0020

[1A00sub3]
ParameterName=Mapped object 3
DataType=0x0007
DefaultValue=0x20010108

[1A01]
ParameterName=TPDO2 mapping parameter
ObjectType=0x9
SubNumber=1

[1A01sub0]
ParameterName=Number of mapped objects
DataType=0x0005
DefaultValue=0

[2001]
ParameterName=Drive flags
ObjectType=0x9
SubNumber=2

[2001sub0]
ParameterName=Highest sub-index supported
DataType=0x0005
DefaultValue=1

[2001sub1]
ParameterName=Fault bits
DataType=0x0005
DefaultValue=0

[6040]
ParameterName=Controlword
ObjectType=0x7
DataType=0x0006
DefaultValue=0

[6041]
ParameterName=Statusword
ObjectType=0x7
DataType=0x0006

[606C]
ParameterName=Velocity actual value
ObjectType=0x7
DataType=0x0004
```

- [ ] **Step 2: Write the failing tests**

`tests/test_eds.py`:
```python
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_eds.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'protocol_analyzer.canopen.eds'`

- [ ] **Step 4: Write `eds.py`**

`src/protocol_analyzer/canopen/eds.py`:
```python
from __future__ import annotations

import configparser
import re
import struct
from dataclasses import dataclass
from pathlib import Path

from ..errors import EdsError

BOOLEAN, REAL32, VISIBLE_STRING, REAL64 = 0x0001, 0x0008, 0x0009, 0x0011
# CiA 301 integer data types -> (byte size, signed)
_INTEGERS = {
    0x0002: (1, True), 0x0003: (2, True), 0x0004: (4, True), 0x0010: (3, True), 0x0015: (8, True),
    0x0005: (1, False), 0x0006: (2, False), 0x0007: (4, False), 0x0016: (3, False), 0x001B: (8, False),
}
SIGNED_TYPES = {dt for dt, (_, signed) in _INTEGERS.items() if signed}

_TOP = re.compile(r"^([0-9A-F]{4})$", re.IGNORECASE)
_SUB = re.compile(r"^([0-9A-F]{4})SUB([0-9A-F]{1,2})$", re.IGNORECASE)


@dataclass(frozen=True)
class OdEntry:
    name: str
    data_type: int | None
    default: str | None
    value: str | None  # DCF ParameterValue


def _to_int(text: str) -> int:
    try:
        return int(text, 0)
    except ValueError:
        return int(text, 10)  # EDS files write decimals with leading zeros ("010")


def parse_int(text: str | None, node_id: int) -> int | None:
    if text is None or not text.strip():
        return None
    expr = re.sub(r"\$NODEID", str(node_id), text.strip(), flags=re.IGNORECASE)
    try:
        return sum(_to_int(part.strip()) for part in expr.split("+"))
    except ValueError:
        return None


def decode_value(data_type: int | None, raw: bytes) -> object | None:
    if data_type == BOOLEAN:
        return bool(raw[0]) if raw else None
    if data_type in _INTEGERS:
        size, signed = _INTEGERS[data_type]
        return int.from_bytes(raw[:size], "little", signed=signed) if len(raw) >= size else None
    if data_type == REAL32 and len(raw) >= 4:
        return struct.unpack("<f", raw[:4])[0]
    if data_type == REAL64 and len(raw) >= 8:
        return struct.unpack("<d", raw[:8])[0]
    if data_type == VISIBLE_STRING:
        return raw.decode("ascii", "replace").rstrip("\x00")
    return None


class ObjectDictionary:
    def __init__(self, node_id: int, objects: dict[int, OdEntry], subs: dict[tuple[int, int], OdEntry]):
        self.node_id = node_id
        self._objects = objects
        self._subs = subs
        self._with_subs = {index for index, _ in subs}

    def entry(self, index: int, subindex: int) -> OdEntry | None:
        if (index, subindex) in self._subs:
            return self._subs[(index, subindex)]
        if subindex == 0 and index not in self._with_subs:
            return self._objects.get(index)
        return None

    def name(self, index: int, subindex: int) -> str | None:
        entry = self.entry(index, subindex)
        if entry is None:
            return None
        parent = self._objects.get(index)
        if (index, subindex) in self._subs and parent is not None:
            return f"{parent.name}.{entry.name}"
        return entry.name

    def value(self, index: int, subindex: int) -> int | None:
        entry = self.entry(index, subindex)
        if entry is None:
            return None
        return parse_int(entry.value if entry.value is not None else entry.default, self.node_id)

    def decode(self, index: int, subindex: int, data: bytes) -> object | None:
        entry = self.entry(index, subindex)
        return decode_value(entry.data_type, data) if entry is not None else None


def load_eds(path: str | Path, node_id: int) -> ObjectDictionary:
    p = Path(path)
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    try:
        parser.read_string(p.read_text(encoding="utf-8", errors="replace"), source=str(p))
    except OSError as exc:
        raise EdsError(f"{p}: cannot read EDS: {exc.strerror}") from exc
    except configparser.Error as exc:
        raise EdsError(f"{p}: not a valid EDS/DCF file: {exc}") from exc
    objects: dict[int, OdEntry] = {}
    subs: dict[tuple[int, int], OdEntry] = {}
    for section in parser.sections():
        sec = parser[section]
        dt = parse_int(sec.get("datatype"), node_id)
        entry = OdEntry(sec.get("parametername", section), dt, sec.get("defaultvalue"), sec.get("parametervalue"))
        if m := _TOP.match(section):
            objects[int(m.group(1), 16)] = entry
        elif m := _SUB.match(section):
            subs[(int(m.group(1), 16), int(m.group(2), 16))] = entry
    if not objects and not subs:
        raise EdsError(f"{p}: no object dictionary entries found")
    return ObjectDictionary(node_id, objects, subs)
```

- [ ] **Step 5: Use the OD in SDO decoding**

In `src/protocol_analyzer/canopen/sdo.py`:
- add `from .eds import ObjectDictionary` to the imports
- replace the constructor
```python
    def __init__(self) -> None:
        self._transfers: dict[int, _Transfer] = {}
```
with
```python
    def __init__(self, ods: dict[int, ObjectDictionary] | None = None) -> None:
        self._ods = ods or {}
        self._transfers: dict[int, _Transfer] = {}
```
- replace the two extension-point methods at the bottom with:
```python
    def _object(self, node: int, index: int, subindex: int) -> list[Field]:
        fields = [Field("index", index, label=f"0x{index:04X}"), Field("subindex", subindex)]
        od = self._ods.get(node)
        name = od.name(index, subindex) if od is not None else None
        if name:
            fields.append(Field("object", name))
        return fields

    def _value(self, node: int, index: int, subindex: int, data: bytes) -> Field:
        od = self._ods.get(node)
        value = od.decode(index, subindex, data) if od is not None else None
        return Field("data", data if value is None else value, raw=data)
```

In `src/protocol_analyzer/canopen/decoder.py`:
- add `from .eds import ObjectDictionary` to the imports
- replace the constructor with
```python
    def __init__(self, ods: dict[int, ObjectDictionary] | None = None) -> None:
        self._ods = ods or {}
        self._sdo = SdoTracker(self._ods)
```

In `src/protocol_analyzer/registry.py`, replace `_canopen` with
```python
def _canopen(arg: str, params: dict, base_dir: Path) -> Decoder:
    from .canopen.decoder import CanopenDecoder
    from .canopen.eds import load_eds

    ods = {node: load_eds(base_dir / path, node) for node, path in params.get("eds", {}).items()}
    return CanopenDecoder(ods)
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest -q`
Expected: all pass. The Task 7 SDO tests are unchanged because they use no EDS.

- [ ] **Step 7: Commit**

```bash
git add src/protocol_analyzer/canopen src/protocol_analyzer/registry.py tests/fixtures/node5.eds tests/test_eds.py
git commit -m "feat: load EDS/DCF object dictionaries for SDO names and typed values

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: PDO decoding from EDS mappings

**Files:**
- Create: `src/protocol_analyzer/canopen/pdo.py`
- Modify: `src/protocol_analyzer/canopen/decoder.py` (`_pdo`)
- Test: `tests/test_pdo.py`

**Interfaces:**
- Consumes: `ObjectDictionary`, `SIGNED_TYPES`, `BOOLEAN`, `REAL32`, `REAL64` (Task 8), `canopen_message`, `_raw` (Task 6).
- Produces:
  - `canopen.pdo.MapEntry(index: int, subindex: int, bits: int)`.
  - `canopen.pdo.pdo_mapping(od, service: str) -> list[MapEntry] | None`. `service` is one of `tpdo1`..`rpdo4`. It returns None when the OD doesn't describe that mapping, and `[]` when the mapping is explicitly empty.
  - `canopen.pdo.decode_pdo(od, mapping, data: bytes) -> tuple[list[Field], int]`, returning the fields and the total mapped bits. Fields are named by the OD, falling back to `0xIIIIsubS`.
- PDO objects are packed little-endian, bit after bit, starting at bit 0 (CiA 301). A mapped object the data doesn't reach becomes a `missing` Field with an error Diagnostic. Unmapped trailing bytes produce a warning.
- **Known v1 limitation:** COB-IDs follow the predefined connection set (0x180+node, …). PDOs moved to other COB-IDs via 0x1400/0x1800 are not followed. Document this in the `CanopenDecoder` docstring.

- [ ] **Step 1: Write the failing tests**

`tests/test_pdo.py`:
```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_pdo.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'protocol_analyzer.canopen.pdo'`

- [ ] **Step 3: Write `pdo.py`**

`src/protocol_analyzer/canopen/pdo.py`:
```python
from __future__ import annotations

import struct
from dataclasses import dataclass

from ..message import Field
from .eds import BOOLEAN, REAL32, REAL64, SIGNED_TYPES, ObjectDictionary

_MAPPING_BASE = {"tpdo": 0x1A00, "rpdo": 0x1600}


@dataclass(frozen=True)
class MapEntry:
    index: int
    subindex: int
    bits: int


def pdo_mapping(od: ObjectDictionary, service: str) -> list[MapEntry] | None:
    """The mapping of 'tpdo1'..'rpdo4' from the OD; None if the OD does not describe it."""
    base = _MAPPING_BASE[service[:4]] + int(service[4]) - 1
    count = od.value(base, 0)
    if count is None:
        return None
    entries = []
    for sub in range(1, count + 1):
        packed = od.value(base, sub)
        if packed is None:
            return None
        entries.append(MapEntry(packed >> 16, (packed >> 8) & 0xFF, packed & 0xFF))
    return entries


def _typed(data_type: int | None, raw: int, bits: int) -> object:
    if data_type == BOOLEAN:
        return bool(raw)
    if data_type in SIGNED_TYPES and raw >> (bits - 1) & 1:
        return raw - (1 << bits)
    if data_type == REAL32 and bits == 32:
        return struct.unpack("<f", raw.to_bytes(4, "little"))[0]
    if data_type == REAL64 and bits == 64:
        return struct.unpack("<d", raw.to_bytes(8, "little"))[0]
    return raw


def decode_pdo(od: ObjectDictionary, mapping: list[MapEntry], data: bytes) -> tuple[list[Field], int]:
    whole = int.from_bytes(data, "little")
    available = len(data) * 8
    fields: list[Field] = []
    pos = 0
    for e in mapping:
        name = od.name(e.index, e.subindex) or f"0x{e.index:04X}sub{e.subindex}"
        if pos + e.bits > available:
            fields.append(Field(name, missing=True))
        else:
            raw_int = (whole >> pos) & ((1 << e.bits) - 1)
            aligned = pos % 8 == 0 and e.bits % 8 == 0
            raw = data[pos // 8:(pos + e.bits) // 8] if aligned else b""
            entry = od.entry(e.index, e.subindex)
            fields.append(Field(name, _typed(entry.data_type if entry else None, raw_int, e.bits), raw=raw))
        pos += e.bits
    return fields, pos
```

- [ ] **Step 4: Decode PDOs in the decoder**

In `src/protocol_analyzer/canopen/decoder.py`:
- add `from .pdo import decode_pdo, pdo_mapping` to the imports
- add a class docstring to `CanopenDecoder`:
```python
    """CANopen on top of CAN frames (predefined connection set).

    PDOs are decoded when the node's EDS/DCF describes their mapping. PDOs moved to
    non-default COB-IDs via 0x1400/0x1800 are not followed (v1 limitation).
    """
```
- replace `_pdo` with:
```python
    def _pdo(self, service: str, node: int | None, frame: CanFrame) -> Message:
        od = self._ods.get(node) if node is not None else None
        mapping = pdo_mapping(od, service) if od is not None else None
        if od is None or mapping is None:
            return canopen_message(frame, service, node, [_raw(frame.data)])
        fields, bits = decode_pdo(od, mapping, frame.data)
        m = canopen_message(frame, service, node, fields)
        have = len(frame.data) * 8
        if not mapping:
            m.warn(f"{service} has no mapped objects in the EDS")
        elif bits > have:
            m.error(f"PDO has {len(frame.data)} bytes, mapping needs {(bits + 7) // 8}")
        elif have - bits >= 8:
            m.warn(f"{(have - bits) // 8} bytes beyond the mapping")
        return m
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest -q`
Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add src/protocol_analyzer/canopen tests/test_pdo.py
git commit -m "feat: decode CANopen PDOs from EDS mappings

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Parameterized CRC engine

**Files:**
- Create: `src/protocol_analyzer/uart/__init__.py` (empty), `src/protocol_analyzer/uart/crc.py`
- Test: `tests/test_crc.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `uart.crc.CrcParams(width, poly, init, refin, refout, xorout)` (frozen). The width is 8, 16 or 32.
  - `uart.crc.PRESETS: dict[str, CrcParams]` with `crc8`, `crc16_modbus`, `crc16_ccitt_false`, `crc16_xmodem`, `crc16_kermit`, `crc16_arc` and `crc32`.
  - `uart.crc.crc(data: bytes, params: CrcParams) -> int`.
- These are catalogue-style parameters (DESIGN §6.4). Every preset is verified against its standard check value over `b"123456789"`.

- [ ] **Step 1: Write the failing tests**

`tests/test_crc.py`:
```python
import pytest

from protocol_analyzer.uart.crc import PRESETS, CrcParams, crc

CHECK = b"123456789"


@pytest.mark.parametrize("name, check", [
    ("crc8", 0xF4),
    ("crc16_modbus", 0x4B37),
    ("crc16_ccitt_false", 0x29B1),
    ("crc16_xmodem", 0x31C3),
    ("crc16_kermit", 0x2189),
    ("crc16_arc", 0xBB3D),
    ("crc32", 0xCBF43926),
])
def test_presets_match_catalogue_check_values(name, check):
    assert crc(CHECK, PRESETS[name]) == check


def test_empty_input_returns_init_after_output_transform():
    assert crc(b"", PRESETS["crc16_modbus"]) == 0xFFFF
    assert crc(b"", PRESETS["crc32"]) == 0


def test_custom_parameters():
    ibm_3740 = CrcParams(width=16, poly=0x1021, init=0xFFFF, refin=False, refout=False, xorout=0)
    assert crc(CHECK, ibm_3740) == 0x29B1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_crc.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'protocol_analyzer.uart'`

- [ ] **Step 3: Write the implementation**

`src/protocol_analyzer/uart/__init__.py`: empty file.

`src/protocol_analyzer/uart/crc.py`:
```python
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CrcParams:
    """A CRC in the Rocksoft/catalogue parameter model."""

    width: int  # 8, 16 or 32
    poly: int
    init: int
    refin: bool
    refout: bool
    xorout: int


PRESETS: dict[str, CrcParams] = {
    "crc8": CrcParams(8, 0x07, 0x00, False, False, 0x00),
    "crc16_modbus": CrcParams(16, 0x8005, 0xFFFF, True, True, 0x0000),
    "crc16_ccitt_false": CrcParams(16, 0x1021, 0xFFFF, False, False, 0x0000),
    "crc16_xmodem": CrcParams(16, 0x1021, 0x0000, False, False, 0x0000),
    "crc16_kermit": CrcParams(16, 0x1021, 0x0000, True, True, 0x0000),
    "crc16_arc": CrcParams(16, 0x8005, 0x0000, True, True, 0x0000),
    "crc32": CrcParams(32, 0x04C11DB7, 0xFFFFFFFF, True, True, 0xFFFFFFFF),
}


def _reflect(value: int, width: int) -> int:
    out = 0
    for _ in range(width):
        out = (out << 1) | (value & 1)
        value >>= 1
    return out


def crc(data: bytes, params: CrcParams) -> int:
    top = 1 << (params.width - 1)
    mask = (1 << params.width) - 1
    reg = params.init
    for byte in data:
        if params.refin:
            byte = _reflect(byte, 8)
        reg ^= byte << (params.width - 8)
        for _ in range(8):
            reg = ((reg << 1) ^ params.poly) & mask if reg & top else (reg << 1) & mask
    if params.refout:
        reg = _reflect(reg, params.width)
    return reg ^ params.xorout
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/test_crc.py -v`
Expected: 9 passed

- [ ] **Step 5: Commit**

```bash
git add src/protocol_analyzer/uart tests/test_crc.py
git commit -m "feat: add parameterized CRC engine with catalogue presets

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 11: UART Definition loader and validation

**Files:**
- Create: `src/protocol_analyzer/uart/definition.py`
- Modify: `defs/example_uart.yaml` (add `show:`)
- Test: `tests/test_definition.py`

**Interfaces:**
- Consumes: `CrcParams`, `PRESETS` (Task 10), `DefinitionError`.
- Produces:
  - `uart.definition.NumType(kind: "u"|"s"|"f", size: int, fmt: str)` with `.is_int`, `.unpack(raw) -> int|float` and `.pack(value) -> bytes`. Also `numeric_type(name) -> NumType|None`. Endianness defaults to little (`le`).
  - `uart.definition.FieldSpec` (dataclass). Common attributes:
    - `name`, `type`, `num`, `scale`, `offset`, `unit`
    - `enum: dict[int,str]|None`
    - `bits: dict[str, tuple[int,int]]|None`
    - `size: int|str|None`, `count: int|str|None`, `encoding`
    - `hook: Callable[[bytes], tuple[object, int]]|None`

    Frame-only attributes:
    - `role`, `value`, `of`, `max`, `dispatch`, `algo`
    - `crc: CrcParams | Callable[[bytes], int] | None`
    - `covers: tuple[str,str]|None`
  - `uart.definition.Variant(when: dict[str,int], fields: list[FieldSpec])` and `Command(cmd_id, name, variants)`.
  - `uart.definition.Definition` with:
    - loaded attributes `path`, `protocol`, `description`, `versions`, `types`, `frame`, `commands`, `show: list[str]`, `gap_ms`
    - derived attributes `sync`, `length`, `payload`, `crc_field`, `prefix: list[FieldSpec]`, `suffix: list[FieldSpec]`, `prefix_size`, `suffix_size`, `sync_bytes`
    - `select(cmd_id, header: dict[str,int]) -> tuple[Command|None, Variant|None]`
  - `uart.definition.load_definition(path) -> Definition`. Raises `DefinitionError("<path>: <where>: <problem>")`.
- Definition rules (DESIGN §6.1–6.5, plus two additions agreed here):
  - `show:` is an optional list of frame field names whose values lead the table summary.
  - A CRC field takes `hook: file.py:function` instead of `algo:`. The function receives the covered bytes and returns an int.
  - A payload field takes `hook: file.py:function` instead of `type:`. The function receives the remaining data and returns `(value, bytes_consumed)`.
  - Hook paths are relative to the Definition file.
  - `when:` values may be enum names of that frame field. A variant without `when:` must be last.
  - `size: rest` and `count: eos` are only allowed on the last field of a list.
  - `versions:` requires a frame field named `version`.

- [ ] **Step 1: Add `show` to the example Definition**

In `defs/example_uart.yaml`, insert after the `versions: [1]` line:
```yaml
show: [src_module, dst_module]   # frame fields that lead each table row
```

- [ ] **Step 2: Write the failing tests**

`tests/test_definition.py`:
```python
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_definition.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'protocol_analyzer.uart.definition'`

- [ ] **Step 4: Write the model and numeric types**

Create `src/protocol_analyzer/uart/definition.py` with this first half:
```python
from __future__ import annotations

import codecs
import importlib.util
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, NoReturn

import yaml

from ..errors import DefinitionError
from .crc import PRESETS, CrcParams

_NUMERIC = re.compile(r"^(?:(?P<int>[us])(?P<isize>[1248])|f(?P<fsize>[48]))(?P<endian>le|be)?$")
_STRUCT_CODES = {("u", 1): "B", ("u", 2): "H", ("u", 4): "I", ("u", 8): "Q",
                 ("s", 1): "b", ("s", 2): "h", ("s", 4): "i", ("s", 8): "q",
                 ("f", 4): "f", ("f", 8): "d"}
BYTES_TYPES = {"bytes", "str", "strz"}
ROLES = {"sync", "length", "payload", "crc"}


@dataclass(frozen=True)
class NumType:
    kind: str  # "u" | "s" | "f"
    size: int
    fmt: str  # struct format, e.g. "<H"

    @property
    def is_int(self) -> bool:
        return self.kind != "f"

    def unpack(self, raw: bytes) -> int | float:
        return struct.unpack(self.fmt, raw)[0]

    def pack(self, value: int | float) -> bytes:
        return struct.pack(self.fmt, value)


def numeric_type(name: object) -> NumType | None:
    m = _NUMERIC.match(name) if isinstance(name, str) else None
    if m is None:
        return None
    kind = m["int"] or "f"
    size = int(m["isize"] or m["fsize"])
    endian = ">" if m["endian"] == "be" else "<"  # little-endian unless stated
    return NumType(kind, size, endian + _STRUCT_CODES[(kind, size)])


@dataclass
class FieldSpec:
    name: str
    type: str | None = None
    num: NumType | None = None
    scale: float | None = None
    offset: float | None = None
    unit: str | None = None
    enum: dict[int, str] | None = None
    bits: dict[str, tuple[int, int]] | None = None
    size: int | str | None = None  # N, an earlier integer field, or "rest"
    count: int | str | None = None  # N, an earlier integer field, or "eos"
    encoding: str = "ascii"
    hook: Callable[[bytes], tuple[Any, int]] | None = None
    # frame fields only
    role: str | None = None
    value: int | None = None
    of: str | None = None
    max: int | None = None
    dispatch: str | None = None
    algo: str | None = None
    crc: CrcParams | Callable[[bytes], int] | None = None
    covers: tuple[str, str] | None = None


@dataclass
class Variant:
    when: dict[str, int]
    fields: list[FieldSpec]


@dataclass
class Command:
    cmd_id: int
    name: str
    variants: list[Variant]


@dataclass
class Definition:
    path: Path
    protocol: str
    description: str
    versions: list[int] | None
    types: dict[str, list[FieldSpec]]
    frame: list[FieldSpec]
    commands: dict[int, Command]
    show: list[str]
    gap_ms: float | None

    def __post_init__(self) -> None:
        roles = {f.role: f for f in self.frame if f.role}
        self.sync: FieldSpec = roles["sync"]
        self.length: FieldSpec = roles["length"]
        self.payload: FieldSpec = roles["payload"]
        self.crc_field: FieldSpec | None = roles.get("crc")
        i = self.frame.index(self.payload)
        self.prefix = self.frame[:i]
        self.suffix = self.frame[i + 1:]
        self.prefix_size = sum(f.num.size for f in self.prefix)
        self.suffix_size = sum(f.num.size for f in self.suffix)
        self.sync_bytes = self.sync.num.pack(self.sync.value)

    def select(self, cmd_id: int, header: dict[str, int]) -> tuple[Command | None, Variant | None]:
        command = self.commands.get(cmd_id)
        if command is None:
            return None, None
        for variant in command.variants:
            if all(header.get(k) == v for k, v in variant.when.items()):
                return command, variant
        return command, None
```

- [ ] **Step 5: Write the loader**

Append to `src/protocol_analyzer/uart/definition.py`:
```python
_TOP_KEYS = {"protocol", "description", "versions", "show", "gap_ms", "enums", "types", "crc", "frame", "commands"}
_FIELD_KEYS = {"name", "type", "hook", "scale", "offset", "unit", "enum", "bits", "size", "count", "encoding"}
_DISPLAY_KEYS = {"scale", "offset", "unit", "enum", "bits"}
_ROLE_KEYS = {"sync": {"value"}, "length": {"of", "max"}, "crc": {"algo", "hook", "covers"}, None: set()}
_FRAME_KEYS = {"name", "type", "role", "value", "of", "max", "dispatch", "algo", "hook", "covers"} | _DISPLAY_KEYS


def load_definition(path: str | Path) -> Definition:
    p = Path(path)
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise DefinitionError(f"{p}: cannot read definition: {exc.strerror}") from exc
    except yaml.YAMLError as exc:
        raise DefinitionError(f"{p}: invalid YAML: {exc}") from exc
    return _Loader(p).load(doc)


def _is_int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_number(v: object) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


class _Loader:
    def __init__(self, path: Path):
        self.path = path
        self.enums: dict[str, dict[int, str]] = {}
        self.crcs: dict[str, CrcParams] = dict(PRESETS)
        self.type_names: set[str] = set()

    def fail(self, where: str, problem: str) -> NoReturn:
        raise DefinitionError(f"{self.path}: {where}: {problem}")

    def load(self, doc: object) -> Definition:
        if not isinstance(doc, dict):
            self.fail("top level", "expected a mapping")
        self._keys(doc, _TOP_KEYS, "top level")
        protocol = doc.get("protocol")
        if not isinstance(protocol, str) or not protocol:
            self.fail("protocol", "required, a non-empty string")
        versions = doc.get("versions")
        if versions is not None and not (isinstance(versions, list) and versions and all(map(_is_int, versions))):
            self.fail("versions", "expected a non-empty list of integers")
        self.enums = {name: self._enum_map(m, f"enums.{name}")
                      for name, m in self._mapping(doc.get("enums", {}), "enums").items()}
        for name, params in self._mapping(doc.get("crc", {}), "crc").items():
            self.crcs[name] = self._crc_params(params, f"crc.{name}")
        raw_types = self._mapping(doc.get("types", {}), "types")
        self.type_names = set(raw_types)
        types = {name: self._fields(spec, f"types.{name}") for name, spec in raw_types.items()}
        frame = self._frame(doc.get("frame"))
        names = [f.name for f in frame]
        commands = self._commands(doc.get("commands", {}), frame)
        show = doc.get("show", [])
        if not isinstance(show, list) or any(s not in names for s in show):
            self.fail("show", "expected a list of frame field names")
        gap = doc.get("gap_ms")
        if gap is not None and not (_is_number(gap) and gap > 0):
            self.fail("gap_ms", "expected a positive number of milliseconds")
        if versions is not None and "version" not in names:
            self.fail("versions", "needs a frame field named 'version'")
        return Definition(self.path, protocol, str(doc.get("description", "")), versions, types, frame,
                          commands, show, gap)

    # --- generic helpers ---
    def _keys(self, d: dict, allowed: set[str], where: str) -> None:
        extra = set(map(str, d)) - allowed
        if extra:
            self.fail(where, f"unknown key(s) {', '.join(sorted(extra))}")

    def _mapping(self, v: object, where: str) -> dict:
        if not isinstance(v, dict):
            self.fail(where, "expected a mapping")
        return v

    def _enum_map(self, m: object, where: str) -> dict[int, str]:
        m = self._mapping(m, where)
        if not all(_is_int(k) and isinstance(v, str) for k, v in m.items()):
            self.fail(where, "expected integer keys and string names")
        return dict(m)

    def _crc_params(self, v: object, where: str) -> CrcParams:
        v = self._mapping(v, where)
        need = {"width", "poly", "init", "refin", "refout", "xorout"}
        if set(v) != need:
            self.fail(where, f"expected exactly the keys {', '.join(sorted(need))}")
        if v["width"] not in (8, 16, 32):
            self.fail(where, "width must be 8, 16 or 32")
        if not all(_is_int(v[k]) for k in ("poly", "init", "xorout")) or \
                not all(isinstance(v[k], bool) for k in ("refin", "refout")):
            self.fail(where, "poly/init/xorout must be integers and refin/refout booleans")
        return CrcParams(**v)

    def _hook(self, text: object, where: str) -> Callable:
        if not isinstance(text, str) or ":" not in text:
            self.fail(where, "hook must be 'file.py:function'")
        file, _, func = text.rpartition(":")
        hook_path = self.path.parent / file
        if not hook_path.is_file():
            self.fail(where, f"hook file {hook_path} not found")
        spec = importlib.util.spec_from_file_location(f"pa_hook_{hook_path.stem}", hook_path)
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:  # user code: report any failure as a Definition problem
            self.fail(where, f"hook file {hook_path.name} failed to load: {exc}")
        fn = getattr(module, func, None)
        if not callable(fn):
            self.fail(where, f"{hook_path.name} has no function {func!r}")
        return fn

    def _ref(self, v: object, ints: set[str], keyword: str, where: str) -> int | str:
        if (_is_int(v) and v >= 0) or v == keyword or (isinstance(v, str) and v in ints):
            return v
        self.fail(where, f"expected a number, '{keyword}', or the name of an earlier integer field")

    def _bits(self, v: object, width: int, where: str) -> dict[str, tuple[int, int]]:
        out = {}
        for name, spec in self._mapping(v, where).items():
            m = re.fullmatch(r"(\d+)(?:-(\d+))?", str(spec))
            lo, hi = (int(m[1]), int(m[2] or m[1])) if m else (-1, -1)
            if not 0 <= lo <= hi < width:
                self.fail(where, f"{name}: expected a bit or 'lo-hi' range within {width} bits")
            out[str(name)] = (lo, hi)
        return out

    def _display(self, f: FieldSpec, raw: dict, where: str) -> None:
        """scale / offset / unit / enum / bits, shared by frame and payload fields."""
        present = _DISPLAY_KEYS & set(raw)
        if present and f.num is None:
            self.fail(where, f"{', '.join(sorted(present))} only apply to numeric types")
        for key in ("scale", "offset"):
            if key in raw:
                if not _is_number(raw[key]):
                    self.fail(where, f"{key} must be a number")
                setattr(f, key, raw[key])
        if "unit" in raw:
            f.unit = str(raw["unit"])
        if "enum" in raw:
            if not f.num.is_int:
                self.fail(where, "enum needs an integer type")
            ref = raw["enum"]
            if isinstance(ref, str):
                if ref not in self.enums:
                    self.fail(where, f"unknown enum {ref!r}")
                f.enum = self.enums[ref]
            else:
                f.enum = self._enum_map(ref, f"{where}.enum")
        if "bits" in raw:
            if not f.num.is_int:
                self.fail(where, "bits needs an integer type")
            f.bits = self._bits(raw["bits"], f.num.size * 8, f"{where}.bits")

    # --- payload fields ---
    def _fields(self, specs: object, where: str) -> list[FieldSpec]:
        if not isinstance(specs, list):
            self.fail(where, "expected a list of fields")
        out: list[FieldSpec] = []
        ints: set[str] = set()  # earlier integer fields, usable by size/count
        for i, raw in enumerate(specs):
            w = f"{where}[{i}]"
            if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
                self.fail(w, "expected a mapping with a 'name'")
            w = f"{w} ({raw['name']})"
            self._keys(raw, _FIELD_KEYS, w)
            f = self._field(raw, w, ints)
            if (f.size == "rest" or f.count == "eos") and i != len(specs) - 1:
                self.fail(w, "a field with size: rest or count: eos must be the last field")
            if f.num is not None and f.num.is_int and f.count is None:
                ints.add(f.name)
            out.append(f)
        if len({f.name for f in out}) != len(out):
            self.fail(where, "duplicate field names")
        return out

    def _field(self, raw: dict, where: str, ints: set[str]) -> FieldSpec:
        f = FieldSpec(name=raw["name"])
        if ("type" in raw) == ("hook" in raw):
            self.fail(where, "needs exactly one of 'type' or 'hook'")
        if "hook" in raw:
            if set(raw) - {"name", "hook"}:
                self.fail(where, "a hook field takes only name and hook")
            f.hook = self._hook(raw["hook"], f"{where}.hook")
            return f
        f.type = raw["type"]
        f.num = numeric_type(f.type)
        if f.num is None and f.type not in BYTES_TYPES and f.type not in self.type_names:
            self.fail(where, f"unknown type {f.type!r}")
        self._display(f, raw, where)
        if f.type in ("bytes", "str"):
            if "size" not in raw:
                self.fail(where, f"{f.type} needs a size (a number, an earlier field, or rest)")
            f.size = self._ref(raw["size"], ints, "rest", f"{where}.size")
        elif "size" in raw:
            self.fail(where, "size only applies to bytes and str")
        if "encoding" in raw:
            if f.type not in ("str", "strz"):
                self.fail(where, "encoding only applies to str and strz")
            try:
                codecs.lookup(raw["encoding"])
            except (LookupError, TypeError):
                self.fail(where, f"unknown encoding {raw['encoding']!r}")
            f.encoding = raw["encoding"]
        if "count" in raw:
            f.count = self._ref(raw["count"], ints, "eos", f"{where}.count")
        return f

    # --- frame ---
    def _frame(self, specs: object) -> list[FieldSpec]:
        if not isinstance(specs, list) or not specs:
            self.fail("frame", "required, a non-empty list of fields")
        frame = []
        for i, raw in enumerate(specs):
            w = f"frame[{i}]"
            if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
                self.fail(w, "expected a mapping with a 'name'")
            w = f"{w} ({raw['name']})"
            self._keys(raw, _FRAME_KEYS, w)
            frame.append(self._frame_field(raw, w))
        if len({f.name for f in frame}) != len(frame):
            self.fail("frame", "duplicate field names")
        by_role: dict[str, FieldSpec] = {}
        for f in frame:
            if f.role in by_role:
                self.fail("frame", f"more than one field with role: {f.role}")
            if f.role:
                by_role[f.role] = f
        for role in ("sync", "length", "payload"):
            if role not in by_role:
                self.fail("frame", f"needs a field with role: {role}")
        if frame[0].role != "sync":
            self.fail("frame[0]", "the first frame field must have role: sync")
        pos = {f.name: i for i, f in enumerate(frame)}
        length, payload = by_role["length"], by_role["payload"]
        if length.of != payload.name:
            self.fail(f"frame ({length.name})", f"of: must name the payload field '{payload.name}'")
        if pos[length.name] > pos[payload.name]:
            self.fail(f"frame ({length.name})", "the length field must come before the payload")
        if payload.dispatch not in pos or pos[payload.dispatch] > pos[payload.name]:
            self.fail(f"frame ({payload.name})", "dispatch: must name a frame field before the payload")
        crc = by_role.get("crc")
        if crc is not None:
            first, last = crc.covers
            if first not in pos or last not in pos or pos[first] > pos[last]:
                self.fail(f"frame ({crc.name})", "covers: expected [first, last] frame field names in frame order")
            if pos[crc.name] <= pos[last]:
                self.fail(f"frame ({crc.name})", "the crc field must come after the fields it covers")
        return frame

    def _frame_field(self, raw: dict, where: str) -> FieldSpec:
        role = raw.get("role")
        if role is not None and role not in ROLES:
            self.fail(where, f"unknown role {role!r} (expected one of {', '.join(sorted(ROLES))})")
        f = FieldSpec(name=raw["name"], role=role)
        if role == "payload":
            if set(raw) - {"name", "role", "dispatch"}:
                self.fail(where, "the payload field takes only name, role and dispatch")
            if not isinstance(raw.get("dispatch"), str):
                self.fail(where, "the payload field needs dispatch: <frame field>")
            f.dispatch = raw["dispatch"]
            return f
        f.type = raw.get("type")
        f.num = numeric_type(f.type)
        if f.num is None or not f.num.is_int:
            self.fail(where, "frame fields other than the payload need an integer type (u1, u2le, ...)")
        for key in ("value", "of", "max", "dispatch", "algo", "hook", "covers"):
            if key in raw and key not in _ROLE_KEYS[role]:
                self.fail(where, f"{key} does not apply to role {role or 'none'}")
        if role is not None:
            for key in _DISPLAY_KEYS & set(raw):
                self.fail(where, f"{key} does not apply to a field with role {role}")
        else:
            self._display(f, raw, where)
        if role == "sync":
            value = raw.get("value")
            if not _is_int(value):
                self.fail(where, "the sync field needs an integer value")
            if not 0 <= value < 1 << (8 * f.num.size):
                self.fail(where, f"value 0x{value:X} does not fit in {f.type}")
            f.value = value
        elif role == "length":
            if not isinstance(raw.get("of"), str):
                self.fail(where, "the length field needs of: <payload field>")
            f.of = raw["of"]
            if "max" in raw:
                if not (_is_int(raw["max"]) and raw["max"] > 0):
                    self.fail(where, "max must be a positive integer")
                f.max = raw["max"]
        elif role == "crc":
            self._crc_field(f, raw, where)
        return f

    def _crc_field(self, f: FieldSpec, raw: dict, where: str) -> None:
        if ("algo" in raw) == ("hook" in raw):
            self.fail(where, "the crc field needs exactly one of algo or hook")
        if "algo" in raw:
            params = self.crcs.get(raw["algo"])
            if params is None:
                known = ", ".join(sorted(self.crcs))
                self.fail(where, f"unknown crc algorithm {raw['algo']!r} (known: {known})")
            if params.width != f.num.size * 8:
                self.fail(where, f"{raw['algo']} is {params.width} bits but {f.type} holds {f.num.size * 8}")
            f.algo, f.crc = raw["algo"], params
        else:
            f.algo, f.crc = f"hook {raw['hook']}", self._hook(raw["hook"], f"{where}.hook")
        covers = raw.get("covers")
        if not (isinstance(covers, list) and len(covers) == 2 and all(isinstance(c, str) for c in covers)):
            self.fail(where, "covers: expected [first, last] frame field names in frame order")
        f.covers = (covers[0], covers[1])

    # --- commands ---
    def _commands(self, raw: object, frame: list[FieldSpec]) -> dict[int, Command]:
        raw = self._mapping(raw, "commands")
        header = {f.name: f for f in frame if f.role != "payload"}
        out = {}
        for cmd_id, spec in raw.items():
            w = f"commands[0x{cmd_id:02X}]" if _is_int(cmd_id) else f"commands[{cmd_id!r}]"
            if not _is_int(cmd_id):
                self.fail(w, "command ids must be integers")
            if not isinstance(spec, dict) or not isinstance(spec.get("name"), str):
                self.fail(w, "expected a mapping with a 'name'")
            self._keys(spec, {"name", "fields", "variants"}, w)
            if ("fields" in spec) == ("variants" in spec):
                self.fail(w, "needs exactly one of 'fields' or 'variants'")
            if "fields" in spec:
                variants = [Variant({}, self._fields(spec["fields"], f"{w}.fields"))]
            else:
                variants = self._variants(spec["variants"], header, w)
            out[cmd_id] = Command(cmd_id, spec["name"], variants)
        return out

    def _variants(self, raw: object, header: dict[str, FieldSpec], where: str) -> list[Variant]:
        if not isinstance(raw, list) or not raw:
            self.fail(f"{where}.variants", "expected a non-empty list")
        out = []
        for j, v in enumerate(raw):
            w = f"{where}.variants[{j}]"
            if not isinstance(v, dict):
                self.fail(w, "expected a mapping")
            self._keys(v, {"when", "fields"}, w)
            when = self._when(v.get("when", {}), header, f"{w}.when")
            if not when and j != len(raw) - 1:
                self.fail(w, "a variant without 'when' matches everything and must be last")
            out.append(Variant(when, self._fields(v.get("fields", []), f"{w}.fields")))
        return out

    def _when(self, raw: object, header: dict[str, FieldSpec], where: str) -> dict[str, int]:
        out = {}
        for name, value in self._mapping(raw, where).items():
            f = header.get(name)
            if f is None:
                self.fail(where, f"{name!r} is not a frame field")
            if isinstance(value, str):
                by_label = {label: k for k, label in (f.enum or {}).items()}
                if value not in by_label:
                    self.fail(where, f"{value!r} is not a name in {name}'s enum")
                value = by_label[value]
            elif not _is_int(value):
                self.fail(where, f"{name}: expected an integer or an enum name")
            out[name] = value
        return out
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/test_definition.py -v`
Expected: all pass (4 + 26 parametrized + 2).

- [ ] **Step 7: Commit**

```bash
git add src/protocol_analyzer/uart/definition.py defs/example_uart.yaml tests/test_definition.py
git commit -m "feat: load and validate UART Definitions

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 12: Payload field decoder

**Files:**
- Create: `src/protocol_analyzer/uart/payload.py`
- Test: `tests/test_payload.py`

**Interfaces:**
- Consumes: `FieldSpec`, `numeric_type`, `load_definition` (Task 11), `Field`.
- Produces:
  - `uart.payload.number_field(spec: FieldSpec, name: str, raw: bytes) -> Field`. It applies enum label, bits children, scale/offset and unit. Task 13 reuses it for header fields.
  - `uart.payload.decode_fields(specs, data: bytes, types: dict[str, list[FieldSpec]]) -> tuple[list[Field], int, str|None]`, returning the fields, the bytes consumed and a problem (None when fine). After a problem (data ran out, missing string terminator, a failing hook), the rest of the fields come back with `missing=True`.
- Field shapes:
  - Arrays: a group Field whose children are named `[0]`, `[1]`, …
  - Structs: a group Field with the struct's fields as children.
  - Bitfields: the integer Field keeps its value and gains one child per bit range. A single bit is a `bool`; a range is an `int`.
  - Scaling: `value = raw * scale + offset`, and `raw` keeps the bytes. An `int` stays an `int` when only `offset` is given.
  - `str` of fixed size is stripped of trailing NULs. `strz` consumes its terminator.
  - `size`/`count` referring to a field use that field's **raw** integer, not its scaled value.

- [ ] **Step 1: Write the failing tests**

`tests/test_payload.py`:
```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_payload.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'protocol_analyzer.uart.payload'`

- [ ] **Step 3: Write the implementation**

`src/protocol_analyzer/uart/payload.py`:
```python
from __future__ import annotations

from ..message import Field
from .definition import FieldSpec

Types = dict[str, list[FieldSpec]]


def number_field(spec: FieldSpec, name: str, raw: bytes) -> Field:
    value = spec.num.unpack(raw)
    f = Field(name, value, raw=raw, unit=spec.unit)
    if spec.bits:
        f.children = [Field(bit, bool(value >> lo & 1) if lo == hi else value >> lo & ((1 << (hi - lo + 1)) - 1))
                      for bit, (lo, hi) in spec.bits.items()]
    if spec.enum is not None:
        f.label = spec.enum.get(value)
    if spec.scale is not None or spec.offset is not None:
        f.value = value * (1 if spec.scale is None else spec.scale) + (spec.offset or 0)
    return f


def decode_fields(specs: list[FieldSpec], data: bytes, types: Types) -> tuple[list[Field], int, str | None]:
    """Decode a field list from the start of `data`: (fields, bytes consumed, problem or None).

    After a problem (data ran out, no terminator, a hook failed) the remaining fields come back missing.
    """
    fields: list[Field] = []
    ints: dict[str, int] = {}  # raw values of earlier integer fields, for size/count references
    pos = 0
    for i, spec in enumerate(specs):
        if spec.count is None:
            f, pos, problem = _one(spec, spec.name, data, pos, types, ints)
            if problem is None and spec.num is not None and spec.num.is_int:
                ints[spec.name] = spec.num.unpack(f.raw)
        else:
            f, pos, problem = _array(spec, data, pos, types, ints)
        fields.append(f)
        if problem is not None:
            fields += [Field(s.name, missing=True) for s in specs[i + 1:]]
            return fields, pos, problem
    return fields, pos, None


def _array(spec: FieldSpec, data: bytes, start: int, types: Types,
           ints: dict[str, int]) -> tuple[Field, int, str | None]:
    if spec.count == "eos":
        n = None
    elif isinstance(spec.count, int):
        n = spec.count
    else:
        n = ints[spec.count]
    items: list[Field] = []
    pos = start
    while (pos < len(data)) if n is None else (len(items) < n):
        item, pos, problem = _one(spec, f"[{len(items)}]", data, pos, types, ints)
        items.append(item)
        if problem is not None:
            return Field(spec.name, None, raw=data[start:pos], children=items), pos, problem
    return Field(spec.name, None, raw=data[start:pos], children=items), pos, None


def _ran_out(spec: FieldSpec, data: bytes) -> str:
    return f"layout needs more than the {len(data)} data bytes (at '{spec.name}')"


def _one(spec: FieldSpec, name: str, data: bytes, pos: int, types: Types,
         ints: dict[str, int]) -> tuple[Field, int, str | None]:
    if spec.hook is not None:
        try:
            value, used = spec.hook(data[pos:])
        except Exception as exc:  # user code: report it on the Message instead of aborting the run
            return Field(name, missing=True), pos, f"hook for field '{spec.name}' failed: {exc}"
        return Field(name, value, raw=data[pos:pos + used]), pos + used, None
    if spec.num is not None:
        end = pos + spec.num.size
        if end > len(data):
            return Field(name, missing=True), pos, _ran_out(spec, data)
        return number_field(spec, name, data[pos:end]), end, None
    if spec.type == "strz":
        end = data.find(b"\x00", pos)
        if end < 0:
            return Field(name, missing=True), pos, f"no zero terminator for '{spec.name}'"
        return Field(name, data[pos:end].decode(spec.encoding, "replace"), raw=data[pos:end + 1]), end + 1, None
    if spec.type in ("bytes", "str"):
        if spec.size == "rest":
            size = len(data) - pos
        else:
            size = spec.size if isinstance(spec.size, int) else ints[spec.size]
        end = pos + size
        if end > len(data):
            return Field(name, missing=True), pos, _ran_out(spec, data)
        raw = data[pos:end]
        value = raw if spec.type == "bytes" else raw.decode(spec.encoding, "replace").rstrip("\x00")
        return Field(name, value, raw=raw), end, None
    children, used, problem = decode_fields(types[spec.type], data[pos:], types)
    return Field(name, None, raw=data[pos:pos + used], children=children), pos + used, problem
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/test_payload.py -v`
Expected: 8 passed

- [ ] **Step 5: Commit**

```bash
git add src/protocol_analyzer/uart/payload.py tests/test_payload.py
git commit -m "feat: decode UART payload fields from Definition layouts

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 13: UART framer and decoder, registration, docs

After this task, `pa decode capture.hex --decoder uart:defs/example_uart.yaml` works end to end. This task completes v1.

**Files:**
- Create: `src/protocol_analyzer/uart/decoder.py`, `tests/uart_helpers.py`
- Modify: `src/protocol_analyzer/registry.py` (add `uart`), `DESIGN.md`, `CLAUDE.md`
- Test: `tests/test_uart_decoder.py`

**Interfaces:**
- Consumes: `Definition`, `load_definition` (Task 11), `decode_fields`, `number_field` (Task 12), `crc`, `CrcParams` (Task 10), `format_fields` (Task 4), `UartChunk`, `CaptureError`, `SessionError`.
- Produces:
  - `uart.decoder.UartDecoder(definition)`, one per Channel. The Analysis builds one stack per Channel.
  - Message names:
    - the Command name
    - `cmd_0xNN` for an unknown command
    - `bad_frame` for a CRC failure
    - `truncated` for an incomplete frame at the end of the capture or at an idle gap
    - `unframed` for bytes outside any frame
  - Fields: every frame field in order. The payload Field is a group of the decoded layout, or raw bytes when there is no layout. `_trailing` is appended for leftover bytes.
  - `summary` is `format_fields(<show fields> + <payload children or raw payload>)`.
  - `sources` are the UartChunks the frame spans. `offset` is the stream offset of the sync byte.
  - `registry` gets a `uart` entry, used as `uart:<definition.yaml>` and resolved against the Session `base_dir`.
- Framing (DESIGN §6.3):
  1. Scan for the sync bytes.
  2. Read the fixed prefix. A length above `max` is a false sync: skip 1 byte.
  3. Wait for payload + suffix, then verify the CRC.
  4. A bad CRC gives a `bad_frame` Message, then scanning resumes 1 byte past its sync.
  5. Bytes already shown in a failed frame are **not** reported again as `unframed`.
  6. At flush time or an idle gap, incomplete candidates become `truncated` and scanning continues past them. Complete frames hidden behind a false sync are still recovered.
- `gap_ms` uses the timestamp of each chunk's first byte (hex captures carry one timestamp per line). A Definition with `gap_ms` fed an untimed capture raises `CaptureError`.

- [ ] **Step 1: Write the test helper**

`tests/uart_helpers.py`:
```python
from protocol_analyzer.records import UartChunk
from protocol_analyzer.uart.crc import PRESETS, crc


def make_frame(cmd, data=b"", src=0x01, dst=0x10, version=1, setting=0, src_trans=0, dst_trans=0,
               bad_crc=False):
    """A frame in the defs/example_uart.yaml layout, with a valid CRC-16/MODBUS unless bad_crc."""
    body = bytes([version, setting, src, dst, src_trans, dst_trans, cmd]) + len(data).to_bytes(2, "little") + data
    value = crc(body, PRESETS["crc16_modbus"]) ^ (0xFFFF if bad_crc else 0)
    return b"\xaa\x55" + body + value.to_bytes(2, "little")


def chunks(*parts, times=None, channel="rx"):
    """UartChunks for consecutive byte strings, with running offsets."""
    out, offset = [], 0
    for i, part in enumerate(parts):
        out.append(UartChunk(None if times is None else times[i], channel, offset, part))
        offset += len(part)
    return out
```

- [ ] **Step 2: Write the failing tests**

`tests/test_uart_decoder.py`:
```python
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/test_uart_decoder.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'protocol_analyzer.uart.decoder'`

- [ ] **Step 4: Write `uart/decoder.py`**

`src/protocol_analyzer/uart/decoder.py`:
```python
from __future__ import annotations

import bisect

from ..decoders.base import Item
from ..errors import CaptureError
from ..message import Field, Message
from ..output import format_fields
from ..records import UartChunk
from .crc import CrcParams, crc
from .definition import Definition, FieldSpec
from .payload import decode_fields, number_field


class UartDecoder:
    """Frames one UART Channel's byte stream with a Definition and decodes each UART frame (DESIGN §6.3)."""

    def __init__(self, definition: Definition):
        self.defn = definition
        self._buf = bytearray()
        self._base = 0  # stream offset of _buf[0]
        self._chunks: list[UartChunk] = []  # chunks overlapping the buffer, oldest first
        self._offsets: list[int] = []  # their start offsets, for bisect
        self._channel = ""
        self._last_time: float | None = None  # timestamp of the latest chunk's first byte
        self._junk = bytearray()  # pending unframed bytes
        self._junk_start = 0
        self._junk_times: tuple[float | None, float | None] = (None, None)
        self._reported_until = 0  # stream offsets below this were already shown in a failed frame
        self._prefix_at: dict[str, int] = {}
        pos = 0
        for spec in definition.prefix:
            self._prefix_at[spec.name] = pos
            pos += spec.num.size

    # --- Decoder protocol ---
    def feed(self, item: Item) -> list[Item]:
        if isinstance(item, Message):
            return [item]
        if not isinstance(item, UartChunk):
            return []
        out: list[Item] = []
        if self.defn.gap_ms is not None:
            out += self._check_gap(item)
        self._channel = item.channel
        self._chunks.append(item)
        self._offsets.append(item.offset)
        self._buf += item.data
        self._last_time = item.timestamp
        out += self._scan()
        return out

    def flush(self) -> list[Item]:
        out: list[Item] = self._scan("capture ends in the middle of a frame") if self._buf else []
        return out + self._flush_junk()

    # --- framing ---
    def _check_gap(self, chunk: UartChunk) -> list[Message]:
        if chunk.timestamp is None:
            raise CaptureError(f"Definition {self.defn.path.name} uses gap_ms, which needs a timestamped capture")
        if self._last_time is None or not self._buf:
            return []
        if (chunk.timestamp - self._last_time) * 1000 <= self.defn.gap_ms:
            return []
        return self._scan("frame interrupted by an idle gap") + self._flush_junk()

    def _scan(self, final: str | None = None) -> list[Message]:
        """Frame as much of the buffer as possible.

        With `final` (end of capture, idle gap) incomplete candidates are reported as truncated
        and scanning continues past them, so complete frames behind a false sync are recovered.
        """
        d = self.defn
        out: list[Message] = []
        while self._buf:
            i = self._buf.find(d.sync_bytes)
            if i < 0:
                keep = 0 if final else len(d.sync_bytes) - 1  # a sync may straddle the next chunk
                self._skip(max(0, len(self._buf) - keep))
                break
            if i:
                self._skip(i)
            complete = len(self._buf) >= d.prefix_size
            if complete:
                length = self._prefix_value(d.length)
                if d.length.max is not None and length > d.length.max:
                    self._skip(1)  # false sync: the length cannot be real
                    continue
                total = d.prefix_size + length + d.suffix_size
                complete = len(self._buf) >= total
            if not complete:
                if final is None:
                    break
                out += self._flush_junk()
                out.append(self._truncated(final))
                self._reported_until = self._base + len(self._buf)
                self._skip(1)
                continue
            msg, ok = self._decode_frame(bytes(self._buf[:total]), length)
            out += self._flush_junk()
            out.append(msg)
            if ok:
                self._consume(total)
            else:
                self._reported_until = max(self._reported_until, self._base + total)
                self._skip(1)
        return out

    def _prefix_value(self, spec: FieldSpec) -> int:
        at = self._prefix_at[spec.name]
        return spec.num.unpack(bytes(self._buf[at:at + spec.num.size]))

    def _consume(self, n: int) -> None:
        del self._buf[:n]
        self._base += n
        while len(self._offsets) > 1 and self._offsets[1] <= self._base:
            self._chunks.pop(0)
            self._offsets.pop(0)

    def _skip(self, n: int) -> None:
        """Move n bytes from the buffer into the pending unframed run, unless already reported."""
        if n <= 0:
            return
        fresh_from = min(n, max(0, self._reported_until - self._base))
        if fresh_from < n:
            if not self._junk:
                self._junk_start = self._base + fresh_from
                self._junk_times = (self._time_at(self._junk_start), None)
            self._junk += self._buf[fresh_from:n]
            self._junk_times = (self._junk_times[0], self._time_at(self._base + n - 1))
        self._consume(n)

    def _time_at(self, offset: int) -> float | None:
        i = bisect.bisect_right(self._offsets, offset) - 1
        return self._chunks[max(i, 0)].timestamp

    def _message(self, name: str, start: int, size: int, fields: list[Field]) -> Message:
        end = start + size - 1
        i0 = max(bisect.bisect_right(self._offsets, start) - 1, 0)
        i1 = max(bisect.bisect_right(self._offsets, end) - 1, 0)
        return Message(self.defn.protocol, name, self._channel, start=self._time_at(start),
                       end=self._time_at(end), offset=start, fields=fields, sources=self._chunks[i0:i1 + 1])

    def _truncated(self, reason: str) -> Message:
        raw = bytes(self._buf)
        m = self._message("truncated", self._base, len(raw), [Field("data", raw, raw=raw)])
        m.error(reason)
        return m

    def _flush_junk(self) -> list[Message]:
        if not self._junk:
            return []
        raw = bytes(self._junk)
        m = Message(self.defn.protocol, "unframed", self._channel, start=self._junk_times[0],
                    end=self._junk_times[1], offset=self._junk_start, fields=[Field("data", raw, raw=raw)])
        m.warn(f"{len(raw)} bytes outside any frame")
        self._junk.clear()
        return [m]

    # --- frame decoding ---
    def _decode_frame(self, frame: bytes, length: int) -> tuple[Message, bool]:
        d = self.defn
        fields: list[Field] = []
        spans: dict[str, tuple[int, int]] = {}
        values: dict[str, int] = {}
        payload = b""
        pos = 0
        for spec in d.frame:
            size = length if spec is d.payload else spec.num.size
            raw = frame[pos:pos + size]
            spans[spec.name] = (pos, pos + size)
            if spec is d.payload:
                payload = raw
            else:
                values[spec.name] = spec.num.unpack(raw)
                fields.append(self._header_field(spec, raw))
            pos += size
        msg = self._message("frame", self._base, len(frame), fields)
        ok = self._check_crc(msg, frame, spans, values)
        if ok:
            data = self._decode_payload(msg, values, payload)
        else:
            msg.name = "bad_frame"
            data = Field(d.payload.name, payload, raw=payload)
        fields.insert(len(d.prefix), data)
        shown = [f for name in d.show for f in fields if f.name == name]
        msg.summary = format_fields(shown + (data.children if data.value is None else [data]))
        return msg, ok

    def _header_field(self, spec: FieldSpec, raw: bytes) -> Field:
        f = number_field(spec, spec.name, raw)
        if spec.role in ("sync", "crc"):
            f.label = f"0x{f.value:0{2 * len(raw)}X}"
        return f

    def _check_crc(self, msg: Message, frame: bytes, spans: dict[str, tuple[int, int]],
                   values: dict[str, int]) -> bool:
        spec = self.defn.crc_field
        if spec is None:
            return True
        covered = frame[spans[spec.covers[0]][0]:spans[spec.covers[1]][1]]
        try:
            expected = crc(covered, spec.crc) if isinstance(spec.crc, CrcParams) else spec.crc(covered)
        except Exception as exc:  # user hook
            msg.error(f"CRC hook failed: {exc}")
            return False
        got = values[spec.name]
        if got != expected:
            width = 2 * spec.num.size
            msg.error(f"CRC mismatch: frame has 0x{got:0{width}X}, {spec.algo} gives 0x{expected:0{width}X}")
            return False
        return True

    def _decode_payload(self, msg: Message, values: dict[str, int], payload: bytes) -> Field:
        d = self.defn
        raw_data = Field(d.payload.name, payload, raw=payload)
        cmd_id = values[d.payload.dispatch]
        command, variant = d.select(cmd_id, values)
        msg.name = command.name if command else f"cmd_0x{cmd_id:02X}"
        if d.versions is not None and values["version"] not in d.versions:
            msg.warn(f"unknown protocol version {values['version']}")
            return raw_data
        if command is None:
            msg.warn(f"unknown command 0x{cmd_id:02X}")
            return raw_data
        if variant is None:
            msg.warn(f"no variant of {command.name} matches this frame")
            return raw_data
        children, used, problem = decode_fields(variant.fields, payload, d.types)
        if problem is not None:
            msg.error(f"definition error in {command.name}: {problem}")
        elif used < len(payload):
            rest = payload[used:]
            children.append(Field("_trailing", rest, raw=rest))
            msg.warn(f"{len(rest)} trailing data bytes not in the {command.name} layout")
        return Field(d.payload.name, None, raw=payload, children=children)
```

- [ ] **Step 5: Register the decoder**

In `src/protocol_analyzer/registry.py`, add this factory below `_canopen`:
```python
def _uart(arg: str, params: dict, base_dir: Path) -> Decoder:
    from .uart.decoder import UartDecoder
    from .uart.definition import load_definition

    if not arg:
        raise SessionError("the uart decoder needs a Definition: --decoder uart:<definition.yaml>")
    return UartDecoder(load_definition(base_dir / arg))
```
and add this entry to the `REGISTRY` dict literal after `"canopen"`:
```python
    "uart": DecoderInfo("uart", "uart:<definition.yaml>",
                        "proprietary UART, framed and decoded by a YAML Definition", _uart),
```

- [ ] **Step 6: Run the full suite**

Run: `.venv/Scripts/python -m pytest -q`
Expected: all pass

- [ ] **Step 7: Update the docs**

In `DESIGN.md`:
- Replace `Status: agreed design, pre-implementation (2026-09-26).` with `Status: v1 implemented per docs/superpowers/plans/2026-09-26-protocol-analyzer-v1.md.`
- After the §4 table row that starts `| UART | raw` and its closing table, add the paragraph: ``Hex text format: one chunk per line, `<seconds> <channel> <hex bytes…>`; `#` starts a comment. A raw `.bin` is one Channel named `uart0`.``
- In §6.1, replace the bullet `` - `protocol`, `description`, `versions` `` with `` - `protocol`, `description`, `versions`, `show` (frame fields that lead each table row) ``
- In the §6.2 Roles table, replace the `crc` row's text `` `algo:` is a preset or a Definition-local name. `` with `` `algo:` is a preset or a Definition-local name, or `hook: file.py:function` computes it. ``
- In the §6.5 vocabulary table, add a last row: ``| Hooks | `hook: file.py:function` instead of `type:`; it receives the remaining data and returns `(value, bytes_consumed)` |``

In `CLAUDE.md`, replace the `Run:` line with:
```markdown
- Run: `.venv/Scripts/pa decode <capture> [--decoder can|canopen|uart:<def.yaml>] [--eds NODE=PATH]`; `pa info <capture>`; `pa decoders`
- Example Definition: `defs/example_uart.yaml` (in-house frame, made-up commands 0x01–0x05)
```

Outside the repo, update the `protocol_analyzer/` line in `D:\Workshop\CLAUDE.md` so it no longer says "Design stage only… no code yet". Make it read: "…`pa` CLI implemented (v1); see its own `CLAUDE.md`."

- [ ] **Step 8: Smoke-test and commit**

Run: `.venv/Scripts/pa decoders && .venv/Scripts/python -m pytest -q`
Expected: three decoders listed (`can`, `canopen [--eds NODE=PATH]`, `uart:<definition.yaml>`) and all tests pass.

```bash
git add src/protocol_analyzer tests DESIGN.md CLAUDE.md
git commit -m "feat: frame and decode proprietary UART captures with Definitions

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Spec coverage map

| DESIGN section | Task(s) |
|---|---|
| §2 stack, packaging, `pa` entry point | 1 |
| §3.1 Records, §3.2 Message/Field | 1 |
| §3.3 stateful chained Decoders, built-in registry | 3 (stack, registry), 6 / 13 (entries) |
| §3.4 bad data shown, never dropped | 3 (error frames), 6–9 (Diagnostics), 13 (bad_frame / truncated / unframed) |
| §4 candump + ASC; UART .bin + hex text; full-duplex Channels | 2, 13 (one UartDecoder per Channel) |
| §5 CANopen classification, NMT/SYNC/TIME/EMCY/heartbeat | 6 |
| §5 SDO expedited + segmented + abort text | 7 |
| §5 EDS/DCF names, PDO mapping | 8, 9 |
| §6.1 YAML Definition, Kaitai-style types, one file, `when:` | 11 |
| §6.2 Roles, `max`, `covers`, `gap_ms` | 11 (validation), 13 (behaviour) |
| §6.3 framing and resync one byte past the failed sync | 13 |
| §6.4 parameterized CRC + presets | 10 (the CRC-discovery helper is listed as *later* in DESIGN §8 and is not in v1) |
| §6.5 payload vocabulary, unknown cmd/version | 12, 13 |
| §6.6 trailing / missing layout diagnostics | 12, 13 |
| §6.7 first Definition | already committed; `show:` added in 11 |
| §7 Session from flags or YAML | 5 |
| §8 CLI decode/info/decoders, filters, time display | 4, 5 |
