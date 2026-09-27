# CLAUDE.md

Lightweight Sigrok-like protocol analyzer (`pa`): CAN/CANopen from candump/ASC captures, proprietary UART framed by YAML Definitions.

- Design decisions: `DESIGN.md`. Vocabulary: `CONTEXT.md`. Use its terms (Record, Message, Decoder, Definition…) and avoid its `_Avoid_` words.
- Setup: `python -m venv .venv && .venv/Scripts/python -m pip install -e ".[dev]"`
- Tests: `.venv/Scripts/python -m pytest -q`
- Run: `.venv/Scripts/pa decode <capture> [--decoder can|canopen|uart:<def.yaml>] [--eds NODE=PATH]`; `pa info <capture>`; `pa decoders`
- Example Definition: `defs/example_uart.yaml` (in-house frame, made-up commands 0x01–0x05)
- Layout: `sources/` read Captures into Records; `decoders/`, `canopen/`, `uart/` turn Records into Messages; `session.py`/`analysis.py` wire Channels to Decoder stacks; `cli.py`, `output.py`, `filters.py` are the front end.
- Rules: user-facing failures raise a `PaError` subclass (CLI prints `pa: error:` and exits 2); bad data becomes a Message with Diagnostics, never a silent drop; tests first.
