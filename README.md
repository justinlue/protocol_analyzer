# pa: protocol analyzer

`pa` is a lightweight, Sigrok-like analyzer for captured bus traffic. It reads a capture file and prints each decoded frame or message on one line:

- **CAN / CAN FD** from candump `.log` and Vector `.asc` captures, as raw frames or as **CANopen** (NMT, SYNC, TIME, EMCY, heartbeat, SDO, PDO), optionally named and typed from EDS/DCF files.
- **Proprietary UART protocols** from `.bin` or hex text captures, framed and decoded by a YAML **Definition** you write.

There are three commands:

| Command | What it does |
|---|---|
| `pa decode <capture>` | Decode a capture into messages |
| `pa info <capture>` | Summarize a capture: record count, time span, channels, CAN ids, error frames |
| `pa decoders` | List the built-in decoders |

Design decisions are in [DESIGN.md](DESIGN.md) and vocabulary in [CONTEXT.md](CONTEXT.md).

## Setup

Requires Python 3.11 or newer.

```
cd D:\Workshop\protocol_analyzer
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
```

`pa` is installed only in the project's virtual environment. Either call it by path:

```
.venv\Scripts\pa decode <capture> ...
```

or activate the environment once per terminal and then just type `pa`:

```
.venv\Scripts\activate          (PowerShell: .venv\Scripts\Activate.ps1)
pa decode <capture> ...
```

Run the tests with `.venv\Scripts\python -m pytest -q`.

## CAN captures (candump `.log`, Vector `.asc`)

```
pa info  bus.log                          # records, time span, channels, CAN ids, error frames
pa decode bus.log                         # raw frames: id, dlc, data, flags
pa decode bus.log --decoder canopen       # CANopen: NMT, SYNC, TIME, EMCY, heartbeat, SDO, PDO
pa decode bus.log --decoder canopen --eds 5=drive.eds --eds 6=io.eds
```

With an EDS or DCF file for a node, that node's SDO lines show object names and typed values, and its PDOs are split into named fields. Without one, PDO payloads stay raw.

Example output:

```
0.000000  can0  canopen  nmt        command=start target=5
0.010000  can0  canopen  heartbeat  node=5 state=pre-operational
0.030000  can0  canopen  sdo        node=5 dir=response command=initiate_upload index=0x1018 subindex=0 object=Identity object.Highest sub-index supported data=1
```

The columns are:

1. Time, in seconds from the first record.
2. Channel.
3. Protocol.
4. Message name.
5. Decoded fields.

Warnings and errors are appended as `!warning: …` or `!error: …`. Bad data is always shown this way, never dropped.

Known v1 limitation: PDOs moved away from their default COB-IDs (via objects 0x1400/0x1800) are not followed.

## UART captures (proprietary protocols)

A UART capture needs a Definition file that describes the frame:

```
pa decode capture.hex --decoder uart:defs/example_uart.yaml
pa decode capture.bin --decoder uart:defs/example_uart.yaml
```

### Capture formats

- **`.hex` / `.txt`:** one chunk per line, `<seconds> <channel> <hex bytes>`. Each channel (for example `rx` and `tx`) is framed separately, so full-duplex links work. `#` starts a comment. Bytes may be spaced or run together.

  ```
  # timestamp channel bytes
  0.000100 rx AA 55 01 00 01 10 00 00 02 0B 00 ...
  0.000900 tx aa550100100100000100...
  ```

- **`.bin`:** raw bytes with no timestamps, read as a single channel named `uart0`. Lines show a byte offset such as `@42` instead of a time.

### Output

A good frame decodes to its command name and payload fields, for example:

```
motor_status  src_module=MCU dst_module=MotorCtrl state=running flags={enabled=true reverse=false mode=3 fault=true} speed=-1500 rpm current=1.5 A temperature=25 °C setpoint=1500 rpm
```

Problems are reported as messages of their own:

| Message | Meaning |
|---|---|
| `bad_frame` | The CRC doesn't match. The error names the expected and actual values. |
| `truncated` | A frame was cut off at the end of the capture or at an idle gap. |
| `unframed` | Bytes outside any frame. |
| `cmd_0xNN` | An unknown command. The header decodes and the payload is shown raw. |

### Writing a Definition for your protocol

Copy [defs/example_uart.yaml](defs/example_uart.yaml) and edit it:

- **`frame:`** lists the header fields in wire order. Roles mark the special ones:
  - `sync` is the preamble value.
  - `length` gives the payload length, with an optional `max`.
  - `payload` uses `dispatch:` to select the command.
  - `crc` takes a preset with `algo:` and the covered range with `covers:`.
- **`commands:`** holds one payload layout per `cmd_id`. An overloaded command lists `variants` with `when:` conditions.
- **`enums:`** and **`types:`** hold reusable value-to-name tables and nested structs.
- **`show:`** lists the header fields that lead each output line, for example `[src_module, dst_module]`.
- **Types** use Kaitai-style names: `u1`, `u2le`, `s4be`, `f4`, `bytes`, `str`, `strz`. They can carry `scale`, `offset`, `unit`, `enum`, `bits`, `size` and `count`.
- **The CRC** can be one of these presets:
  - `crc8`
  - `crc16_modbus`
  - `crc16_ccitt_false`
  - `crc16_xmodem`
  - `crc16_kermit`
  - `crc16_arc`
  - `crc32`

  You can also define your own parameters in a top-level `crc:` section, or point to a Python function with `hook: file.py:function`.
- **Hooks:** a payload field can use `hook: file.py:function` instead of `type:` for anything the vocabulary can't express. Hook paths are relative to the Definition file.

`pa` checks the Definition when it loads and names the exact field if something is wrong. The full format is described in [DESIGN.md](DESIGN.md) §6.

Note: hooks run Python code from the Definition's folder, so only use Definitions you trust.

## Narrowing the output

```
pa decode bus.log --decoder canopen --node 5 --service sdo,emcy
pa decode bus.log --id 0x181,0x705
pa decode bus.log --time 1.5:3.0          # seconds, same basis as the display
pa decode cap.hex --decoder uart:my.yaml --channel rx --errors-only
```

| Flag | Keeps |
|---|---|
| `--id` | CAN ids, comma-separated (decimal or `0x`) |
| `--node` | CANopen node ids |
| `--service` | message names (`sdo`, `emcy`, `heartbeat`, your command names, …) |
| `--channel` | channels |
| `--errors-only` | messages with an error |
| `--time START:END` | a time window. Either end may be left out. It needs a timestamped capture, so not `.bin`. |
| `--abs` | show (and filter on) absolute timestamps instead of time from the first record |

## JSON output

For scripts and other tools, add `--format jsonl`. Each message becomes one JSON object per line, containing:

- time and offset
- channel, protocol and name
- the full field tree, with raw bytes as hex
- the diagnostics

```
pa decode bus.log --decoder canopen --format jsonl > out.jsonl
```

## Different decoders per channel (session file)

When a capture mixes channels that need different decoders, put the bindings in a YAML session file. Paths inside it are relative to the session file.

```yaml
capture: bus.asc
channels:
  "1": {decoder: canopen, eds: {5: node5.eds}}
  "2": {decoder: [can]}          # a list is a decoder stack, bottom first
  "*": {decoder: can}            # every other channel
```

```
pa decode --session my_session.yaml
pa decode other.asc --session my_session.yaml    # same bindings, different capture (relative to the current folder)
```

Channels with no binding and no `"*"` entry are skipped.

## Errors

Any mistake gives a single `pa: error: …` line on stderr and exit code 2, never a Python traceback. That covers:

- a missing or unreadable file
- an unknown capture type
- a malformed capture
- an invalid Definition, EDS or session file
- a decoder that doesn't match the capture type (for example `uart:` on a CAN log)

An empty capture decodes to nothing and exits 0.
