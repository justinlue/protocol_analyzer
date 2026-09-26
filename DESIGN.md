# Protocol Analyzer: Design

Status: agreed design, pre-implementation (2026-09-26). Vocabulary is defined in [CONTEXT.md](CONTEXT.md).

## 1. Goal and scope

A lightweight, Sigrok-like analyzer for industrial control protocols. It works at the **frame and byte level**, not on sampled logic levels.

- **v1 inputs are captured files.** Live adapters (python-can interfaces, pyserial) come later behind the same Source interface.
- **Out of scope:** bit-level decoding of logic-analyzer samples (bit timing, CAN bit-stuffing, UART start/stop bits). This is what keeps the tool light.
- **v1 protocols:** CAN/CAN-FD frames, CANopen on top of them, and proprietary UART protocols described by user-supplied Definitions.

## 2. Stack and project hygiene

- Python ≥ 3.11, `pyproject.toml`, src layout, editable install.
- Console entry point: `pa`.
- Libraries: `python-can` (capture formats, later live adapters), `pyyaml`. `pyserial` arrives with live UART.
- Tests: pytest, test-first, with small checked-in fixture Captures.
- Standalone project with a library core. Other tools (e.g. LogParse) consume it through `pa decode --format jsonl`.

## 3. Architecture

```
Capture ─▶ Source ─▶ Records (CanFrame | UartChunk), tagged by Channel
                         │
                         ▼
            Decoder stack per Channel (bound by the Session)
              CanFrame ─▶ CANopen decoder ─▶ Messages
              UartChunk ─▶ UART framer+decoder (Definition) ─▶ Messages
                         │
                         ▼
             Filters ─▶ Output (table | jsonl)
```

### 3.1 Records

- **CanFrame**: `timestamp`, `channel`, `id`, `is_extended`, `is_remote`, `is_fd`, `brs`, `esi`, `dlc`, `data`, `is_error`.
- **UartChunk**: `timestamp` (or `offset` when the Capture has none), `channel`, `data`.

### 3.2 Message

`protocol`, `name`, `fields` (an ordered tree of Fields), `start`/`end` (timestamp or byte offset), `sources` (the Records it came from), `diagnostics`.

A Field carries its name, raw bytes, decoded value, and optionally a physical value, unit and enum name.

### 3.3 Decoders

- Stateful stream processors: they take Records or Messages in and give Messages out, and may hold state across inputs (e.g. SDO segmented transfer).
- Decoders chain from day one, so one Decoder can consume another's Messages (e.g. a future CAN → ISO-TP → UDS).
- v1 has a **built-in registry** only, with no entry-point plugin discovery. UART protocols are data (Definitions), not code. Hooks are loaded by path from the Definition.

### 3.4 Bad data

Bad data is **always shown, never dropped**. A failed frame becomes a Message with Diagnostics and its raw bytes attached, then decoding resyncs and continues. CAN error frames become Messages too.

## 4. Inputs

| Kind | v1 formats | Notes |
|---|---|---|
| CAN | candump `.log`, Vector `.asc` | Read via python-can. `.blf`/`.trc` are cheap to add later. |
| UART | raw `.bin`, timestamped hex text | `.bin` has no timestamps, so Messages carry byte offsets. |

UART links are **full-duplex**, and each direction is its own Channel with its own framer. Pairing requests with responses is deferred. When it lands, the src/dst transaction ids are the pairing key.

## 5. CANopen decoder (v1)

**Classify every frame by COB-ID:**

| COB-ID | Service |
|---|---|
| 0x000 | NMT command |
| 0x080 | SYNC |
| 0x081–0x0FF | EMCY (0x080 + node) |
| 0x100 | TIME |
| 0x180 / 0x280 / 0x380 / 0x480 + node | TPDO1–4 |
| 0x200 / 0x300 / 0x400 / 0x500 + node | RPDO1–4 |
| 0x580 + node | SDO server→client |
| 0x600 + node | SDO client→server |
| 0x700 + node | Heartbeat / node guarding / boot-up |
| 0x7E4 / 0x7E5 | LSS |

**Fully decoded in v1:**
- NMT
- Heartbeat and boot-up
- SYNC
- EMCY, with the error-code table
- SDO expedited and segmented, including abort-code text

**EDS/DCF (optional, one per node, `--eds node=path`):**
- Supplies Object-dictionary names for SDO indexes.
- Supplies PDO mappings, so PDOs decode into named objects. Without an EDS, PDO payloads stay raw.

**Deferred to v2:** SDO block transfer, LSS content decoding, learning PDO mappings from observed SDO writes.

## 6. Proprietary UART decoder

### 6.1 Definition format

Our own YAML schema, validated on load with clear error messages. It borrows Kaitai Struct's type names so it feels familiar. One Definition per protocol. Per-version differences are expressed with `when:`.

A Definition has these top-level keys:
- `protocol`, `description`, `versions`
- `enums`: named value→name tables
- `types`: reusable nested structs
- `crc`: named parameter sets, in addition to the built-in presets
- `frame`: the ordered frame field list
- `commands`: payload layouts keyed by `cmd_id`

### 6.2 Frame field list and Roles

The frame is a general ordered field list, not a hard-wired header shape. Framing behavior comes from **Roles**:

| Role | Meaning |
|---|---|
| `sync` | Constant `value`. The framer scans the stream for its wire bytes. |
| `length` | Byte count of the field named in `of:`. `max:` bounds it; a larger value is treated as a false sync. |
| `payload` | Variable-length data. `dispatch:` names the field that selects the Command. |
| `crc` | Checksum. `algo:` is a preset or a Definition-local name. `covers: [first, last]` is an inclusive field range. |

Optional idle-gap framing (`gap_ms`) may be declared. It requires a timestamped Capture and errors clearly on one without timestamps.

### 6.3 Framing and Resync

1. Scan for the sync wire bytes.
2. Read fixed fields up to the length field. If the length is above `max`, it is a false sync.
3. Wait for payload + CRC bytes, then verify the CRC.
4. On any failure, emit an error Message holding the raw bytes and **resume scanning one byte after the failed sync**. This recovers real frames hidden behind a false sync.

There is no byte stuffing. Payloads may legitimately contain the sync bytes, and length-based framing plus the CRC handles that.

### 6.4 CRC engine

- The engine is a parameterized CRC in the standard catalogue form: `width`, `poly`, `init`, `refin`, `refout`, `xorout`.
- Named presets cover at least CRC-16/MODBUS, CCITT-FALSE, XMODEM, KERMIT, IBM/ARC and CRC-32.
- The CRC value is stored in the frame using the field's declared endianness.
- A `pa` helper will try every preset (and each plausible coverage range) against a Capture and report which ones match. This is how the real parameters of a protocol get found.

### 6.5 Commands and payload layouts

- `commands` maps `cmd_id` to a `name` and payload `fields`.
- An overloaded cmd lists `variants`, each with a `when:` qualifier matched against frame fields (e.g. `src_module`, `version`). The first match wins, and a variant without `when:` is the fallback.
- **Unknown cmd** or **unknown version:** the header still decodes, the payload is shown as raw hex, and a warning Diagnostic is attached.

**Payload field vocabulary:**

| Feature | Syntax |
|---|---|
| Integers / floats | `u1`–`u8`, `s1`–`s8`, `f4`, `f8`, with `le`/`be` suffix (default `le`) |
| Scaling | `scale`, `offset`, `unit` (physical = raw × scale + offset) |
| Enums | `enum:` a name from `enums`, or an inline map |
| Bitfields | `bits: {name: bit, name: lo-hi}` inside one integer |
| Bytes / strings | `bytes` or `str`, with `size: N \| <field> \| rest`; `strz` for zero-terminated; `encoding:` (default ascii) |
| Arrays | `count: N \| <field> \| eos` on any field |
| Nested structs | `type:` a name from `types` |

**Deferred:** conditional fields (present only when a flag is set). They will be added when a real Command needs them.

### 6.6 When the layout and the data length disagree

- **Layout consumes fewer bytes than `data_len`:** decode the fields and keep the leftover as `_trailing` raw hex, with a warning. Newer firmware often appends fields.
- **Layout needs more bytes than `data_len`:** decode what fits, mark the remaining fields missing, and attach an error Diagnostic that blames the **Definition**. The CRC passed, so the Capture itself is fine.

### 6.7 First Definition

`defs/example_uart.yaml` describes the in-house frame, with made-up example Commands until the real ones are supplied:

```
preamble u2le (0x55AA) | version u1 | setting u1 | src_module u1 | dst_module u1
| src_trans u1 | dst_trans u1 | cmd_id u1 | data_len u2le | data[data_len] | crc u2le
```

- All multi-byte values are little-endian.
- The header is 11 bytes. The minimum frame is 13 bytes.
- The CRC is CRC-16/MODBUS over version..data. The algorithm is provisional until confirmed.
- `data_len` counts data bytes only, with `max` 1024.
- Module ids resolve through the `modules` enum. Transaction ids are shown raw.

## 7. Session

- A Session binds Captures and Channels to Decoder stacks and their parameters (EDS per node, Definition path).
- It can be built from **CLI flags** (the single-channel case) or from a **session YAML** (`--session`). Flags are converted into a Session object, so there is a single code path.

## 8. CLI

```
pa decode <capture> [--decoder canopen|uart:<def.yaml>] [--eds NODE=PATH ...]
                    [--session FILE] [--format table|jsonl] [--abs] [filters...]
pa info <capture>      # frame count, IDs seen, channels, time span
pa decoders            # list built-in decoders
```

- **Filters** (v1 uses simple flags, applied to Message fields): `--id`, `--node`, `--service`, `--channel`, `--errors-only`, `--time START:END`. A Wireshark-style expression language can slot in later without touching Decoders.
- **Time display:** relative to the first Record by default, absolute with `--abs`. Captures without timestamps show byte offsets.
- **Later:** `pa stats` (per-COB-ID / per-node breakdown), `--follow` for live input, and the CRC-discovery helper (§6.4).

## 9. Deferred (not v1)

- Live adapters: python-can interfaces and pyserial
- `.blf`/`.trc` input
- DBC signal decoding
- J1939, ISO-TP/UDS
- SDO block transfer, LSS decoding
- Request/response pairing
- Expression filters
- Entry-point plugins
- Conditional payload fields
- GUI
