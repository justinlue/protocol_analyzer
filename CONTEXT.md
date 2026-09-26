# Protocol Analyzer

A lightweight analyzer that turns captured bus traffic (CAN, proprietary UART) into decoded, human-readable protocol messages. Think Sigrok's decoder stack, starting at the frame/byte level instead of sampled logic levels.

## Input

**Capture**:
A file of recorded bus traffic (candump log, Vector ASC, raw UART binary, timestamped UART hex text).
_Avoid_: Log, trace, dump

**Source**:
Anything that yields Records from a Capture or, later, a live adapter.
_Avoid_: Reader, input, driver

**Channel**:
One physical bus or one direction of a UART link within a Capture; every Record belongs to exactly one.
_Avoid_: Port, interface, line

**Record**:
The smallest unit a Source produces: either a CanFrame or a UartChunk.
_Avoid_: Event, packet, sample

**CanFrame**:
One CAN or CAN-FD frame as seen on the bus: identifier, frame-type flags, DLC and data bytes, or an error frame.
_Avoid_: CAN message, packet

**UartChunk**:
A run of bytes received on one UART Channel, with the timestamp or byte offset of its first byte. Carries no framing meaning.
_Avoid_: UART frame, packet, buffer

## Decoding

**Decoder**:
A stateful stream processor that consumes Records or Messages and produces Messages for one protocol layer.
_Avoid_: Parser, dissector, plugin

**Decoder stack**:
An ordered chain of Decoders bound to a Channel, each consuming the output of the one below.
_Avoid_: Pipeline, chain

**Message**:
A decoded protocol unit: protocol name, message name, a tree of Fields, time span, links to its source Records, and any Diagnostics.
_Avoid_: Frame (reserved for CanFrame / UART frame), packet, annotation

**Field**:
A named, decoded value inside a Message, carrying its raw bytes and, where defined, its physical value, unit or enum name.
_Avoid_: Signal (reserved for DBC decoding), attribute

**Diagnostic**:
A warning or error attached to a Message (bad CRC, unknown version, trailing bytes, layout mismatch). Bad data always becomes a Message with Diagnostics, never a silent drop.
_Avoid_: Exception, fault

**Resync**:
Recovering frame alignment after a failed UART frame by rescanning from one byte past the failed sync.

**Session**:
The full binding of Captures, Channels and Decoder stacks for one analysis run, whether built from CLI flags or a session file.
_Avoid_: Config, project, profile

## CANopen

**COB-ID**:
The CAN identifier interpreted as CANopen function code plus Node ID.

**Node ID**:
The 7-bit CANopen device address (1–127) embedded in most COB-IDs.

**Object dictionary**:
A CANopen device's table of index/subindex entries, described by an EDS or DCF file.
_Avoid_: OD table, register map

**PDO mapping**:
The Object-dictionary entries that describe which objects are packed into a PDO's data, and where.

## Proprietary UART

**Definition**:
A YAML file describing one proprietary UART protocol: its frame layout, Commands, enums and reusable types.
_Avoid_: Spec, schema, parsing file, protocol file

**UART frame**:
One complete framed unit on a UART Channel (sync through CRC), recovered from UartChunks by the framer.
_Avoid_: Packet, message

**Role**:
The framing meaning a Definition assigns to a frame field: `sync`, `length`, `payload` or `crc`.

**Command**:
One entry of a Definition, keyed by `cmd_id`, giving a name and the payload layout for UART frames with that id.
_Avoid_: Opcode, message type

**Hook**:
A Python function referenced from a Definition as `module:function` for a checksum or field that YAML cannot express.
_Avoid_: Plugin, callback, extension
