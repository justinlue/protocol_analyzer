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
