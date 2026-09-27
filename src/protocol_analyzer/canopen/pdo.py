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
