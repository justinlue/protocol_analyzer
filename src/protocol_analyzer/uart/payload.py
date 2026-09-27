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
