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
    except UnicodeDecodeError:
        raise DefinitionError(f"{p}: not UTF-8 text; save the Definition as UTF-8") from None
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
        self._check_type_cycles(types)
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

    def _check_type_cycles(self, types: dict[str, list[FieldSpec]]) -> None:
        def visit(name: str, path: tuple[str, ...]) -> None:
            for f in types[name]:
                if f.type in path:
                    self.fail(f"types.{path[0]}", "contains itself (directly or through other types)")
                if f.type in types:
                    visit(f.type, path + (f.type,))

        for name in types:
            visit(name, (name,))

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
            if f.num.kind != "u":
                self.fail(where, "the length field needs an unsigned integer type (u1, u2le, ...)")
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
