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
