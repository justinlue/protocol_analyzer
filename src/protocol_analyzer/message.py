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
