from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .errors import SessionError
from .sources import capture_kind

ANY_CHANNEL = "*"


@dataclass
class Binding:
    decoders: list[str]  # decoder specs, bottom of the stack first
    params: dict = field(default_factory=dict)


@dataclass
class Session:
    capture: Path
    bindings: dict[str, Binding]
    base_dir: Path = field(default_factory=Path.cwd)  # resolves relative Definition / EDS paths

    def binding_for(self, channel: str) -> Binding | None:
        return self.bindings.get(channel) or self.bindings.get(ANY_CHANNEL)


def session_from_args(capture: str | Path, decoder: str | None = None,
                      eds: list[str] | None = None) -> Session:
    capture = Path(capture)
    if decoder is None:
        if capture_kind(capture) == "uart":
            raise SessionError("UART captures need --decoder uart:<definition.yaml>")
        decoder = "can"
    params: dict = {}
    if eds:
        if decoder.partition(":")[0] != "canopen":
            raise SessionError("--eds only applies to --decoder canopen")
        params["eds"] = dict(_parse_eds_flag(text) for text in eds)
    return Session(capture, {ANY_CHANNEL: Binding([decoder], params)})


def _parse_eds_flag(text: str) -> tuple[int, str]:
    node, sep, path = text.partition("=")
    try:
        node_id = int(node, 0)
    except ValueError:
        node_id = -1
    if not sep or not path or not 1 <= node_id <= 127:
        raise SessionError(f"--eds expects NODE=PATH with NODE 1-127, got {text!r}")
    return node_id, path


def load_session(path: str | Path) -> Session:
    p = Path(path)
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SessionError(f"{p}: cannot read session file: {exc.strerror}") from exc
    except yaml.YAMLError as exc:
        raise SessionError(f"{p}: invalid YAML: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("capture"), str):
        raise SessionError(f"{p}: session file needs a 'capture' path")
    channels = doc.get("channels")
    if not isinstance(channels, dict) or not channels:
        raise SessionError(f"{p}: session file needs a non-empty 'channels' mapping")
    bindings = {str(ch): _binding(p, str(ch), spec) for ch, spec in channels.items()}
    return Session(p.parent / doc["capture"], bindings, base_dir=p.parent)


def _binding(path: Path, channel: str, spec: object) -> Binding:
    where = f"{path}: channels.{channel}"
    if not isinstance(spec, dict) or "decoder" not in spec:
        raise SessionError(f"{where}: needs a 'decoder'")
    decoders = [spec["decoder"]] if isinstance(spec["decoder"], str) else spec["decoder"]
    if not isinstance(decoders, list) or not decoders or not all(isinstance(d, str) for d in decoders):
        raise SessionError(f"{where}.decoder: expected a decoder name or a list of them")
    params = {k: v for k, v in spec.items() if k != "decoder"}
    if "eds" in params:
        eds = params["eds"]
        try:
            if not isinstance(eds, dict):
                raise ValueError
            params["eds"] = {int(str(node), 0): str(eds_path) for node, eds_path in eds.items()}
        except ValueError:
            raise SessionError(f"{where}.eds: expected a mapping of node id to EDS path") from None
    return Binding(decoders, params)
