from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .decoders.base import Decoder
from .errors import SessionError

# (argument after "name:", the Binding's params, base dir for relative paths) -> Decoder
Factory = Callable[[str, dict, Path], Decoder]


@dataclass(frozen=True)
class DecoderInfo:
    name: str
    usage: str
    description: str
    factory: Factory


def _can(arg: str, params: dict, base_dir: Path) -> Decoder:
    from .decoders.can import CanDecoder

    return CanDecoder()


def _canopen(arg: str, params: dict, base_dir: Path) -> Decoder:
    from .canopen.decoder import CanopenDecoder

    return CanopenDecoder()


REGISTRY: dict[str, DecoderInfo] = {
    "can": DecoderInfo("can", "can", "CAN/CAN-FD frame layer: id, flags, dlc, data", _can),
    "canopen": DecoderInfo("canopen", "canopen [--eds NODE=PATH]",
                           "CANopen: NMT, SYNC, TIME, EMCY, heartbeat, SDO, PDO", _canopen),
}


def build_decoder(spec: str, params: dict | None = None, base_dir: Path = Path(".")) -> Decoder:
    name, _, arg = spec.partition(":")
    info = REGISTRY.get(name)
    if info is None:
        known = ", ".join(sorted(REGISTRY))
        raise SessionError(f"unknown decoder '{name}' (available: {known})")
    return info.factory(arg, params or {}, base_dir)
