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
    kind: str = "can"  # the Records the decoder reads at the bottom of a stack: "can" | "uart"


def _can(arg: str, params: dict, base_dir: Path) -> Decoder:
    from .decoders.can import CanDecoder

    return CanDecoder()


def _canopen(arg: str, params: dict, base_dir: Path) -> Decoder:
    from .canopen.decoder import CanopenDecoder
    from .canopen.eds import load_eds

    ods = {node: load_eds(base_dir / path, node) for node, path in params.get("eds", {}).items()}
    return CanopenDecoder(ods)


def _uart(arg: str, params: dict, base_dir: Path) -> Decoder:
    from .uart.decoder import UartDecoder
    from .uart.definition import load_definition

    if not arg:
        raise SessionError("the uart decoder needs a Definition: --decoder uart:<definition.yaml>")
    return UartDecoder(load_definition(base_dir / arg))


REGISTRY: dict[str, DecoderInfo] = {
    "can": DecoderInfo("can", "can", "CAN/CAN-FD frame layer: id, flags, dlc, data", _can),
    "canopen": DecoderInfo("canopen", "canopen [--eds NODE=PATH]",
                           "CANopen: NMT, SYNC, TIME, EMCY, heartbeat, SDO, PDO", _canopen),
    "uart": DecoderInfo("uart", "uart:<definition.yaml>",
                        "proprietary UART, framed and decoded by a YAML Definition", _uart, "uart"),
}


def decoder_info(spec: str) -> DecoderInfo:
    name = spec.partition(":")[0]
    info = REGISTRY.get(name)
    if info is None:
        known = ", ".join(sorted(REGISTRY))
        raise SessionError(f"unknown decoder '{name}' (available: {known})")
    return info


def build_decoder(spec: str, params: dict | None = None, base_dir: Path = Path(".")) -> Decoder:
    return decoder_info(spec).factory(spec.partition(":")[2], params or {}, base_dir)
