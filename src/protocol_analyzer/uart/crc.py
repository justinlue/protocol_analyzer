from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CrcParams:
    """A CRC in the Rocksoft/catalogue parameter model."""

    width: int  # 8, 16 or 32
    poly: int
    init: int
    refin: bool
    refout: bool
    xorout: int


PRESETS: dict[str, CrcParams] = {
    "crc8": CrcParams(8, 0x07, 0x00, False, False, 0x00),
    "crc16_modbus": CrcParams(16, 0x8005, 0xFFFF, True, True, 0x0000),
    "crc16_ccitt_false": CrcParams(16, 0x1021, 0xFFFF, False, False, 0x0000),
    "crc16_xmodem": CrcParams(16, 0x1021, 0x0000, False, False, 0x0000),
    "crc16_kermit": CrcParams(16, 0x1021, 0x0000, True, True, 0x0000),
    "crc16_arc": CrcParams(16, 0x8005, 0x0000, True, True, 0x0000),
    "crc32": CrcParams(32, 0x04C11DB7, 0xFFFFFFFF, True, True, 0xFFFFFFFF),
}


def _reflect(value: int, width: int) -> int:
    out = 0
    for _ in range(width):
        out = (out << 1) | (value & 1)
        value >>= 1
    return out


def crc(data: bytes, params: CrcParams) -> int:
    top = 1 << (params.width - 1)
    mask = (1 << params.width) - 1
    reg = params.init
    for byte in data:
        if params.refin:
            byte = _reflect(byte, 8)
        reg ^= byte << (params.width - 8)
        for _ in range(8):
            reg = ((reg << 1) ^ params.poly) & mask if reg & top else (reg << 1) & mask
    if params.refout:
        reg = _reflect(reg, params.width)
    return reg ^ params.xorout
