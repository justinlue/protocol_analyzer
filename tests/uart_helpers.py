from protocol_analyzer.records import UartChunk
from protocol_analyzer.uart.crc import PRESETS, crc


def make_frame(cmd, data=b"", src=0x01, dst=0x10, version=1, setting=0, src_trans=0, dst_trans=0,
               bad_crc=False):
    """A frame in the defs/example_uart.yaml layout, with a valid CRC-16/MODBUS unless bad_crc."""
    body = bytes([version, setting, src, dst, src_trans, dst_trans, cmd]) + len(data).to_bytes(2, "little") + data
    value = crc(body, PRESETS["crc16_modbus"]) ^ (0xFFFF if bad_crc else 0)
    return b"\xaa\x55" + body + value.to_bytes(2, "little")


def chunks(*parts, times=None, channel="rx"):
    """UartChunks for consecutive byte strings, with running offsets."""
    out, offset = [], 0
    for i, part in enumerate(parts):
        out.append(UartChunk(None if times is None else times[i], channel, offset, part))
        offset += len(part)
    return out
