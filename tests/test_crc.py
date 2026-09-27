import pytest

from protocol_analyzer.uart.crc import PRESETS, CrcParams, crc

CHECK = b"123456789"


@pytest.mark.parametrize("name, check", [
    ("crc8", 0xF4),
    ("crc16_modbus", 0x4B37),
    ("crc16_ccitt_false", 0x29B1),
    ("crc16_xmodem", 0x31C3),
    ("crc16_kermit", 0x2189),
    ("crc16_arc", 0xBB3D),
    ("crc32", 0xCBF43926),
])
def test_presets_match_catalogue_check_values(name, check):
    assert crc(CHECK, PRESETS[name]) == check


def test_empty_input_returns_init_after_output_transform():
    assert crc(b"", PRESETS["crc16_modbus"]) == 0xFFFF
    assert crc(b"", PRESETS["crc32"]) == 0


def test_custom_parameters():
    ibm_3740 = CrcParams(width=16, poly=0x1021, init=0xFFFF, refin=False, refout=False, xorout=0)
    assert crc(CHECK, ibm_3740) == 0x29B1
