import argparse

import pytest

from protocol_analyzer.filters import Filters, csv_set, int_set, time_range
from protocol_analyzer.message import Field, Message
from protocol_analyzer.records import CanFrame


def _msg(name="sdo", channel="can0", start=10.0, can_id=0x585, node=5):
    return Message("canopen", name, channel, start=start, fields=[Field("node", node)],
                   sources=[CanFrame(start, channel, can_id)])


def test_empty_filters_match_everything():
    assert Filters().matches(_msg(), t0=10.0)


def test_each_filter():
    m = _msg()
    assert Filters(ids={0x585}).matches(m, 10.0)
    assert not Filters(ids={0x181}).matches(m, 10.0)
    assert Filters(nodes={5}).matches(m, 10.0)
    assert not Filters(nodes={6}).matches(m, 10.0)
    assert Filters(services={"SDO"}).matches(m, 10.0)
    assert not Filters(services={"emcy"}).matches(m, 10.0)
    assert not Filters(channels={"can1"}).matches(m, 10.0)
    assert not Filters(errors_only=True).matches(m, 10.0)
    m.error("x")
    assert Filters(errors_only=True).matches(m, 10.0)


def test_time_filter_uses_display_basis():
    m = _msg(start=12.0)
    assert Filters(time_range=(1.5, 3.0)).matches(m, t0=10.0)
    assert not Filters(time_range=(1.5, 3.0)).matches(m, t0=10.0, absolute=True)
    assert Filters(time_range=(11.0, None)).matches(m, t0=10.0, absolute=True)
    untimed = Message("u", "f", "rx", offset=3)
    assert not Filters(time_range=(None, 5.0)).matches(untimed, t0=None)


def test_flag_parsers():
    assert int_set("0x181, 385") == {0x181, 385}
    assert csv_set("sdo,emcy") == {"sdo", "emcy"}
    assert time_range("1.5:3") == (1.5, 3.0)
    assert time_range(":3") == (None, 3.0)
    with pytest.raises(argparse.ArgumentTypeError):
        int_set("0x18G")
    with pytest.raises(argparse.ArgumentTypeError):
        time_range("5")
