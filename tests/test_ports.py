import pytest

from netrecon.ports import parse_port_spec, service_name


def test_single_port():
    assert parse_port_spec("80") == [80]


def test_list_and_range():
    assert parse_port_spec("22,80,100-103") == [22, 80, 100, 101, 102, 103]


def test_sorted_and_deduplicated():
    assert parse_port_spec("443,80,80") == [80, 443]


def test_out_of_range_rejected():
    with pytest.raises(ValueError):
        parse_port_spec("70000")
    with pytest.raises(ValueError):
        parse_port_spec("0")


def test_reversed_range_rejected():
    with pytest.raises(ValueError):
        parse_port_spec("100-50")


def test_empty_rejected():
    with pytest.raises(ValueError):
        parse_port_spec("")


def test_service_names():
    assert service_name(22) == "ssh"
    assert service_name(443) == "https"
    assert service_name(49999) == "unknown"
