"""Tests for protocol plugin registry."""

import pytest

from vulnforge.protocols import registry
from vulnforge.protocols.base import ProtocolPlugin


def test_builtin_plugins():
    plugins = registry.available()
    assert "xrce-dds" in plugins
    assert "zenoh" in plugins
    assert "dds" in plugins


def test_get_normalized():
    cls = registry.get("XRCE_DDS")
    assert cls.name == "XRCE-DDS"
    assert cls.default_port == 8888
    assert cls.transport == "udp"


def test_unknown_plugin():
    with pytest.raises(KeyError):
        registry.get("not-a-protocol")


def test_xrce_baseline():
    cls = registry.get("xrce-dds")
    plugin = cls()
    msg = plugin.baseline_message(0)
    assert msg.startswith(b"XRCE")


def test_dds_baseline():
    cls = registry.get("dds")
    plugin = cls()
    msg = plugin.baseline_message(0)
    assert msg.startswith(b"RTPS")


def test_capture_filter():
    cls = registry.get("zenoh")
    plugin = cls()
    assert plugin.capture_filter() == "tcp port 7447"
