"""Tests for safety guard."""

import pytest

from vulnforge.traffic.safety import UnsafeTargetError, validate_target


def test_loopback_allowed():
    assert validate_target("127.0.0.1") == "127.0.0.1"


def test_private_allowed():
    assert validate_target("192.168.1.1") == "192.168.1.1"


def test_public_rejected():
    with pytest.raises(UnsafeTargetError):
        validate_target("8.8.8.8")


def test_hostname_public_rejected():
    with pytest.raises(UnsafeTargetError):
        validate_target("google.com")


def test_empty_rejected():
    with pytest.raises(UnsafeTargetError):
        validate_target("")
