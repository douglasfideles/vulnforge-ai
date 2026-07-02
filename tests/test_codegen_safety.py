import socket

import pytest

from vulnforge.traffic.codegen import CodeValidationError, compile_mutator, self_test, validate_mutator
from vulnforge.traffic.safety import UnsafeTargetError, resolve_safe_target


@pytest.mark.parametrize(
    "body",
    [
        "import os\nreturn baseline",
        "return open('/tmp/x')",
        "return eval('baseline')",
        "return rng.seed(2) or baseline",
        "return 2 ** 8 and baseline",
        "while True:\n    return baseline",
        "return baseline + b'x' * 1000001",
        "return baseline.decode()",
        "return missing",
    ],
)
def test_sandbox_rejects_forbidden_code(body):
    with pytest.raises(CodeValidationError):
        validate_mutator(body)


@pytest.mark.parametrize(
    "body",
    [
        "return baseline",
        "return baseline + b'A' * rng.randrange(1, 10)",
        "return bytes([baseline[0] ^ 255]) + baseline[1:] + urandom(8)",
    ],
)
def test_sandbox_accepts_bounded_mutators(body):
    self_test(body, b"XRCE")
    assert callable(compile_mutator(body))


def test_self_test_rejects_empty():
    with pytest.raises(CodeValidationError, match="non-empty"):
        self_test("return b''", b"XRCE")


@pytest.mark.parametrize("target", ["127.0.0.1", "10.1.2.3", "192.168.1.5", "169.254.1.2"])
def test_safety_accepts_lab_addresses(target):
    assert resolve_safe_target(target)


@pytest.mark.parametrize("address", ["8.8.8.8", "192.0.2.10", "100.64.0.1"])
def test_safety_rejects_public_or_non_lab(monkeypatch, address):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))])
    with pytest.raises(UnsafeTargetError, match="public"):
        resolve_safe_target("example.test")


def test_safety_rejects_unresolved(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.gaierror("no host")
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(UnsafeTargetError, match="resolved"):
        resolve_safe_target("missing.test")
