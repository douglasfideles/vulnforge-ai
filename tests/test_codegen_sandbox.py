"""Tests for the AST codegen sandbox."""

import pytest

from vulnforge.traffic.codegen import (
    CodeValidationError,
    compile_mutator,
    validate_and_compile,
    validate_body,
)


def test_valid_identity_mutator():
    code = "return baseline"
    mutator = validate_and_compile(code, b"base")
    assert mutator(b"base", 0, __import__("random").Random(1), bytes) == b"base"


def test_valid_rng_mutator():
    code = "return baseline + rng.randbytes(4)"
    mutator = validate_and_compile(code, b"base")
    result = mutator(b"base", 0, __import__("random").Random(1), bytes)
    assert len(result) == 8


def test_rejects_import():
    with pytest.raises(CodeValidationError):
        validate_body("import os\nreturn baseline")


def test_rejects_open():
    with pytest.raises(CodeValidationError):
        validate_body("return open('/etc/passwd').read()")


def test_rejects_eval():
    with pytest.raises(CodeValidationError):
        validate_body("return eval('1+1')")


def test_rejects_attr_access():
    with pytest.raises(CodeValidationError):
        validate_body("return baseline.upper()")


def test_rejects_while():
    with pytest.raises(CodeValidationError):
        validate_body("while True:\n    return baseline")


def test_rejects_power():
    with pytest.raises(CodeValidationError):
        validate_body("return baseline + bytes([2**100])")


def test_rejects_large_constant():
    with pytest.raises(CodeValidationError):
        validate_body("return baseline + bytes([2000000])")


def test_rejects_missing_return():
    with pytest.raises(CodeValidationError):
        validate_body("x = baseline")
