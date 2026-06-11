"""Testes do sandbox de validacao de codigo de ataque sintetizado."""

import pytest

from vulnforge.traffic.codegen import (
    CodeValidationError,
    self_test,
    validate_payload_code,
)

SAFE = "return urandom(64) + bytes([seq & 0xFF])\n"
SAFE_RNG = (
    "body = bytearray(urandom(32))\n"
    "body[0] = rng.randrange(256)\n"
    "return bytes(body)\n"
)


def test_safe_code_passes():
    validate_payload_code(SAFE)
    validate_payload_code(SAFE_RNG)
    sizes = self_test(SAFE)
    assert all(s > 0 for s in sizes)


@pytest.mark.parametrize("code", [
    "import os\nreturn os.urandom(10)\n",            # import proibido
    "return open('/etc/passwd').read().encode()\n",  # open + atributo
    "return eval('1')\n",                            # eval
    "x = ().__class__\nreturn b''\n",                # atributo dunder
    "while True:\n    pass\nreturn b''\n",           # while
    "return b'A' * 10000000\n",                       # constante gigante
    "return 2 ** 64\n",                               # operador **
    "return urandom(__import__('os').getpid())\n",   # __import__
    "return b''\n",                                   # payload vazio (self_test)
    "seq + 1\n",                                       # sem return
])
def test_malicious_or_invalid_code_is_rejected(code):
    with pytest.raises(CodeValidationError):
        # validacao estatica OU self-test devem barrar
        validate_payload_code(code)
        self_test(code)


def test_non_bytes_return_is_rejected():
    with pytest.raises(CodeValidationError):
        self_test("return seq + 1\n")
