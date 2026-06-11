"""Testes do sandbox para a funcao mutate(baseline, seq, rng, urandom)."""

import pytest

from vulnforge.traffic.codegen import (
    CodeValidationError,
    compile_mutator,
    self_test_mutator,
    validate_mutator_code,
)

SAFE_IDENTITY = "return baseline\n"
SAFE_MUTATE = (
    "b = bytearray(baseline)\n"
    "if len(b) > 1:\n"
    "    b[0] = b[0] ^ 0xFF\n"
    "    b[1] = rng.randrange(256)\n"
    "return bytes(b) + urandom(4)\n"
)


def test_baseline_is_an_allowed_name():
    validate_mutator_code(SAFE_IDENTITY)
    validate_mutator_code(SAFE_MUTATE)


def test_mutator_runs_on_real_baseline():
    fn = compile_mutator(SAFE_MUTATE)
    import random

    out = fn(b"\x80\x00\x00\x00abc", 0, random.Random(0), __import__("os").urandom)
    assert isinstance(out, (bytes, bytearray)) and len(out) > 0


def test_identity_preserves_baseline():
    sizes = self_test_mutator(SAFE_IDENTITY, baseline=b"hello-baseline")
    assert all(s == len("hello-baseline") for s in sizes)


@pytest.mark.parametrize("code", [
    "import os\nreturn baseline\n",                 # import proibido
    "return open('x').read()\n",                     # open + atributo
    "return baseline.decode()\n",                    # atributo nao-rng
    "while True:\n    pass\nreturn baseline\n",       # while
    "return baseline * 10000000\n",                   # constante gigante
    "return eval('baseline')\n",                      # eval
])
def test_dangerous_mutators_rejected(code):
    with pytest.raises(CodeValidationError):
        validate_mutator_code(code)
        self_test_mutator(code)


def test_empty_return_rejected():
    with pytest.raises(CodeValidationError):
        self_test_mutator("return baseline[:0]\n")  # vazio
