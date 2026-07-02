"""Tests for mutator self-test and offline fallback mutators."""

import random

from vulnforge.llm import exploit_synth


def test_offline_mutators_pass_sandbox():
    baseline = b"BASELINE"
    rng = random.Random(1337)
    for code in exploit_synth.OFFLINE_MUTATORS.values():
        mutator = exploit_synth._build_mutator(code, baseline)[0]
        for seq in range(6):
            result = mutator(baseline, seq, rng, rng.randbytes)
            assert isinstance(result, bytes)
            assert len(result) > 0
            assert len(result) <= 65507


def test_oversized_mutator_length():
    baseline = b"X"
    code = exploit_synth.OFFLINE_MUTATORS["oversized_payload"]
    mutator = exploit_synth._build_mutator(code, baseline)[0]
    result = mutator(baseline, 0, random.Random(1), random.Random(1).randbytes)
    assert len(result) == 60001
