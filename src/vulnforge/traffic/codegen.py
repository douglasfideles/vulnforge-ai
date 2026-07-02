from __future__ import annotations

import ast
import random
import types

MAX_CONST_INT = 1_000_000
MAX_PAYLOAD = 65507
ALLOWED_BUILTINS = {
    "bytes": bytes, "bytearray": bytearray, "int": int, "float": float, "bool": bool,
    "len": len, "range": range, "min": min, "max": max, "abs": abs, "list": list,
    "tuple": tuple, "sum": sum, "ord": ord, "chr": chr, "bin": bin, "hex": hex,
    "reversed": reversed, "enumerate": enumerate,
}
RNG_METHODS = {"randrange", "randint", "random", "getrandbits", "choice", "randbytes"}
FORBIDDEN = (
    ast.Import, ast.ImportFrom, ast.While, ast.With, ast.AsyncWith, ast.Try, ast.Raise,
    ast.Global, ast.Nonlocal, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef,
    ast.Lambda, ast.Await, ast.Yield, ast.YieldFrom, ast.Delete, ast.Starred,
)


class CodeValidationError(ValueError):
    pass


def _wrap(body: str) -> str:
    return "def mutate(baseline, seq, rng, urandom):\n" + "\n".join(f"    {line}" for line in body.splitlines())


def validate_mutator(body: str) -> ast.Module:
    try:
        tree = ast.parse(_wrap(body))
    except (SyntaxError, IndentationError) as exc:
        raise CodeValidationError(f"Invalid mutator syntax: {exc}") from None
    function = tree.body[0]
    if not any(isinstance(node, ast.Return) and node.value is not None for node in ast.walk(function)):
        raise CodeValidationError("Mutator must return a value")
    defined = {"baseline", "seq", "rng", "urandom", *ALLOWED_BUILTINS}
    for node in ast.walk(function):
        if node is function:
            continue
        if isinstance(node, FORBIDDEN):
            raise CodeValidationError(f"Forbidden syntax: {type(node).__name__}")
        if isinstance(node, ast.Pow):
            raise CodeValidationError("Power operator is forbidden")
        if isinstance(node, ast.Constant) and isinstance(node.value, int) and abs(node.value) > MAX_CONST_INT:
            raise CodeValidationError("Integer constant exceeds 1000000")
        if isinstance(node, ast.Attribute):
            if not (isinstance(node.value, ast.Name) and node.value.id == "rng" and node.attr in RNG_METHODS):
                raise CodeValidationError("Only whitelisted rng methods may be accessed")
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id not in {*ALLOWED_BUILTINS, "urandom"}:
                    raise CodeValidationError(f"Call to {node.func.id!r} is forbidden")
            elif not isinstance(node.func, ast.Attribute):
                raise CodeValidationError("Dynamic calls are forbidden")
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    defined.add(target.id)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id not in defined:
            raise CodeValidationError(f"Undefined name: {node.id}")
    return tree


def compile_mutator(body: str):
    tree = validate_mutator(body)
    namespace = {"__builtins__": ALLOWED_BUILTINS}
    exec(compile(tree, "<validated-mutator>", "exec"), namespace)
    return namespace["mutate"]


def self_test(body: str, baseline: bytes = b"\x00") -> None:
    mutator = compile_mutator(body)
    rng = random.Random(1337)
    for seq in range(6):
        output = mutator(baseline, seq, rng, lambda n: bytes([seq & 0xFF]) * n)
        if not isinstance(output, (bytes, bytearray)) or not output or len(output) > MAX_PAYLOAD:
            raise CodeValidationError("Mutator output must be non-empty bytes of at most 65507 bytes")

