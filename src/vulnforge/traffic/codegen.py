"""AST-based sandbox for LLM/offline generated mutator code."""

from __future__ import annotations

import ast
import builtins
import random
import re
from typing import Any, Callable

MAX_CONST_INT = 1_000_000

ALLOWED_BUILTINS = {
    "bytes",
    "bytearray",
    "int",
    "float",
    "bool",
    "len",
    "range",
    "min",
    "max",
    "abs",
    "list",
    "tuple",
    "sum",
    "ord",
    "chr",
    "bin",
    "hex",
    "reversed",
    "enumerate",
}

ALLOWED_RNG_METHODS = {
    "randrange",
    "randint",
    "random",
    "getrandbits",
    "choice",
    "randbytes",
}

FORBIDDEN_NODES = (
    ast.Import,
    ast.ImportFrom,
    ast.While,
    ast.With,
    ast.AsyncWith,
    ast.Try,
    ast.Raise,
    ast.Global,
    ast.Nonlocal,
    ast.ClassDef,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.Lambda,
    ast.Await,
    ast.Yield,
    ast.YieldFrom,
    ast.Delete,
    ast.Starred,
)

INJECTED_NAMES = {"baseline", "seq", "rng", "urandom"}


class CodeValidationError(ValueError):
    """Raised when generated code violates the sandbox policy."""


class _SandboxValidator(ast.NodeVisitor):
    def __init__(self) -> None:
        self.has_return = False
        self.defined: set[str] = set()

    def visit_Return(self, node: ast.Return) -> None:
        self.has_return = True
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        # Allow simple for loops over range/enumerate only.
        self._check_iter(node.iter)
        for stmt in node.body + node.orelse:
            self.visit(stmt)

    def _check_iter(self, node: ast.AST) -> None:
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                if func.id not in {"range", "enumerate", "reversed"}:
                    raise CodeValidationError(f"Loop iterator '{func.id}' nao permitido")
            else:
                raise CodeValidationError("Loop iterator deve ser uma funcao permitida")
        else:
            raise CodeValidationError("Loop deve iterar sobre range/enumerate/reversed")

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        for stmt in node.body + node.orelse:
            self.visit(stmt)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.defined.add(target.id)
        self.visit(node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.target)
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value:
            self.visit(node.value)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name):
            if func.id not in ALLOWED_BUILTINS and func.id not in INJECTED_NAMES and func.id not in self.defined:
                raise CodeValidationError(f"Chamada para '{func.id}' nao permitida")
        elif isinstance(func, ast.Attribute):
            if not (isinstance(func.value, ast.Name) and func.value.id == "rng"):
                raise CodeValidationError("Acesso a atributo permitido apenas em rng.*")
            if func.attr not in ALLOWED_RNG_METHODS:
                raise CodeValidationError(f"Metodo rng.{func.attr} nao permitido")
        else:
            raise CodeValidationError("Chamadas dinamicas nao permitidas")
        for arg in node.args:
            self.visit(arg)
        for kw in node.keywords:
            self.visit(kw.value)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if not (isinstance(node.value, ast.Name) and node.value.id == "rng"):
            raise CodeValidationError("Acesso a atributo permitido apenas em rng.*")
        if node.attr not in ALLOWED_RNG_METHODS:
            raise CodeValidationError(f"Atributo rng.{node.attr} nao permitido")

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            if node.id not in ALLOWED_BUILTINS and node.id not in INJECTED_NAMES and node.id not in self.defined:
                raise CodeValidationError(f"Nome nao definido: {node.id}")

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, int) and abs(node.value) > MAX_CONST_INT:
            raise CodeValidationError(f"Constante inteira {node.value} excede limite")

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if isinstance(node.op, ast.Pow):
            raise CodeValidationError("Operador '**' nao permitido")
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        self.generic_visit(node)

    def generic_visit(self, node: ast.AST) -> None:
        if isinstance(node, FORBIDDEN_NODES):
            raise CodeValidationError(f"Construcao '{type(node).__name__}' nao permitida")
        super().generic_visit(node)


def validate_body(body_code: str, signature: str = "mutate(baseline, seq, rng, urandom)") -> ast.Module:
    """Validate a mutator body against the AST whitelist."""
    code = f"def {signature}:\n" + "\n".join(f"    {line}" for line in body_code.splitlines())
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        raise CodeValidationError(f"Sintaxe invalida: {exc}") from exc

    func = tree.body[0]
    if not isinstance(func, ast.FunctionDef):
        raise CodeValidationError("Codigo deve ser um corpo de funcao")

    validator = _SandboxValidator()
    for stmt in func.body:
        validator.visit(stmt)
    if not validator.has_return:
        raise CodeValidationError("Funcao deve conter 'return'")
    return tree


def compile_mutator(tree: ast.Module, signature: str = "mutate(baseline, seq, rng, urandom)") -> Callable[..., bytes]:
    """Compile the validated mutator function with restricted builtins."""
    code = compile(tree, "<generated>", "exec")
    restricted_builtins = {name: getattr(builtins, name) for name in ALLOWED_BUILTINS if hasattr(builtins, name)}
    namespace: dict[str, Any] = {"__builtins__": restricted_builtins}
    exec(code, namespace)  # noqa: S102
    return namespace[signature.split("(")[0]]


def self_test(
    mutator: Callable[..., Any],
    baseline: bytes,
    runs: int = 6,
    max_len: int = 65507,
) -> None:
    """Run the mutator several times and verify outputs are bounded bytes."""
    rng = random.Random(1337)
    for seq in range(runs):
        result = mutator(baseline, seq, rng, rng.randbytes)
        if not isinstance(result, (bytes, bytearray)):
            raise CodeValidationError(f"Retorno nao e bytes na iteracao {seq}: {type(result)}")
        payload = bytes(result)
        if not payload:
            raise CodeValidationError(f"Payload vazio na iteracao {seq}")
        if len(payload) > max_len:
            raise CodeValidationError(f"Payload muito longo na iteracao {seq}: {len(payload)}")


def validate_and_compile(
    body_code: str,
    baseline: bytes,
    signature: str = "mutate(baseline, seq, rng, urandom)",
) -> Callable[..., bytes]:
    """Full pipeline: AST validation, compilation, and self-test."""
    tree = validate_body(body_code, signature=signature)
    mutator = compile_mutator(tree, signature=signature)
    self_test(mutator, baseline)
    return mutator
