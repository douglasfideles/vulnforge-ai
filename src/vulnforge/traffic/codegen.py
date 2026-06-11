"""Geracao e validacao (sandbox) de codigo de ataque sintetizado pela LLM.

A LLM sintetiza APENAS o corpo de `build_payload(seq, rng, urandom) -> bytes` -
ou seja, a logica de criacao do payload especifica do CVE. A parte de rede e a
guarda de seguranca NAO sao geradas: ficam num template fixo e confiavel.

O corpo passa por um validador AST (whitelist) antes de ser escrito/executado:
sem imports, sem atributos (exceto metodos de `rng`), apenas builtins seguros,
sem `while`, constantes limitadas. Isso impede I/O, exec, acesso a globais, etc.
"""

from __future__ import annotations

import ast
import os
import random
import textwrap
from pathlib import Path

# Builtins liberados dentro do corpo gerado.
ALLOWED_BUILTINS = frozenset({
    "bytes", "bytearray", "int", "float", "bool", "len", "range", "min", "max",
    "abs", "list", "tuple", "sum", "ord", "chr", "bin", "hex", "reversed", "enumerate",
})
# Metodos liberados no objeto `rng` (random.Random).
ALLOWED_RNG_METHODS = frozenset({
    "randrange", "randint", "random", "getrandbits", "choice", "randbytes",
})
# Nomes injetados disponiveis no escopo.
# Nomes injetados por tipo de funcao gerada.
PAYLOAD_ARGS = ("seq", "rng", "urandom")             # build_payload(seq, rng, urandom)
MUTATOR_ARGS = ("baseline", "seq", "rng", "urandom")  # mutate(baseline, seq, rng, urandom)
INJECTED_NAMES = frozenset(PAYLOAD_ARGS)              # compat retro

MAX_CONST_INT = 1_000_000  # evita alocacoes/loops gigantes


class CodeValidationError(ValueError):
    """Codigo sintetizado violou as regras de seguranca do sandbox."""


_FORBIDDEN_NODES = (
    ast.Import, ast.ImportFrom, ast.While, ast.With, ast.AsyncWith, ast.Try,
    ast.Raise, ast.Global, ast.Nonlocal, ast.ClassDef, ast.FunctionDef,
    ast.AsyncFunctionDef, ast.Lambda, ast.Await, ast.Yield, ast.YieldFrom,
    ast.Delete, ast.Starred,
)


def _collect_assigned(tree: ast.AST) -> set[str]:
    """Nomes que recebem atribuicao em qualquer ponto (alvos Store)."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
    return names


def _validate(code: str, arg_names: tuple[str, ...]) -> None:
    """Valida o corpo de uma funcao gerada com os args dados. Mesmo sandbox p/ todos."""
    if not code or not code.strip():
        raise CodeValidationError("Codigo gerado vazio.")

    wrapped = f"def _f({', '.join(arg_names)}):\n" + textwrap.indent(textwrap.dedent(code), "    ")
    try:
        tree = ast.parse(wrapped)
    except SyntaxError as exc:
        raise CodeValidationError(f"Sintaxe invalida: {exc}") from exc

    func = tree.body[0]
    injected = set(arg_names)
    assigned = _collect_assigned(func) | injected
    has_return = False

    for node in ast.walk(func):
        if node is func:
            continue  # o proprio wrapper def _f(...) nao conta
        if isinstance(node, _FORBIDDEN_NODES):
            raise CodeValidationError(f"Construcao proibida: {type(node).__name__}")

        if isinstance(node, ast.Attribute):
            value = node.value
            if not (isinstance(value, ast.Name) and value.id == "rng"
                    and node.attr in ALLOWED_RNG_METHODS):
                raise CodeValidationError(
                    f"Acesso a atributo proibido: .{node.attr} "
                    "(somente metodos de rng sao permitidos)"
                )

        if isinstance(node, ast.Call):
            func_node = node.func
            if isinstance(func_node, ast.Name):
                if func_node.id not in ALLOWED_BUILTINS and func_node.id not in injected:
                    raise CodeValidationError(f"Chamada nao permitida: {func_node.id}()")
            elif isinstance(func_node, ast.Attribute):
                pass  # ja validado acima (apenas rng.metodo)
            else:
                raise CodeValidationError("Chamada com alvo dinamico nao permitida.")

        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id not in assigned and node.id not in ALLOWED_BUILTINS:
                raise CodeValidationError(f"Nome nao permitido: {node.id}")

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow):
            raise CodeValidationError("Operador ** nao permitido (risco de alocacao).")

        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            if abs(node.value) > MAX_CONST_INT:
                raise CodeValidationError(
                    f"Constante inteira muito grande: {node.value} (max {MAX_CONST_INT})."
                )

        if isinstance(node, ast.Return) and node.value is not None:
            has_return = True

    if not has_return:
        raise CodeValidationError("O codigo deve ter um `return` de bytes.")


def validate_payload_code(code: str) -> None:
    """Valida o corpo de build_payload(seq, rng, urandom)."""
    _validate(code, PAYLOAD_ARGS)


def validate_mutator_code(code: str) -> None:
    """Valida o corpo de mutate(baseline, seq, rng, urandom)."""
    _validate(code, MUTATOR_ARGS)


def _compile(code: str, name: str, arg_names: tuple[str, ...]):
    wrapped = f"def {name}({', '.join(arg_names)}):\n" + textwrap.indent(
        textwrap.dedent(code), "    "
    )
    namespace: dict = {}
    exec(compile(wrapped, f"<synth_{name}>", "exec"), {"__builtins__": _safe_builtins()}, namespace)
    return namespace[name]


def compile_payload(code: str):
    """Valida, compila e retorna build_payload(seq, rng, urandom)."""
    validate_payload_code(code)
    return _compile(code, "build_payload", PAYLOAD_ARGS)


def compile_mutator(code: str):
    """Valida, compila e retorna mutate(baseline, seq, rng, urandom)."""
    validate_mutator_code(code)
    return _compile(code, "mutate", MUTATOR_ARGS)


def self_test_mutator(code: str, baseline: bytes | None = None,
                      samples: int = 6, max_bytes: int = 65507) -> list[int]:
    """Executa o mutator sobre um baseline de exemplo e valida tipo/tamanho."""
    fn = compile_mutator(code)
    rng = random.Random(1234)
    base = baseline if baseline is not None else bytes([0x80, 0x00, 0x00, 0x00]) + b"baseline"
    sizes: list[int] = []
    for seq in range(samples):
        out = fn(base, seq, rng, os.urandom)
        if not isinstance(out, (bytes, bytearray)):
            raise CodeValidationError(f"mutate retornou {type(out).__name__}, esperado bytes.")
        if len(out) == 0:
            raise CodeValidationError("mutate retornou payload vazio.")
        if len(out) > max_bytes:
            raise CodeValidationError(f"Payload de {len(out)} bytes excede o maximo de {max_bytes}.")
        sizes.append(len(out))
    return sizes


def _safe_builtins() -> dict:
    import builtins

    return {name: getattr(builtins, name) for name in ALLOWED_BUILTINS}


def self_test(code: str, samples: int = 6, max_bytes: int = 65507) -> list[int]:
    """Executa o payload algumas vezes e valida tipo/tamanho. Retorna tamanhos."""
    fn = compile_payload(code)
    rng = random.Random(1234)
    sizes: list[int] = []
    for seq in range(samples):
        out = fn(seq, rng, os.urandom)
        if not isinstance(out, (bytes, bytearray)):
            raise CodeValidationError(
                f"build_payload retornou {type(out).__name__}, esperado bytes."
            )
        if len(out) == 0:
            raise CodeValidationError("build_payload retornou payload vazio.")
        if len(out) > max_bytes:
            raise CodeValidationError(
                f"Payload de {len(out)} bytes excede o maximo de {max_bytes}."
            )
        sizes.append(len(out))
    return sizes


_MODULE_TEMPLATE = '''#!/usr/bin/env python3
"""Ataque SINTETIZADO por VulnForge AI - {scenario_id}
Protocolo: {protocol} | Estrategia: {strategy} | Fonte: {source}

{rationale}

ATENCAO: codigo gerado automaticamente para validacao academica em laboratorio
isolado. A guarda de seguranca restringe o alvo a IP privado/loopback.
Revise antes de executar. Gerado por: {source}.
"""
from __future__ import annotations

import os
import random

from vulnforge.traffic.attacks.common import run_and_report, send_loop, synth_parser

_SEED = {seed}


def build_payload(seq, rng, urandom):
{body}


def main(argv=None):
    parser = synth_parser(
        {description!r}, port={port}, transport={transport!r},
        duration={duration}, rate={rate},
    )
    args = parser.parse_args(argv)
    rng = random.Random(_SEED)

    def factory(seq):
        out = build_payload(seq, rng, os.urandom)
        if not isinstance(out, (bytes, bytearray)):
            raise TypeError("build_payload deve retornar bytes")
        return bytes(out[:65507])

    sent = send_loop(args.transport, args.target, args.port, args.duration, args.rate, factory)
    run_and_report({label!r}, sent, args.target, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def render_attack_module(
    *, scenario_id: str, protocol: str, strategy: str, source: str, rationale: str,
    payload_code: str, port: int, transport: str, duration: float, rate: float,
    label: str, seed: int = 1337,
) -> str:
    """Renderiza o modulo Python do ataque sintetizado (apos validacao)."""
    validate_payload_code(payload_code)
    body = textwrap.indent(textwrap.dedent(payload_code).strip("\n"), "    ")
    return _MODULE_TEMPLATE.format(
        scenario_id=scenario_id, protocol=protocol, strategy=strategy, source=source,
        rationale=rationale.strip() or "(sem racional fornecido)", body=body,
        description=f"Ataque sintetizado {strategy} contra {protocol} ({scenario_id})",
        port=port, transport=transport, duration=duration, rate=rate, label=label, seed=seed,
    )


def write_attack_module(content: str, scenario_id: str, out_dir: str | Path) -> Path:
    """Escreve o modulo gerado em <out_dir>/<scenario_id>.py."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{scenario_id}.py"
    path.write_text(content, encoding="utf-8")
    return path


_MUTATOR_TEMPLATE = '''#!/usr/bin/env python3
"""Ataque SINTETIZADO (protocolo-ancorado) por VulnForge AI - {scenario_id}
Protocolo: {protocol} | Estrategia: {strategy} | Fonte: {source}

{rationale}

A mensagem-BASE e produzida pelo plugin REAL do protocolo (framing valido); a funcao
mutate() abaixo (gerada e validada em sandbox) aplica a transformacao maliciosa.
Uso EXCLUSIVO em laboratorio isolado (alvo privado/loopback).
"""
from __future__ import annotations

import os
import random

from vulnforge.protocols import registry
from vulnforge.traffic.attacks.common import run_and_report, send_loop, synth_parser

_SEED = {seed}
_PLUGIN = registry.get({protocol!r})


def mutate(baseline, seq, rng, urandom):
{body}


def main(argv=None):
    parser = synth_parser(
        {description!r}, port={port}, transport={transport!r},
        duration={duration}, rate={rate},
    )
    args = parser.parse_args(argv)
    rng = random.Random(_SEED)

    def factory(seq):
        base = _PLUGIN.baseline_message(seq) if _PLUGIN is not None else b""
        out = mutate(base, seq, rng, os.urandom)
        if not isinstance(out, (bytes, bytearray)):
            raise TypeError("mutate deve retornar bytes")
        return bytes(out[:65507])

    sent = send_loop(args.transport, args.target, args.port, args.duration, args.rate, factory)
    run_and_report({label!r}, sent, args.target, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def render_mutator_module(
    *, scenario_id: str, protocol: str, strategy: str, source: str, rationale: str,
    mutator_code: str, port: int, transport: str, duration: float, rate: float,
    label: str, seed: int = 1337,
) -> str:
    """Renderiza o modulo protocolo-ancorado (baseline real + mutate sandboxed)."""
    validate_mutator_code(mutator_code)
    body = textwrap.indent(textwrap.dedent(mutator_code).strip("\n"), "    ")
    return _MUTATOR_TEMPLATE.format(
        scenario_id=scenario_id, protocol=protocol, strategy=strategy, source=source,
        rationale=rationale.strip() or "(sem racional fornecido)", body=body,
        description=f"Ataque {strategy} (protocolo-ancorado) contra {protocol} ({scenario_id})",
        port=port, transport=transport, duration=duration, rate=rate, label=label, seed=seed,
    )
