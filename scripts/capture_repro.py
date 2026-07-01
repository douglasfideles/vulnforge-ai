#!/usr/bin/env python
"""Captura a saida REAL da reproducao e gera 'prints' estilo terminal (PNG).

Roda os comandos do teste minimo + pytest, captura stdout/stderr e renderiza
imagens de terminal usadas pela apresentacao (scripts/make_presentation.py).

Uso:  python scripts/capture_repro.py
Saida: docs/img/repro_*.png
Requer: Pillow (vem com fpdf2). Opcional: Docker (para o print do container).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "img"
OUT.mkdir(parents=True, exist_ok=True)

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"

# paleta terminal (github dark-ish)
BG = (13, 17, 23)
BAR = (32, 38, 48)
FG = (201, 209, 217)
DIM = (110, 122, 138)
PROMPT = (54, 211, 153)     # verde
CMD = (224, 230, 240)
COMMENT = (235, 170, 90)    # ambar
OK = (63, 200, 120)         # verde forte
KEY = (88, 166, 255)        # azul

ANSI = re.compile(r"\x1b\[[0-9;]*m")
PROTO = str(ROOT / ".venv" / "bin" / "protoforge")
ENV = {**os.environ, "TERM": "dumb", "NO_COLOR": "1", "COLUMNS": "98"}


def run(cmd: list[str]) -> str:
    p = subprocess.run(cmd, cwd=ROOT, env=ENV, capture_output=True, text=True)
    return ANSI.sub("", (p.stdout + p.stderr)).rstrip("\n")


def wrap(line: str, width: int) -> list[str]:
    if len(line) <= width:
        return [line]
    out, cur = [], line
    while len(cur) > width:
        out.append(cur[:width])
        cur = "  " + cur[width:]
    out.append(cur)
    return out


def color_for(line: str) -> tuple[int, int, int]:
    s = line.lstrip()
    if s.startswith("$"):
        return PROMPT
    if s.startswith("#"):
        return COMMENT
    if re.search(r"\b(passed|CONCLUIDO|SUCESSO|status=dry-run|exit 0|exited with code 0)\b", line):
        return OK
    if "| INFO" in line or "INFO " in line:
        return DIM
    return FG


def render(title: str, lines: list[str], path: Path, width_chars: int = 98) -> None:
    fs = 21
    font = ImageFont.truetype(MONO, fs)
    font_b = ImageFont.truetype(MONO_B, fs)
    bar_font = ImageFont.truetype(MONO_B, 19)
    cw = font.getlength("M")
    lh = int(fs * 1.42)
    pad = 26
    bar_h = 46

    wrapped: list[str] = []
    for ln in lines:
        wrapped.extend(wrap(ln, width_chars) if ln else [""])

    img_w = int(pad * 2 + cw * width_chars)
    img_h = bar_h + pad * 2 + lh * len(wrapped)
    img = Image.new("RGB", (img_w, img_h), BG)
    d = ImageDraw.Draw(img)

    # barra de titulo + bolinhas
    d.rectangle([0, 0, img_w, bar_h], fill=BAR)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([20 + i * 26, bar_h // 2 - 7, 20 + i * 26 + 14, bar_h // 2 + 7], fill=c)
    d.text((img_w // 2, bar_h // 2), title, font=bar_font, fill=DIM, anchor="mm")

    y = bar_h + pad
    for ln in wrapped:
        f = font_b if ln.lstrip().startswith("$") else font
        d.text((pad, y), ln, font=f, fill=color_for(ln))
        y += lh
    img.save(path)
    print(f"  -> {path.relative_to(ROOT)}  ({img.size[0]}x{img.size[1]})")


# ----------------------------------------------------------------- captura
def main() -> None:
    print("Capturando reproducao real...")

    # garante DB limpo para saida consistente
    db = ROOT / "data" / "vulnforge.db"
    if db.exists():
        db.unlink()

    # --- PRINT 1: passos 1-4 ---
    out_import = run([PROTO, "import-vulns", "--file", "data/raw/vulns.json"])
    out_analyze = run([PROTO, "analyze", "--vuln-id", "CVE-2024-0001", "--protocol", "XRCE-DDS"])
    out_gen = run([PROTO, "generate-scenario", "--vuln-id", "CVE-2024-0001",
                   "--out", "scenarios/generated/cve_0001.yaml"])
    out_run = run([PROTO, "run-scenario", "--file",
                   "scenarios/examples/xrce_dds_flooding.yaml", "--dry-run"])
    m = re.search(r"run_id=(\S+)", out_run)
    run_id = m.group(1) if m else ""

    p1 = ["$ protoforge import-vulns --file data/raw/vulns.json", out_import, "",
          "$ protoforge analyze --vuln-id CVE-2024-0001 --protocol XRCE-DDS"]
    # mostra so o miolo do JSON da analise (compacto)
    a = [l for l in out_analyze.splitlines()
         if any(k in l for k in ('INFO', 'protocol', 'likely_attack', 'dataset_label', 'confidence', 'source'))]
    p1 += a
    render("reproducao — analise offline (passos 1-2)", p1, OUT / "repro_1.png")

    # --- PRINT 2: cenario + dry-run + dataset + IDS + relatorio ---
    out_ds = run([PROTO, "build-dataset", "--flows", "data/flows/example.csv",
                  "--label", "flooding", "--out", "data/datasets/out.csv"])
    out_ids = run([PROTO, "train-ids", "--dataset", "data/datasets/example_labeled.csv",
                   "--label-column", "label"])
    out_rep = run([PROTO, "report", "--run-id", run_id]) if run_id else "(run_id ausente)"

    ids_lines = [l for l in out_ids.splitlines()
                 if any(k in l for k in ('INFO', 'best_model', 'rows', 'accuracy', 'f1', '"model"'))]
    p2 = ["$ protoforge generate-scenario --vuln-id CVE-2024-0001 --out .../cve_0001.yaml", out_gen, "",
          "$ protoforge run-scenario --file .../xrce_dds_flooding.yaml --dry-run"]
    p2 += [l for l in out_run.splitlines() if l.startswith("#") or "run_id=" in l]
    p2 += ["",
           "$ protoforge build-dataset --flows data/flows/example.csv --label flooding ...", out_ds, "",
           "$ protoforge train-ids --dataset data/datasets/example_labeled.csv"]
    p2 += ids_lines
    p2 += ["", "$ protoforge report --run-id " + run_id, out_rep]
    render("reproducao — pipeline end-to-end (passos 3-7)", p2, OUT / "repro_2.png")

    # --- PRINT 3: testes ---
    out_tests = run([str(ROOT / ".venv" / "bin" / "pytest"), "-q"])
    t = out_tests.splitlines()
    tail = t[-12:] if len(t) > 12 else t
    render("reproducao — suite de testes (pytest -q)",
           ["$ pytest -q"] + tail, OUT / "repro_3.png")

    # --- PRINT 4: Docker (se disponivel) ---
    if shutil.which("docker"):
        try:
            dout = subprocess.run(
                ["docker", "compose", "up", "--no-build", "--abort-on-container-exit"],
                cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=240)
            txt = ANSI.sub("", dout.stdout + dout.stderr)
            keep = [l for l in txt.splitlines()
                    if any(k in l for k in ("===", "Importadas 4", "run_id=", "f1=",
                                            "CONCLUIDO", "exited with code", "Started", "Created"))]
            subprocess.run(["docker", "compose", "down"], cwd=ROOT, env=ENV,
                           capture_output=True, text=True)
            render("reproducao — pipeline no container (docker compose up)",
                   ["$ docker compose up --build"] + keep[:22], OUT / "repro_4.png")
        except Exception as exc:  # noqa: BLE001
            print(f"  (docker pulado: {exc})")
    else:
        print("  (docker ausente; pulando print do container)")

    # limpa artefato temporario
    for f in ("out.csv", "out.csv.meta.json"):
        p = ROOT / "data" / "datasets" / f
        if p.exists():
            p.unlink()
    print("OK.")


if __name__ == "__main__":
    main()
