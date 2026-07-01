#!/usr/bin/env python
"""Gera a apresentacao (PDF) de REVISAO da ferramenta VulnForge AI.

Uso:  python scripts/make_presentation.py [saida.pdf]
Requer: fpdf2  (pip install fpdf2). Fontes DejaVu (Unicode) do sistema.
"""
from __future__ import annotations

import sys
from pathlib import Path

from fpdf import FPDF

# ---------------------------------------------------------------- paleta / layout
NAVY = (24, 35, 61)        # fundo escuro / titulos
NAVY2 = (31, 45, 78)       # variacao
TEAL = (38, 166, 154)      # acento primario
AMBER = (235, 152, 52)     # acento secundario
LIGHT = (240, 243, 248)    # caixa clara
GRAY = (90, 100, 115)      # texto secundario
DARK = (33, 41, 54)        # texto corpo
WHITE = (255, 255, 255)
GREEN = (39, 158, 96)
RED = (200, 70, 70)

W, H = 297.0, 210.0        # A4 paisagem (mm)
ML, MR = 20.0, 20.0        # margens laterais
CONTENT_W = W - ML - MR

FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")


class Deck(FPDF):
    def __init__(self) -> None:
        super().__init__(orientation="L", unit="mm", format="A4")
        self.set_auto_page_break(False)
        self.add_font("DJ", "", str(FONT_DIR / "DejaVuSans.ttf"))
        self.add_font("DJ", "B", str(FONT_DIR / "DejaVuSans-Bold.ttf"))
        self.add_font("MONO", "", str(FONT_DIR / "DejaVuSansMono.ttf"))
        self.page_no_total = 0

    # -- primitivos ---------------------------------------------------------
    def box(self, x, y, w, h, color, radius=0.0):
        self.set_fill_color(*color)
        try:
            self.rect(x, y, w, h, style="F",
                      round_corners=bool(radius), corner_radius=radius)
        except TypeError:
            self.rect(x, y, w, h, style="F")

    def text_at(self, x, y, txt, size, color=DARK, bold=False, font="DJ"):
        self.set_xy(x, y)
        self.set_font(font, "B" if bold else "", size)
        self.set_text_color(*color)
        self.cell(0, size * 0.45, txt)

    def footer_band(self, idx, total, label):
        self.box(0, H - 9, W, 9, NAVY)
        self.set_text_color(180, 190, 205)
        self.set_font("DJ", "", 8)
        self.set_xy(ML, H - 7.6)
        self.cell(0, 4, "VulnForge AI · Revisão de Artefato de Pesquisa")
        self.set_xy(W - MR - 30, H - 7.6)
        self.cell(30, 4, f"{label}   ·   {idx}/{total}", align="R")


def bullets(pdf: Deck, items, x, y, w, gap=2.2, lh=5.0):
    """items: lista de (nivel, texto, cor_marcador|None)."""
    pdf.set_text_color(*DARK)
    for level, txt, mk in items:
        indent = 0 if level == 0 else 7
        msize = 3.0 if level == 0 else 2.0
        color = mk or (TEAL if level == 0 else AMBER)
        fsize = 11 if level == 0 else 9.5
        # marcador (quadrado)
        pdf.set_fill_color(*color)
        pdf.rect(x + indent, y + 1.4, msize, msize, style="F")
        # texto
        pdf.set_xy(x + indent + msize + 2.5, y - 0.3)
        pdf.set_font("DJ", "B" if level == 0 else "", fsize)
        pdf.set_text_color(*(DARK if level == 0 else GRAY))
        pdf.multi_cell(w - indent - msize - 2.5, lh, txt, align="L")
        y = pdf.get_y() + gap
    return y


def header(pdf: Deck, kicker, title):
    pdf.box(0, 0, W, 30, NAVY)
    pdf.box(0, 30, W, 1.6, TEAL)
    pdf.text_at(ML, 8.5, kicker.upper(), 9, color=TEAL, bold=True)
    pdf.text_at(ML, 15.5, title, 19, color=WHITE, bold=True)


# ============================================================ SLIDES
def slide_cover(pdf: Deck):
    pdf.add_page()
    pdf.box(0, 0, W, H, NAVY)
    pdf.box(0, 0, 8, H, TEAL)
    pdf.box(0, H - 4, W, 4, AMBER)
    pdf.text_at(ML, 42, "REVISÃO DE ARTEFATO DE PESQUISA", 11, color=TEAL, bold=True)
    pdf.set_xy(ML, 58)
    pdf.set_font("DJ", "B", 40)
    pdf.set_text_color(*WHITE)
    pdf.cell(0, 18, "VulnForge AI")
    pdf.set_xy(ML, 82)
    pdf.set_font("DJ", "", 15)
    pdf.set_text_color(200, 210, 222)
    pdf.multi_cell(CONTENT_W - 30, 7,
                   "Da vulnerabilidade ao IDS: geração reprodutível de ataques validados "
                   "e datasets rotulados para protocolos IoT (DDS · XRCE-DDS · Zenoh)", align="L")
    # rótulo de avaliação
    pdf.box(ML, 120, 80, 16, TEAL, radius=2)
    pdf.text_at(ML + 6, 125.5, "Veredito: APROVADO (com ressalvas)", 10.5, color=WHITE, bold=True)
    # rodapé de identificação
    pdf.text_at(ML, 168, "Revisor:  Douglas Rodrigues Fideles", 11, color=WHITE, bold=True)
    pdf.text_at(ML, 176, "Tipo de artefato:  Software (CLI + API)   ·   Licença: GPL-3.0-or-later", 10, color=(170, 182, 198))
    pdf.text_at(ML, 184, "Contexto: selos de artefato SBRC — Disponível · Funcional · Sustentável · Reprodutível", 10, color=(170, 182, 198))


def slide_resumo(pdf: Deck, idx, total):
    header(pdf, "1 · Resumo executivo", "O que é a ferramenta")
    y = bullets(pdf, [
        (0, "Ferramenta de pesquisa acadêmica em cibersegurança de protocolos IoT emergentes (DDS, XRCE-DDS, Zenoh).", None),
        (0, "Automatiza o pipeline completo: CVE → análise → cenário → execução+captura → dataset rotulado → IDS baseline → relatório.", None),
        (0, "CLI `protoforge` + API FastAPI opcional. Python puro, sem GPU, offline por padrão e seguro por padrão (dry-run).", None),
        (1, "Resolve uma lacuna real: a quase inexistência de datasets de ataque rotulados para esses protocolos.", None),
        (1, "Pode usar LLM (nuvem/local) ou cair para um motor rule-based 100% offline e determinístico.", None),
    ], ML, 44, CONTENT_W * 0.62, gap=3.2, lh=5.4)
    # caixa lateral "em uma frase"
    bx = ML + CONTENT_W * 0.66
    bw = CONTENT_W * 0.34
    pdf.box(bx, 44, bw, 120, LIGHT, radius=3)
    pdf.box(bx, 44, bw, 10, TEAL, radius=3)
    pdf.text_at(bx + 5, 47.5, "EM UMA FRASE", 9, color=WHITE, bold=True)
    pdf.set_xy(bx + 5, 60)
    pdf.set_font("DJ", "B", 12.5)
    pdf.set_text_color(*NAVY)
    pdf.multi_cell(bw - 10, 6.4,
                   "Converte um CVE de protocolo IoT em tráfego de ataque validado e rotulado "
                   "e num IDS baseline — com guardas de segurança e modo 100% offline.", align="L")
    pdf.footer_band(idx, total, "Resumo")


def slide_problema(pdf: Deck, idx, total):
    header(pdf, "2 · Motivação", "O problema que ela ataca")
    bullets(pdf, [
        (0, "DDS / XRCE-DDS / Zenoh são pub/sub usados em ROS 2, robótica, veículos autônomos e IoT industrial.", None),
        (1, "São críticos, porém sub-representados em datasets públicos de detecção de intrusão.", None),
        (0, "Treinar um IDS exige tráfego de ATAQUE rotulado — que praticamente não existe para esses protocolos.", None),
        (0, "Produzir esse tráfego à mão é caro e exige traduzir a descrição de um CVE em um ataque concreto, executável e válido.", None),
        (1, "Sem ancoragem no protocolo real, o 'ataque' vira ruído aleatório — sem valor científico.", None),
        (0, "VulnForge AI automatiza esse caminho de ponta a ponta, de forma reprodutível e auditável.", None),
    ], ML, 44, CONTENT_W, gap=3.6, lh=5.6)
    pdf.footer_band(idx, total, "Motivação")


def slide_arquitetura(pdf: Deck, idx, total):
    header(pdf, "3 · Arquitetura", "Pipeline de ponta a ponta")
    steps = ["CVE\n(JSON/CSV)", "Análise\nLLM / regras", "Cenário\nYAML", "Execução\n+ captura",
             "Dataset\nrotulado", "IDS\nbaseline", "Relatório\nMarkdown"]
    n = len(steps)
    gapx = 4.0
    bw = (CONTENT_W - gapx * (n - 1)) / n
    y0 = 58
    bh = 26
    for i, s in enumerate(steps):
        x = ML + i * (bw + gapx)
        col = TEAL if i % 2 == 0 else NAVY2
        pdf.box(x, y0, bw, bh, col, radius=2)
        pdf.set_xy(x, y0 + 6)
        pdf.set_font("DJ", "B", 8.6)
        pdf.set_text_color(*WHITE)
        pdf.multi_cell(bw, 5, s, align="C")
        if i < n - 1:
            pdf.text_at(x + bw + 0.4, y0 + bh / 2 - 2, "→", 11, color=AMBER, bold=True)
    pdf.text_at(ML, y0 + bh + 12, "Camadas (src/vulnforge/):", 11, color=NAVY, bold=True)
    bullets(pdf, [
        (1, "vulnerability · llm · protocols · scenarios · traffic · validation · dataset · ids · reports", None),
        (1, "Cada etapa é um módulo isolado e testável; a configuração vive em .env / JSON (não no código).", None),
        (1, "Segurança transversal: dry-run padrão, guarda de IP privado/loopback e sandbox AST do código sintetizado.", None),
    ], ML, y0 + bh + 20, CONTENT_W, gap=2.4, lh=5.2)
    pdf.footer_band(idx, total, "Arquitetura")


def slide_cap1(pdf: Deck, idx, total):
    header(pdf, "4 · Capacidades (núcleo)", "Da vuln ao tráfego capturado")
    bullets(pdf, [
        (0, "Ingestão & normalização — importa CVEs (JSON/CSV) para SQLite num modelo Pydantic consistente.", None),
        (0, "Análise da ameaça — produz JSON estruturado (protocolo, tipo de ataque, pré-condições, comportamento esperado).", None),
        (1, "Com chave: LLM em nuvem (OpenRouter) ou local (Ollama/vLLM). Sem chave: rule-based offline e determinístico.", None),
        (0, "Geração de cenário — YAML validado por schema (alvo, ataque, baseline, captura).", None),
        (0, "Execução + captura — orquestra sonda → tcpdump → tráfego normal → ataque → PCAP.", None),
        (1, "5 famílias nativas: flooding · oversized · malformed · fuzz · replay (com baseline benigno).", None),
    ], ML, 44, CONTENT_W, gap=3.0, lh=5.4)
    pdf.footer_band(idx, total, "Capacidades")


def slide_cap2(pdf: Deck, idx, total):
    header(pdf, "5 · Capacidades (avançadas)", "Validade científica e segurança")
    bullets(pdf, [
        (0, "Validade protocolar — cada ataque parte da mensagem-base REAL do protocolo (cookie XRCE, frame Zenoh, header RTPS).", None),
        (1, "Com a lib oficial: sessão válida. Sem ela: degrada e rotula o ataque como 'unvalidated' (honestidade explícita).", None),
        (0, "forge-attack — sintetiza o ataque específico do CVE: o LLM gera só a função mutate() sobre o baseline.", None),
        (1, "Sandbox AST: sem import/IO/exec — só constrói bytes; auto-teste antes de gravar; fallback offline seguro.", None),
        (0, "Harness de validação de efeito — sonda antes → ataque → sonda depois → análise de PCAP → veredito.", None),
        (1, "valid / invalid / inconclusive: só cenários 'valid' viram amostras de ataque no dataset.", None),
        (0, "Dataset rotulado + IDS baseline (RandomForest + LogisticRegression) + relatório Markdown end-to-end.", None),
    ], ML, 44, CONTENT_W, gap=2.5, lh=5.1)
    pdf.footer_band(idx, total, "Capacidades")


def slide_seguranca(pdf: Deck, idx, total):
    header(pdf, "6 · Segurança", "O que impede uso indevido")
    cards = [
        ("Dry-run por padrão", "Só imprime os comandos. Execução real exige --no-dry-run --execute --yes + confirmação."),
        ("Guarda de IP", "traffic/safety.py recusa qualquer alvo que não seja privado/loopback. Sem alvos públicos."),
        ("Sandbox AST", "Código sintetizado não pode importar, fazer IO ou exec — apenas montar bytes de payload."),
        ("Escopo de laboratório", "Uso acadêmico em ambiente isolado, declarado em toda a documentação e nos avisos."),
    ]
    cw = (CONTENT_W - 8) / 2
    ch = 50
    for i, (t, d) in enumerate(cards):
        cx = ML + (i % 2) * (cw + 8)
        cy = 46 + (i // 2) * (ch + 8)
        pdf.box(cx, cy, cw, ch, LIGHT, radius=3)
        pdf.box(cx, cy, 2.4, ch, TEAL)
        pdf.text_at(cx + 7, cy + 8, t, 13, color=NAVY, bold=True)
        pdf.set_xy(cx + 7, cy + 17)
        pdf.set_font("DJ", "", 10.5)
        pdf.set_text_color(*GRAY)
        pdf.multi_cell(cw - 13, 5.4, d, align="L")
    pdf.footer_band(idx, total, "Segurança")


def slide_selos(pdf: Deck, idx, total):
    header(pdf, "7 · Avaliação", "Selos de artefato (SBRC)")
    rows = [
        ("SeloD — Disponível", "CONCEDER", GREEN,
         "Repo público, README detalhado, licença GPL-3.0, badges e requisitos mínimos documentados."),
        ("SeloF — Funcional", "CONCEDER", GREEN,
         "Teste mínimo roda offline via script/Docker; sem paths pessoais; 50 testes passando; build validado."),
        ("SeloS — Sustentável", "CONCEDER", GREEN,
         "Modular, config externalizada (.env/JSON), docstrings, sandbox AST e protocolos plugáveis."),
        ("SeloR — Reprodutível", "PARCIAL", AMBER,
         "requirements fixado + seed/temperature determinístico + resultados esperados; ressalva: dataset de exemplo é sintético."),
    ]
    y = 46
    rh = 27
    for name, verd, col, desc in rows:
        pdf.box(ML, y, CONTENT_W, rh, LIGHT, radius=2)
        pdf.text_at(ML + 6, y + 7, name, 12, color=NAVY, bold=True)
        pdf.set_xy(ML + 6, y + 13.5)
        pdf.set_font("DJ", "", 9.6)
        pdf.set_text_color(*GRAY)
        pdf.multi_cell(CONTENT_W - 66, 4.8, desc, align="L")
        # selo de veredito
        pdf.box(W - MR - 50, y + 7, 44, 13, col, radius=2)
        pdf.set_xy(W - MR - 50, y + 9.6)
        pdf.set_font("DJ", "B", 11)
        pdf.set_text_color(*WHITE)
        pdf.cell(44, 5, verd, align="C")
        y += rh + 4
    pdf.footer_band(idx, total, "Avaliação")


def slide_fortes(pdf: Deck, idx, total):
    header(pdf, "8 · Avaliação", "Pontos fortes")
    bullets(pdf, [
        (0, "Funciona sem rede, sem GPU e sem chave de LLM — o caminho offline é determinístico e citável.", GREEN),
        (0, "Segurança por construção: dry-run, guarda de IP privado e sandbox AST do código gerado.", GREEN),
        (0, "Validade científica: ataques ancorados no framing real do protocolo, com veredito de efeito.", GREEN),
        (0, "Reprodutibilidade prática: requirements fixado, script único, Docker que roda o teste mínimo out-of-the-box.", GREEN),
        (0, "Arquitetura modular e extensível: novos protocolos via plugin (herdar ProtocolPlugin).", GREEN),
        (0, "Honestidade acadêmica explícita: rotula ataques 'unvalidated' e não promete geração de 0-day.", GREEN),
    ], ML, 44, CONTENT_W, gap=3.6, lh=5.4)
    pdf.footer_band(idx, total, "Pontos fortes")


def slide_limites(pdf: Deck, idx, total):
    header(pdf, "9 · Avaliação", "Limitações e pontos de atenção")
    bullets(pdf, [
        (0, "O dataset de exemplo é sintético e linearmente separável: IDS atinge F1=1.00 — valida o pipeline, não é benchmark real.", RED),
        (0, "O modo LLM em nuvem não é bit-a-bit reprodutível; reprodutibilidade forte depende do modo local/offline com seed.", RED),
        (0, "Captura real de PCAP e CICFlowMeter dependem de ferramentas externas (tcpdump / CICFlowMeter) não embarcadas.", RED),
        (0, "Cenários reais reusam imagens do repo irmão `ataques/` — é preciso subir os alvos antes da execução real.", RED),
        (0, "MVP: sem frontend e sem autenticação na API. IDS é baseline (2 modelos), não estado da arte.", RED),
    ], ML, 44, CONTENT_W, gap=3.8, lh=5.5)
    pdf.footer_band(idx, total, "Limitações")


def slide_repro(pdf: Deck, idx, total):
    header(pdf, "10 · Reprodutibilidade", "Como executar e validar")
    pdf.text_at(ML, 44, "Três caminhos para o teste mínimo (offline, dry-run):", 11, color=NAVY, bold=True)
    code = (
        "# A) Script\n"
        "bash scripts/setup.sh && source .venv/bin/activate\n"
        "bash scripts/run-minimal.sh\n\n"
        "# B) Manual\n"
        "pip install -r requirements.txt && pip install -e .\n"
        "protoforge import-vulns --file data/raw/vulns.json\n\n"
        "# C) Docker\n"
        "docker compose up --build"
    )
    pdf.box(ML, 52, CONTENT_W * 0.56, 92, (28, 38, 58), radius=3)
    pdf.set_xy(ML + 5, 57)
    pdf.set_font("MONO", "", 9.2)
    pdf.set_text_color(210, 235, 228)
    pdf.multi_cell(CONTENT_W * 0.56 - 10, 5.0, code)
    # painel direito: evidências
    bx = ML + CONTENT_W * 0.60
    bw = CONTENT_W * 0.40
    pdf.text_at(bx, 50, "Evidências verificadas", 12, color=NAVY, bold=True)
    bullets(pdf, [
        (1, "pytest: 50 passed.", GREEN),
        (1, "run-minimal.sh: 7/7 etapas, relatório gerado.", GREEN),
        (1, "docker compose up: pipeline completo, exit 0.", GREEN),
        (1, "compose sem campo 'version' e sem path pessoal.", GREEN),
        (1, "requirements.txt fixado (ambiente de referência).", GREEN),
        (1, "Determinismo: temperature=0 + seed registrados no relatório.", GREEN),
    ], bx, 58, bw, gap=2.6, lh=4.8)
    pdf.footer_band(idx, total, "Reprodutibilidade")


def slide_veredito(pdf: Deck, idx, total):
    pdf.add_page()
    pdf.box(0, 0, W, H, NAVY)
    pdf.box(0, 0, 8, H, AMBER)
    pdf.text_at(ML, 30, "11 · CONCLUSÃO", 11, color=AMBER, bold=True)
    pdf.set_xy(ML, 40)
    pdf.set_font("DJ", "B", 26)
    pdf.set_text_color(*WHITE)
    pdf.cell(0, 12, "Veredito da revisão")
    pdf.set_xy(ML, 60)
    pdf.set_font("DJ", "", 13)
    pdf.set_text_color(205, 214, 226)
    pdf.multi_cell(CONTENT_W - 20, 7,
                   "Artefato tecnicamente sólido, seguro por construção e executável por terceiros sem fricção. "
                   "Recomendado para uso e citação acadêmica como gerador reprodutível de datasets de ataque "
                   "para protocolos IoT emergentes.", align="L")
    pills = [("Disponível", GREEN), ("Funcional", GREEN), ("Sustentável", GREEN), ("Reprodutível*", AMBER)]
    px = ML
    for label, col in pills:
        w = 58
        pdf.box(px, 100, w, 16, col, radius=3)
        pdf.set_xy(px, 104)
        pdf.set_font("DJ", "B", 11)
        pdf.set_text_color(*WHITE)
        pdf.cell(w, 6, label, align="C")
        px += w + 6
    pdf.text_at(ML, 124, "* Reprodutível concedido parcialmente — ver ressalva do dataset sintético.", 9.5, color=(170, 182, 198))
    pdf.text_at(ML, 150, "Recomendação ao comitê:", 12, color=AMBER, bold=True)
    pdf.set_xy(ML, 158)
    pdf.set_font("DJ", "", 11.5)
    pdf.set_text_color(220, 228, 238)
    pdf.multi_cell(CONTENT_W - 20, 6,
                   "Conceder D, F e S. Conceder R com a ressalva de documentar que o dataset de exemplo é "
                   "sintético (substituí-lo por captura real fortaleceria a avaliação experimental).", align="L")
    pdf.box(0, H - 4, W, 4, TEAL)


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("docs/VulnForge-AI-Review.pdf")
    out.parent.mkdir(parents=True, exist_ok=True)
    pdf = Deck()
    builders = [slide_resumo, slide_problema, slide_arquitetura, slide_cap1, slide_cap2,
                slide_seguranca, slide_selos, slide_fortes, slide_limites, slide_repro]
    total = len(builders) + 2  # capa + veredito
    slide_cover(pdf)
    for i, b in enumerate(builders, start=2):
        pdf.add_page()
        b(pdf, i, total)
    slide_veredito(pdf, total, total)
    pdf.output(str(out))
    print(f"PDF gerado: {out}  ({out.stat().st_size // 1024} KB, {total} slides)")


if __name__ == "__main__":
    main()
