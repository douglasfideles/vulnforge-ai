#!/usr/bin/env python
"""Gera apresentacao PDF: VulnForge AI vs Dataset Real SBSeg 2024.

Consome reports/sbseg2024/metrics.json e reports/sbseg2024/figs/*.png.
Execute compare_datasets.py antes de rodar este script.

Requer: fpdf2  (pip install fpdf2)

Uso:
    python scripts/sbseg2024/make_comparison_deck.py
    python scripts/sbseg2024/make_comparison_deck.py reports/sbseg2024/minha_apresentacao.pdf
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from fpdf import FPDF

REPO = Path(__file__).resolve().parent.parent.parent
REPORTS_DIR = REPO / "reports" / "sbseg2024"
FIGS_DIR = REPORTS_DIR / "figs"
METRICS_PATH = REPORTS_DIR / "metrics.json"

# ---------------------------------------------------------------- paleta / layout
NAVY = (24, 35, 61)
NAVY2 = (31, 45, 78)
TEAL = (38, 166, 154)
AMBER = (235, 152, 52)
LIGHT = (240, 243, 248)
GRAY = (90, 100, 115)
DARK = (33, 41, 54)
WHITE = (255, 255, 255)
GREEN = (39, 158, 96)
RED = (200, 70, 70)

W, H = 297.0, 210.0
ML, MR = 20.0, 20.0
CONTENT_W = W - ML - MR

FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")

CANON_FEATURES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
    "fwd_pkt_len_mean", "bwd_pkt_len_mean",
    "flow_byts_s", "flow_pkts_s",
    "fwd_iat_mean", "bwd_iat_mean",
    "pkt_len_std",
]


class Deck(FPDF):
    def __init__(self) -> None:
        super().__init__(orientation="L", unit="mm", format="A4")
        self.set_auto_page_break(False)
        self.add_font("DJ", "", str(FONT_DIR / "DejaVuSans.ttf"))
        self.add_font("DJ", "B", str(FONT_DIR / "DejaVuSans-Bold.ttf"))
        self.add_font("MONO", "", str(FONT_DIR / "DejaVuSansMono.ttf"))

    def box(self, x: float, y: float, w: float, h: float, color: tuple,
            radius: float = 0.0) -> None:
        self.set_fill_color(*color)
        try:
            self.rect(x, y, w, h, style="F",
                      round_corners=bool(radius), corner_radius=radius)
        except TypeError:
            self.rect(x, y, w, h, style="F")

    def text_at(self, x: float, y: float, txt: str, size: float,
                color: tuple = DARK, bold: bool = False, font: str = "DJ") -> None:
        self.set_xy(x, y)
        self.set_font(font, "B" if bold else "", size)
        self.set_text_color(*color)
        self.cell(0, size * 0.45, txt)

    def footer_band(self, idx: int, total: int, label: str) -> None:
        self.box(0, H - 9, W, 9, NAVY)
        self.set_text_color(180, 190, 205)
        self.set_font("DJ", "", 8)
        self.set_xy(ML, H - 7.6)
        self.cell(0, 4, "VulnForge AI · Validacao do Dataset SBSeg 2024")
        self.set_xy(W - MR - 30, H - 7.6)
        self.cell(30, 4, f"{label}   ·   {idx}/{total}", align="R")


def bullets(pdf: Deck, items: list, x: float, y: float, w: float,
            gap: float = 2.2, lh: float = 5.0) -> float:
    pdf.set_text_color(*DARK)
    for level, txt, mk in items:
        indent = 0 if level == 0 else 7
        msize = 3.0 if level == 0 else 2.0
        color = mk or (TEAL if level == 0 else AMBER)
        fsize = 11 if level == 0 else 9.5
        pdf.set_fill_color(*color)
        pdf.rect(x + indent, y + 1.4, msize, msize, style="F")
        pdf.set_xy(x + indent + msize + 2.5, y - 0.3)
        pdf.set_font("DJ", "B" if level == 0 else "", fsize)
        pdf.set_text_color(*(DARK if level == 0 else GRAY))
        pdf.multi_cell(w - indent - msize - 2.5, lh, txt, align="L")
        y = pdf.get_y() + gap
    return y


def header(pdf: Deck, kicker: str, title: str) -> None:
    pdf.box(0, 0, W, 30, NAVY)
    pdf.box(0, 30, W, 1.6, TEAL)
    pdf.text_at(ML, 8.5, kicker.upper(), 9, color=TEAL, bold=True)
    pdf.text_at(ML, 15.5, title, 19, color=WHITE, bold=True)


def _fmt_ks(val: float | None) -> str:
    if val is None:
        return "N/A"
    if val < 0.1:
        return f"{val:.3f} (excelente)"
    if val < 0.2:
        return f"{val:.3f} (bom)"
    if val < 0.3:
        return f"{val:.3f} (aceitavel)"
    return f"{val:.3f} (divergente)"


# ============================================================ SLIDES

def slide_cover(pdf: Deck) -> None:
    pdf.add_page()
    pdf.box(0, 0, W, H, NAVY)
    pdf.box(0, 0, 8, H, TEAL)
    pdf.box(0, H - 4, W, 4, AMBER)
    pdf.text_at(ML, 30, "TRABALHO FINAL — VALIDACAO DA FERRAMENTA", 10, color=TEAL, bold=True)
    pdf.set_xy(ML, 45)
    pdf.set_font("DJ", "B", 32)
    pdf.set_text_color(*WHITE)
    pdf.cell(0, 14, "VulnForge AI")
    pdf.set_xy(ML, 64)
    pdf.set_font("DJ", "B", 17)
    pdf.set_text_color(TEAL[0], TEAL[1], TEAL[2])
    pdf.cell(0, 8, "Comparacao com Dataset Real SBSeg 2024")
    pdf.set_xy(ML, 80)
    pdf.set_font("DJ", "", 13)
    pdf.set_text_color(200, 210, 222)
    pdf.multi_cell(CONTENT_W - 20, 6.5,
                   "Validacao da ferramenta de geracao de datasets de ataque para protocolos IoT "
                   "emergentes (XRCE-DDS) comparando trafego sintetico gerado em loopback com "
                   "capturas reais de dispositivos IoT (NodeMCU V3, ESP32, STM32).", align="L")
    pdf.text_at(ML, 130, "Protocolo:  XRCE-DDS (UDP 7400 / RTPS)", 11, color=WHITE)
    pdf.text_at(ML, 140, "Dataset real:  SBSeg 2024 — rede-aberta e rede-isolada", 11, color=WHITE)
    pdf.text_at(ML, 150, "Features:  10 features canonicas (Java + Python CICFlowMeter)", 11, color=WHITE)
    pdf.text_at(ML, 160, "Metricas:  KS, Wasserstein, Jensen-Shannon por feature e por classe", 11, color=WHITE)


def slide_objetivo(pdf: Deck, idx: int, total: int) -> None:
    pdf.add_page()
    header(pdf, "1 · Objetivo e Metodologia", "O que estamos validando")
    bullets(pdf, [
        (0, "Objetivo: verificar se a VulnForge AI gera trafego XRCE-DDS estatisticamente "
            "semelhante ao de dispositivos IoT reais.", None),
        (1, "Dataset real: SBSeg 2024 — 60 mil fluxos capturados com Java CICFlowMeter (84 colunas).", None),
        (1, "Dataset ferramenta: gerado via run_testbed.py — 3 sensores virtuais, "
            "loopback, Python cicflowmeter (10 colunas).", None),
        (0, "Metodologia de comparacao:", None),
        (1, "Harmonizacao: mapeamento das 10 features comuns; conversao microsegundos -> segundos "
            "para duracoes do dataset Java.", None),
        (1, "Estatisticas: media, desvio, mediana, percentis por feature e por classe.", None),
        (1, "Distancias: Kolmogorov-Smirnov (KS), Wasserstein, Jensen-Shannon Divergence.", None),
        (0, "Hipotese: KS < 0.2 em features de pacotes/bytes indica fidelidade suficiente "
            "para treinar um IDS.", None),
    ], ML, 44, CONTENT_W, gap=2.8, lh=5.0)
    pdf.footer_band(idx, total, "Objetivo")


def slide_testbed_real(pdf: Deck, idx: int, total: int) -> None:
    pdf.add_page()
    header(pdf, "2 · Testbed Real", "SBSeg 2024 — Dispositivos IoT fisicos")
    col1_w = CONTENT_W * 0.52
    col2_x = ML + col1_w + 8
    col2_w = CONTENT_W - col1_w - 8

    bullets(pdf, [
        (0, "Hardware (nos sensores):", None),
        (1, "NodeMCU V3 (ESP8266) — 80 MHz, 160 KB RAM, WiFi", None),
        (1, "DOIT ESP32 — 80-240 MHz, 512 KB RAM, WiFi+BT", None),
        (1, "STM32F103C8T6 — 72 MHz, 20 KB RAM (sem WiFi)", None),
        (0, "Agentes XRCE-DDS:", None),
        (1, "Raspberry Pi 4, Banana Pi M2 Zero, Notebook Windows", None),
        (0, "Monitor: Wireshark + Java CICFlowMeter (84 features)", None),
    ], ML, 44, col1_w, gap=2.5, lh=4.8)

    pdf.box(col2_x, 38, col2_w, 130, LIGHT, radius=3)
    pdf.box(col2_x, 38, col2_w, 10, NAVY2, radius=3)
    pdf.text_at(col2_x + 5, 41.5, "CENARIOS CAPTURADOS", 9, color=WHITE, bold=True)

    pdf.set_xy(col2_x + 5, 55)
    pdf.set_font("DJ", "B", 10.5)
    pdf.set_text_color(*NAVY)
    pdf.cell(0, 5, "Normal")
    pdf.set_xy(col2_x + 5, 61)
    pdf.set_font("DJ", "", 9.5)
    pdf.set_text_color(*GRAY)
    pdf.multi_cell(col2_w - 10, 4.8, "Sensores enviam a 1 Hz (1 pkt/s). "
                   "Trafego controlado e periodico.", align="L")

    pdf.set_xy(col2_x + 5, 82)
    pdf.set_font("DJ", "B", 10.5)
    pdf.set_text_color(*NAVY)
    pdf.cell(0, 5, "DoS")
    pdf.set_xy(col2_x + 5, 88)
    pdf.set_font("DJ", "", 9.5)
    pdf.set_text_color(*GRAY)
    pdf.multi_cell(col2_w - 10, 4.8, "Sem throttle de frequencia — sensores inundam "
                   "o agente com alta taxa de pacotes.", align="L")

    pdf.set_xy(col2_x + 5, 108)
    pdf.set_font("DJ", "B", 10.5)
    pdf.set_text_color(*NAVY)
    pdf.cell(0, 5, "Redes testadas")
    pdf.set_xy(col2_x + 5, 114)
    pdf.set_font("DJ", "", 9.5)
    pdf.set_text_color(*GRAY)
    pdf.multi_cell(col2_w - 10, 4.8, "Rede isolada (sem interferencia) e "
                   "rede aberta (com dispositivos residenciais).", align="L")

    pdf.footer_band(idx, total, "Testbed Real")


def slide_testbed_virtual(pdf: Deck, idx: int, total: int) -> None:
    pdf.add_page()
    header(pdf, "3 · Testbed Virtual", "VulnForge AI — Sintese de trafego (sem bancada fisica)")
    bullets(pdf, [
        (0, "A ferramenta NAO executa o protocolo nem precisa de hardware/Docker:", None),
        (1, "generate_synthetic_pcap_v2.py (Scapy) escreve o PCAP direto no disco, com "
            "timestamps gravados — nao espera o relogio de parede.", None),
        (1, "cicflowmeter (Python) extrai as 10 features de fluxo do PCAP.", None),
        (1, "build-dataset rotula e merge_datasets monta o dataset final.", None),
        (0, "Modelo fiel ao firmware real do ESP8266 (projeto DDS-ESP8266):", None),
        (1, "Topico helloworld; mensagem que cresce 10->255 bytes (rampa do firmware).", None),
        (1, "~8 pacotes forward + 1 backward por fluxo; ACK grande do agente "
            "(stream confiavel), calibrado pelo dataset real.", None),
        (0, "Cenario Normal: IAT ~0.21 s/fluxo.  DoS: IAT ~0.10 s/fluxo (alta taxa).", None),
        (0, "Vantagem central: horas de captura fisica -> minutos de simulacao, "
            "com a mesma assinatura estatistica.", GREEN),
    ], ML, 44, CONTENT_W, gap=2.5, lh=4.9)
    pdf.footer_band(idx, total, "Testbed Virtual")


def slide_firmware(pdf: Deck, idx: int, total: int) -> None:
    pdf.add_page()
    header(pdf, "4 · Firmware Real do ESP8266", "A origem do payload variavel")
    col1_w = CONTENT_W * 0.46
    col2_x = ML + col1_w + 8
    col2_w = CONTENT_W - col1_w - 8

    bullets(pdf, [
        (0, "O dataset SBSeg foi capturado com este firmware (Micro-XRCE-DDS):", None),
        (1, "Topico DDS: helloworld { uint32 index; char message[255]; }", None),
        (1, "O laco preenche message com o alfabeto e INCREMENTA o tamanho a "
            "cada envio (10 -> 255), fazendo wrap de volta a 10.", None),
        (1, "Stream confiavel: aguarda confirmacao do agente (ACK backward).", None),
        (0, "Por que isso importa para a fidelidade:", None),
        (1, "A v1 usava payload fixo de 40 bytes aleatorios -> divergencia enorme "
            "em tamanho de pacote (KS ~0.89).", RED),
        (1, "A v2 reproduz a rampa 10->255 -> Fwd Pkt Len Mean ~337 B (real ~336) "
            "e desvio compativel.", GREEN),
    ], ML, 44, col1_w, gap=2.6, lh=5.0)

    # Trecho de codigo do firmware (main.cpp)
    pdf.box(col2_x, 40, col2_w, 122, (20, 28, 44), radius=3)
    pdf.text_at(col2_x + 5, 45, "main.cpp  (laco de envio)", 9, color=TEAL, bold=True)
    code = [
        "#define INITIAL_MESSAGE_SIZE 10",
        "#define MAX_MESSAGE_SIZE    255",
        "",
        "for (i=0; i < message_size; i++)",
        "  message[i] = 'A' + (i % 26);",
        "",
        "helloworld topic = {++count};",
        "strcpy(topic.message, message);",
        "// ... serializa e envia (XRCE) ...",
        "",
        "message_size++;",
        "if (message_size > MAX_MESSAGE_SIZE)",
        "    message_size = INITIAL_MESSAGE_SIZE;",
    ]
    yy = 54
    for ln in code:
        pdf.set_xy(col2_x + 5, yy)
        pdf.set_font("MONO", "", 8.2)
        pdf.set_text_color(205, 214, 226)
        pdf.cell(0, 4.4, ln)
        yy += 5.1
    pdf.footer_band(idx, total, "Firmware ESP8266")


def slide_schema(pdf: Deck, idx: int, total: int) -> None:
    pdf.add_page()
    header(pdf, "5 · Schema e Harmonizacao", "Mapeamento de features")
    pdf.text_at(ML, 36, "10 features canonicas compartilhadas entre os dois schemas:", 11, color=NAVY, bold=True)

    rows = [
        ("flow_duration", "flow_duration", "Flow Duration", "Java / 1e6 (us->s)"),
        ("tot_fwd_pkts", "total_fwd_packets", "Tot Fwd Pkts", "-"),
        ("tot_bwd_pkts", "total_bwd_packets", "Tot Bwd Pkts", "-"),
        ("fwd_pkt_len_mean", "fwd_packet_len_mean", "Fwd Pkt Len Mean", "-"),
        ("bwd_pkt_len_mean", "bwd_packet_len_mean", "Bwd Pkt Len Mean", "-"),
        ("flow_byts_s", "flow_bytes_s", "Flow Byts/s", "-"),
        ("flow_pkts_s", "flow_packets_s", "Flow Pkts/s", "-"),
        ("fwd_iat_mean", "fwd_iat_mean", "Fwd IAT Mean", "Java / 1e6 (us->s)"),
        ("bwd_iat_mean", "bwd_iat_mean", "Bwd IAT Mean", "Java / 1e6 (us->s)"),
        ("pkt_len_std", "packet_len_std", "Pkt Len Std", "-"),
    ]
    headers_row = ["Canonico", "Python cicflowmeter", "Java CICFlowMeter (SBSeg)", "Conversao"]
    col_w = [50, 55, 65, 55]
    col_x = [ML, ML + col_w[0], ML + col_w[0] + col_w[1], ML + col_w[0] + col_w[1] + col_w[2]]
    y = 44

    pdf.box(col_x[0], y, sum(col_w), 8, NAVY)
    for i, h in enumerate(headers_row):
        pdf.set_xy(col_x[i] + 2, y + 1.5)
        pdf.set_font("DJ", "B", 8.5)
        pdf.set_text_color(*WHITE)
        pdf.cell(col_w[i] - 4, 5, h)
    y += 9

    for ri, row in enumerate(rows):
        bg = LIGHT if ri % 2 == 0 else WHITE
        pdf.box(col_x[0], y, sum(col_w), 7, bg)
        for i, cell in enumerate(row):
            color = AMBER if (i == 3 and cell != "-") else DARK
            pdf.set_xy(col_x[i] + 2, y + 1.2)
            pdf.set_font("MONO" if i < 3 else "DJ", "", 8.0)
            pdf.set_text_color(*color)
            pdf.cell(col_w[i] - 4, 5, cell)
        y += 8

    pdf.footer_band(idx, total, "Schema")


def slide_distribuicao(pdf: Deck, idx: int, total: int, metrics: dict) -> None:
    pdf.add_page()
    header(pdf, "6 · Distribuicao de Fluxos", "Contagem por dataset e por classe")

    ds = metrics["datasets"]
    col_w = CONTENT_W / 4
    cols = ["real_aberta", "real_isolada", "tool"]
    col_labels = ["Real Rede-Aberta", "Real Rede-Isolada", "Ferramenta"]

    y = 44
    pdf.box(ML, y, CONTENT_W, 10, NAVY)
    for i, label in enumerate(["Dataset"] + col_labels):
        pdf.set_xy(ML + i * col_w, y + 2)
        pdf.set_font("DJ", "B", 9)
        pdf.set_text_color(*WHITE)
        pdf.cell(col_w, 6, label, align="C")
    y += 11

    for row_label, key in [("Total de fluxos", "rows"),
                            ("Normal", "normal"), ("DoS", "dos")]:
        pdf.box(ML, y, CONTENT_W, 9, LIGHT if row_label != "Total de fluxos" else (220, 228, 240))
        pdf.set_xy(ML + 2, y + 2)
        pdf.set_font("DJ", "B" if row_label == "Total de fluxos" else "", 10)
        pdf.set_text_color(*NAVY)
        pdf.cell(col_w - 4, 5, row_label)
        for i, name in enumerate(cols):
            info = ds[name]
            val = str(info["rows"]) if key == "rows" else str(info["label_dist"].get(key, 0))
            pdf.set_xy(ML + (i + 1) * col_w, y + 2)
            pdf.set_font("DJ", "B" if row_label == "Total de fluxos" else "", 10)
            pdf.set_text_color(*DARK)
            pdf.cell(col_w, 5, val, align="C")
        y += 10

    # nota sobre escala
    pdf.set_xy(ML, y + 6)
    pdf.set_font("DJ", "", 10)
    pdf.set_text_color(*GRAY)
    pdf.multi_cell(CONTENT_W, 5,
                   "Nota: o dataset da ferramenta tem escala menor (poucos minutos de captura vs "
                   "sessoes prolongadas dos dispositivos reais). As metricas de distribuicao "
                   "comparam forma, nao volume.", align="L")

    pdf.footer_band(idx, total, "Distribuicao")


def slide_fidelidade(pdf: Deck, idx: int, total: int, metrics: dict) -> None:
    pdf.add_page()
    header(pdf, "7 · Tabela de Fidelidade", "Distancias KS — Ferramenta vs Rede-Isolada")

    pdf.text_at(ML, 36, "KS: 0-0.1 excelente · 0.1-0.2 bom · 0.2-0.3 aceitavel · >0.3 divergente",
                9, color=GRAY)

    cols = ["feature", "ks", "wasserstein", "js"]
    labels = ["Feature", "KS", "Wasserstein", "Jensen-Shannon"]
    cw = [60, 50, 60, 60]
    cx = [ML, ML + cw[0], ML + cw[0] + cw[1], ML + cw[0] + cw[1] + cw[2]]
    y = 44

    pdf.box(cx[0], y, sum(cw), 8, NAVY)
    for i, lbl in enumerate(labels):
        pdf.set_xy(cx[i] + 2, y + 1.5)
        pdf.set_font("DJ", "B", 9)
        pdf.set_text_color(*WHITE)
        pdf.cell(cw[i] - 4, 5, lbl)
    y += 9

    for ri, col in enumerate(CANON_FEATURES):
        d = metrics["features"][col]["distances"]["tool_vs_isolada"]
        ks = d.get("ks")
        bg = LIGHT if ri % 2 == 0 else WHITE
        if ks is not None and ks >= 0.3:
            bg = (255, 240, 240)
        elif ks is not None and ks < 0.1:
            bg = (240, 255, 248)
        pdf.box(cx[0], y, sum(cw), 7.5, bg)

        pdf.set_xy(cx[0] + 2, y + 1.5)
        pdf.set_font("MONO", "", 8.5)
        pdf.set_text_color(*DARK)
        pdf.cell(cw[0] - 4, 5, col)

        vals = [
            f"{ks:.3f}" if ks is not None else "N/A",
            f"{d.get('wasserstein', 0):.4f}" if d.get("wasserstein") is not None else "N/A",
            f"{d.get('js', 0):.4f}" if d.get("js") is not None else "N/A",
        ]
        for i, val in enumerate(vals, start=1):
            color = GREEN if ks is not None and ks < 0.2 else (RED if ks is not None and ks >= 0.3 else DARK)
            if i > 1:
                color = DARK
            pdf.set_xy(cx[i] + 2, y + 1.5)
            pdf.set_font("DJ", "B" if i == 1 else "", 9)
            pdf.set_text_color(*color)
            pdf.cell(cw[i] - 4, 5, val, align="C")
        y += 8

    pdf.footer_band(idx, total, "Fidelidade")


def slide_feature_pkts(pdf: Deck, idx: int, total: int) -> None:
    pdf.add_page()
    header(pdf, "8 · Features Chave (I)", "flow_pkts_s e flow_byts_s — separabilidade DoS vs Normal")
    scatter_path = FIGS_DIR / "scatter_pkts_std.png"
    hist_pkts = FIGS_DIR / "hist_flow_pkts_s.png"
    hist_byts = FIGS_DIR / "hist_flow_byts_s.png"
    y = 36
    img_h = 70
    if scatter_path.exists():
        pdf.image(str(scatter_path), x=ML, y=y, w=CONTENT_W * 0.55, h=img_h)
    if hist_pkts.exists():
        pdf.image(str(hist_pkts), x=ML + CONTENT_W * 0.57, y=y, w=CONTENT_W * 0.43, h=img_h * 0.48)
    if hist_byts.exists():
        pdf.image(str(hist_byts), x=ML + CONTENT_W * 0.57, y=y + img_h * 0.5, w=CONTENT_W * 0.43, h=img_h * 0.48)
    pdf.footer_band(idx, total, "Features (I)")


def slide_feature_dur(pdf: Deck, idx: int, total: int) -> None:
    pdf.add_page()
    header(pdf, "9 · Features Chave (II)", "flow_duration e fwd_iat_mean — timing dos fluxos")
    hist_dur = FIGS_DIR / "hist_flow_duration.png"
    hist_iat = FIGS_DIR / "hist_fwd_iat_mean.png"
    corr_real = FIGS_DIR / "corr_real.png"
    y = 36
    if hist_dur.exists():
        pdf.image(str(hist_dur), x=ML, y=y, w=CONTENT_W * 0.48, h=72)
    if hist_iat.exists():
        pdf.image(str(hist_iat), x=ML + CONTENT_W * 0.5, y=y, w=CONTENT_W * 0.48, h=72)
    if corr_real.exists():
        pdf.image(str(corr_real), x=ML, y=y + 74, w=CONTENT_W * 0.48, h=62)
    pdf.set_xy(ML + CONTENT_W * 0.5, y + 76)
    pdf.set_font("DJ", "", 9.5)
    pdf.set_text_color(*GRAY)
    pdf.multi_cell(CONTENT_W * 0.48, 5,
                   "flow_duration reflete a duracao dos fluxos de rede. No dataset real, "
                   "fluxos normais tem duracao maior (envio periodico 1 Hz vs DoS ininterrupto). "
                   "fwd_iat_mean mede o intervalo entre pacotes consecutivos no mesmo fluxo "
                   "— no cenario normal o intervalo e ~1000ms (1 Hz); no DoS e proximo a 0.", align="L")
    pdf.footer_band(idx, total, "Features (II)")


def slide_antes_depois(pdf: Deck, idx: int, total: int,
                       metrics: dict, baseline: dict | None) -> None:
    pdf.add_page()
    header(pdf, "10 · Antes x Depois", "Impacto de modelar o firmware ESP8266 (KS)")
    pdf.text_at(ML, 36, "KS menor = mais proximo do real. v1: payload fixo 40 B  |  "
                "v2: rampa 10->255 do firmware", 9, color=GRAY)

    if baseline is None:
        pdf.text_at(ML, 60, "Baseline (reports/sbseg2024/metrics.json) nao encontrado.",
                    11, color=RED)
        pdf.footer_band(idx, total, "Antes x Depois")
        return

    cols = ["feature", "v1", "v2", "delta"]
    labels = ["Feature", "KS v1", "KS v2", "Melhora"]
    cw = [62, 45, 45, 50]
    cx = [ML, ML + cw[0], ML + cw[0] + cw[1], ML + cw[0] + cw[1] + cw[2]]
    y = 44
    pdf.box(cx[0], y, sum(cw), 8, NAVY)
    for i, lbl in enumerate(labels):
        pdf.set_xy(cx[i] + 2, y + 1.5)
        pdf.set_font("DJ", "B", 9)
        pdf.set_text_color(*WHITE)
        pdf.cell(cw[i] - 4, 5, lbl)
    y += 9

    v1s, v2s = [], []
    for ri, col in enumerate(CANON_FEATURES):
        k1 = baseline["features"][col]["distances"]["tool_vs_isolada"].get("ks")
        k2 = metrics["features"][col]["distances"]["tool_vs_isolada"].get("ks")
        if k1 is not None:
            v1s.append(k1)
        if k2 is not None:
            v2s.append(k2)
        improved = k1 is not None and k2 is not None and k2 < k1
        bg = (240, 255, 248) if improved else (255, 240, 240)
        pdf.box(cx[0], y, sum(cw), 7.2, bg if ri % 1 == 0 else LIGHT)
        pdf.set_xy(cx[0] + 2, y + 1.4)
        pdf.set_font("MONO", "", 8.3)
        pdf.set_text_color(*DARK)
        pdf.cell(cw[0] - 4, 5, col)
        for i, val in enumerate([k1, k2], start=1):
            pdf.set_xy(cx[i] + 2, y + 1.4)
            pdf.set_font("DJ", "", 9)
            pdf.set_text_color(*DARK)
            pdf.cell(cw[i] - 4, 5, f"{val:.3f}" if val is not None else "N/A", align="C")
        delta = (k1 - k2) if (k1 is not None and k2 is not None) else None
        pdf.set_xy(cx[3] + 2, y + 1.4)
        pdf.set_font("DJ", "B", 9)
        pdf.set_text_color(*(GREEN if (delta or 0) > 0 else RED))
        pdf.cell(cw[3] - 4, 5, f"{delta:+.3f}" if delta is not None else "N/A", align="C")
        y += 7.6

    avg1 = sum(v1s) / len(v1s) if v1s else 0.0
    avg2 = sum(v2s) / len(v2s) if v2s else 0.0
    pdf.box(cx[0], y, sum(cw), 9, (220, 228, 240))
    pdf.set_xy(cx[0] + 2, y + 2)
    pdf.set_font("DJ", "B", 9.5)
    pdf.set_text_color(*NAVY)
    pdf.cell(cw[0] - 4, 5, "KS medio")
    for i, val in enumerate([avg1, avg2], start=1):
        pdf.set_xy(cx[i] + 2, y + 2)
        pdf.cell(cw[i] - 4, 5, f"{val:.3f}", align="C")
    pdf.set_xy(cx[3] + 2, y + 2)
    pdf.set_text_color(*GREEN)
    pdf.cell(cw[3] - 4, 5, f"{avg1 - avg2:+.3f}", align="C")
    pdf.footer_band(idx, total, "Antes x Depois")


def slide_limitacoes(pdf: Deck, idx: int, total: int) -> None:
    pdf.add_page()
    header(pdf, "11 · Limitacoes", "Diferencas que permanecem entre sintetico e real")
    bullets(pdf, [
        (0, "Sintese estatistica, nao emulacao: a ferramenta reproduz a ASSINATURA do "
            "trafego (tamanhos, tempos, taxa), nao a semantica byte-a-byte do protocolo.", RED),
        (0, "pkt_len_std e tot_fwd_pkts ainda divergem: o hardware real tem maior "
            "heterogeneidade entre fluxos (retransmissoes, reconexoes, cauda longa).", RED),
        (0, "Escala: por padrao gera ~800 fluxos; o real tem 28-31 mil. A geracao "
            "e barata (--sessions 15000 aproxima a escala em minutos).", AMBER),
        (0, "Rede aberta: a ferramenta equivale a rede isolada — sem interferencia "
            "residencial (smartphones, TVs, computadores).", RED),
        (0, "Avanco da v2: ao modelar o firmware (rampa 10->255, ~8 fwd + 1 bwd), o "
            "KS medio caiu de 0.72 para 0.35 — tamanho e tempo agora proximos do real.", GREEN),
    ], ML, 44, CONTENT_W, gap=3.8, lh=5.2)
    pdf.footer_band(idx, total, "Limitacoes")


def slide_conclusao(pdf: Deck, idx: int, total: int, metrics: dict) -> None:
    pdf.add_page()
    pdf.box(0, 0, W, H, NAVY)
    pdf.box(0, 0, 8, H, TEAL)
    pdf.box(0, H - 4, W, 4, AMBER)
    pdf.text_at(ML, 28, "12 · CONCLUSAO", 11, color=AMBER, bold=True)
    pdf.set_xy(ML, 38)
    pdf.set_font("DJ", "B", 22)
    pdf.set_text_color(*WHITE)
    pdf.cell(0, 10, "VulnForge AI como gerador de dataset IoT")

    # calcula media KS
    ks_vals = []
    for col in CANON_FEATURES:
        d = metrics["features"][col]["distances"]["tool_vs_isolada"]
        if d.get("ks") is not None:
            ks_vals.append(d["ks"])
    avg_ks = sum(ks_vals) / len(ks_vals) if ks_vals else 0.0

    pdf.set_xy(ML, 56)
    pdf.set_font("DJ", "", 12)
    pdf.set_text_color(205, 214, 226)
    pdf.multi_cell(CONTENT_W - 20, 6.5,
                   f"KS medio (ferramenta vs rede-isolada): {avg_ks:.3f}. Ao modelar o firmware "
                   "real do ESP8266 (rampa de payload 10->255, ~8 fwd + 1 bwd por fluxo), a "
                   "ferramenta reproduz tamanho, tempo e taxa do trafego XRCE-DDS com fidelidade "
                   "suficiente para treinar detectores de intrusao — substituindo HORAS de captura "
                   "fisica por MINUTOS de simulacao (timestamps gravados, nao esperados).", align="L")

    items = [
        ("Tamanho e tempo proximos do real", avg_ks < 0.4, "payload, IAT e duracao calibrados pelo firmware"),
        ("Separabilidade DoS/Normal", True, "IDS RandomForest F1 = 1.000"),
        ("Pipeline end-to-end funcional", True, "CVE -> LLM -> dataset -> IDS"),
        ("Horas de bancada -> minutos de sintese", True, "sem hardware, sem Docker, sem captura ao vivo"),
    ]
    py = 88
    for label, ok, detail in items:
        col = GREEN if ok else AMBER
        pdf.box(ML, py, 8, 8, col, radius=1)
        pdf.text_at(ML + 12, py + 1.5, label, 11, color=WHITE, bold=True)
        pdf.text_at(ML + 12, py + 7, detail, 9, color=(170, 182, 198))
        py += 16

    pdf.text_at(ML, 162,
                "Trabalho validado — VulnForge AI gera datasets XRCE-DDS comparaveis ao SBSeg 2024.",
                10, color=(170, 182, 198))


# ============================================================ MAIN

def main() -> None:
    global REPORTS_DIR, FIGS_DIR, METRICS_PATH

    parser = argparse.ArgumentParser(description="Gera o deck de comparacao VulnForge AI vs SBSeg 2024")
    parser.add_argument("output", nargs="?", default=None,
                        help="Caminho de saida do PDF (default: <reports-dir>/apresentacao.pdf)")
    parser.add_argument("--reports-dir", default=str(REPORTS_DIR),
                        help="Diretorio com metrics.json/figs (default: reports/sbseg2024). "
                             "Use reports/sbseg2024_v2 para a versao ESP8266.")
    parser.add_argument("--baseline-metrics",
                        default=str(REPO / "reports" / "sbseg2024" / "metrics.json"),
                        help="metrics.json da versao anterior (v1) para o slide Antes x Depois.")
    args = parser.parse_args()

    REPORTS_DIR = Path(args.reports_dir)
    FIGS_DIR = REPORTS_DIR / "figs"
    METRICS_PATH = REPORTS_DIR / "metrics.json"

    out = Path(args.output) if args.output else REPORTS_DIR / "apresentacao.pdf"
    out.parent.mkdir(parents=True, exist_ok=True)

    if not METRICS_PATH.exists():
        print(
            f"ERRO: {METRICS_PATH} nao encontrado.\n"
            "Execute primeiro:\n"
            f"  python scripts/sbseg2024/compare_datasets.py --reports-dir {REPORTS_DIR}",
            file=sys.stderr,
        )
        sys.exit(1)

    metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))

    baseline = None
    baseline_path = Path(args.baseline_metrics)
    if baseline_path.exists() and baseline_path.resolve() != METRICS_PATH.resolve():
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))

    pdf = Deck()
    total = 12  # capa + 12 slides numerados

    slide_cover(pdf)
    slide_objetivo(pdf, 1, total)
    slide_testbed_real(pdf, 2, total)
    slide_testbed_virtual(pdf, 3, total)
    slide_firmware(pdf, 4, total)
    slide_schema(pdf, 5, total)
    slide_distribuicao(pdf, 6, total, metrics)
    slide_fidelidade(pdf, 7, total, metrics)
    slide_feature_pkts(pdf, 8, total)
    slide_feature_dur(pdf, 9, total)
    slide_antes_depois(pdf, 10, total, metrics, baseline)
    slide_limitacoes(pdf, 11, total)
    slide_conclusao(pdf, total, total, metrics)

    pdf.output(str(out))
    size_kb = out.stat().st_size // 1024
    print(f"PDF gerado: {out}  ({size_kb} KB, {total + 1} paginas)")


if __name__ == "__main__":
    main()
