#!/usr/bin/env python
"""Orquestra o testbed SBSeg 2024 em ambiente virtual (loopback).

Reproduz o cenario do artigo: 3 sensores IoT publicando em UDP 7400 (XRCE-DDS),
um agente respondendo (trafego backward), captura via tcpdump e extracao de
fluxos com cicflowmeter — gerando um dataset comparavel ao dataset real SBSeg 2024.

Requer:
    sudo (para tcpdump) ou capabilidade CAP_NET_RAW
    pip install cicflowmeter
    agent_sink.py no mesmo diretorio

Uso:
    sudo -E env PATH=$PATH python scripts/sbseg2024/run_testbed.py
    sudo -E env PATH=$PATH python scripts/sbseg2024/run_testbed.py --duration 30 --rate-dos 100
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = Path(__file__).resolve().parent
PYTHON = sys.executable


def _wait(procs: list[subprocess.Popen], timeout: float | None = None) -> None:
    for p in procs:
        try:
            p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()


def _stop(proc: subprocess.Popen, timeout: float = 3.0) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def run_scenario(
    *,
    label: str,
    benign: bool,
    rate: float,
    duration: int,
    pcap_path: Path,
    flows_path: Path,
    dataset_path: Path,
) -> Path:
    """Executa um cenario (normal ou dos) e devolve o caminho do dataset rotulado."""
    print(f"\n=== Cenario: {label} (rate={rate} pkt/s, benign={benign}, duration={duration}s) ===")

    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    flows_path.parent.mkdir(parents=True, exist_ok=True)
    dataset_path.parent.mkdir(parents=True, exist_ok=True)

    # 1. Sobe agent_sink
    sink = subprocess.Popen(
        [PYTHON, str(SCRIPTS_DIR / "agent_sink.py"), "--port", "7400", "--host", "127.0.0.1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.5)

    # 2. Inicia tcpdump na interface loopback
    dump = subprocess.Popen(
        ["tcpdump", "-i", "lo", "-w", str(pcap_path), "udp", "port", "7400"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.5)

    # 3. Lanca 3 sensores em paralelo (simula 3 dispositivos IoT)
    cmd = [
        PYTHON, "-m", "vulnforge.traffic.attacks.flooding",
        "--target", "127.0.0.1",
        "--port", "7400",
        "--transport", "udp",
        "--rate", str(rate),
        "--duration", str(duration),
    ]
    if benign:
        cmd.append("--benign")

    sensors = [
        subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=str(REPO))
        for _ in range(3)
    ]
    print(f"  3 sensores iniciados (PID: {[s.pid for s in sensors]})")

    # 4. Aguarda sensores terminarem
    _wait(sensors, timeout=duration + 15)
    print("  Sensores encerrados.")

    # 5. Para tcpdump e agent_sink
    _stop(dump)
    _stop(sink)
    print(f"  Captura encerrada: {pcap_path}")

    # 6. Extrai fluxos com cicflowmeter
    ret = subprocess.run(
        ["cicflowmeter", "-f", str(pcap_path), "-c", str(flows_path)],
        capture_output=True,
        text=True,
    )
    if ret.returncode != 0:
        print(f"  AVISO cicflowmeter stderr: {ret.stderr.strip()}", file=sys.stderr)
    if not flows_path.exists() or flows_path.stat().st_size == 0:
        print(f"  ERRO: cicflowmeter nao gerou {flows_path}", file=sys.stderr)
        sys.exit(1)
    print(f"  Fluxos extraidos: {flows_path}")

    # 7. Build dataset com label
    sys.path.insert(0, str(REPO / "src"))
    from vulnforge.dataset.builder import build_dataset  # noqa: PLC0415

    meta = build_dataset(str(flows_path), label=label, out_path=str(dataset_path))
    print(f"  Dataset: {dataset_path} ({meta.rows} linhas, label='{label}')")
    return dataset_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Testbed SBSeg 2024 — VulnForge AI")
    parser.add_argument("--duration", type=int, default=60,
                        help="Duracao de cada cenario em segundos (default: 60)")
    parser.add_argument("--rate-normal", type=float, default=1.0,
                        help="Taxa de envio normal por sensor em pkt/s (default: 1.0)")
    parser.add_argument("--rate-dos", type=float, default=50.0,
                        help="Taxa de envio DoS por sensor em pkt/s (default: 50.0)")
    args = parser.parse_args()

    data_dir = REPO / "data" / "sbseg2024"
    tool_dir = data_dir / "tool"
    runs_dir = data_dir / "runs"
    tool_dir.mkdir(parents=True, exist_ok=True)
    runs_dir.mkdir(parents=True, exist_ok=True)

    normal_dataset = run_scenario(
        label="normal",
        benign=True,
        rate=args.rate_normal,
        duration=args.duration,
        pcap_path=runs_dir / "xrce_dds_normal.pcap",
        flows_path=runs_dir / "xrce_dds_normal_flows.csv",
        dataset_path=tool_dir / "xrce_dds_normal.csv",
    )

    dos_dataset = run_scenario(
        label="dos",
        benign=False,
        rate=args.rate_dos,
        duration=args.duration,
        pcap_path=runs_dir / "xrce_dds_dos.pcap",
        flows_path=runs_dir / "xrce_dds_dos_flows.csv",
        dataset_path=tool_dir / "xrce_dds_dos.csv",
    )

    # 8. Merge dos dois cenarios
    from vulnforge.dataset.builder import merge_datasets  # noqa: PLC0415

    merged = tool_dir / "xrce_dds_tool.csv"
    meta = merge_datasets([str(normal_dataset), str(dos_dataset)], out_path=str(merged))
    print(f"\n=== Dataset final: {merged} ({meta.rows} linhas, labels={meta.labels}) ===")
    print("\nPasso seguinte:")
    print("  python scripts/sbseg2024/compare_datasets.py")


if __name__ == "__main__":
    main()
