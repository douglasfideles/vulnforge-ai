# VulnForge AI

[![Licença: GPL-3.0](https://img.shields.io/badge/licen%C3%A7a-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Testes](https://img.shields.io/badge/testes-50%20passing-brightgreen.svg)](#testes)
[![Sem GPU](https://img.shields.io/badge/GPU-n%C3%A3o%20requerida-success.svg)](#requisitos-mínimos)

Ferramenta de pesquisa acadêmica em cibersegurança de protocolos IoT emergentes — foco em
**DDS, XRCE-DDS e Zenoh**. Transforma informações de vulnerabilidades em **cenários controlados
de laboratório**, captura de tráfego, **datasets rotulados** e modelos **IDS baseline**.

> ⚠️ **Uso exclusivamente acadêmico, em laboratório isolado.** Os ataques só executam contra
> alvos com IP **privado/loopback**. Não use contra produção ou redes públicas.

Pipeline:
`vuln → análise (LLM/regras) → cenário YAML → execução + captura → dataset → IDS → relatório`

---

## Índice

- [Requisitos mínimos](#requisitos-mínimos)
- [Início rápido (3 caminhos)](#início-rápido-3-caminhos)
- [Execução mínima passo a passo (com saída esperada)](#execução-mínima-passo-a-passo-com-saída-esperada)
- [Docker](#docker)
- [Reprodutibilidade](#reprodutibilidade)
- [Configuração de LLM (opcional)](#configuração-de-llm-opcional)
- [Uso completo da CLI](#uso-completo-da-cli-protoforge)
- [Síntese de ataque a partir do CVE](#síntese-de-ataque-a-partir-do-cve-forge-attack)
- [Ataques nativos](#ataques-nativos)
- [Validade protocolar (Fase 2)](#validade-protocolar-e-validação-de-efeito-fase-2)
- [Estrutura](#estrutura)
- [API opcional (FastAPI)](#api-opcional-fastapi)
- [Testes](#testes)
- [Segurança e limitações](#segurança-e-limitações)

---

## Requisitos mínimos

O **teste mínimo é Python puro, offline e dry-run** — **não requer GPU, rede, chave de LLM,
`tcpdump`, Docker nem alvos externos**.

| Recurso | Mínimo | Observação |
|---|---|---|
| **CPU/GPU** | qualquer x86-64; **GPU não é necessária** | nenhuma dependência CUDA/GPU |
| **RAM** | ~2 GB | scikit-learn treina o IDS baseline em segundos |
| **Disco** | ~500 MB | venv + dependências; sem datasets pesados |
| **Python** | **3.11+** | testado em 3.12 |
| **SO** | Linux, macOS ou Windows/WSL2 | — |
| **Rede** | não necessária no teste mínimo | só usada no modo LLM em nuvem |

**Opcionais** (só para recursos avançados): `tcpdump` (captura real de PCAP), **Docker** (modo
container e ataques empacotados), chave de LLM (modo nuvem — veja [LLM](#configuração-de-llm-opcional)).

**Ambiente de referência testado:** Python 3.12.3, Linux WSL2 (kernel 6.6), Docker 29.x +
Compose v2. Versões exatas das dependências em [`requirements.txt`](requirements.txt).

---

## Início rápido (3 caminhos)

### A) Script (recomendado) — instala e roda o teste mínimo

```bash
cd vulnforge-ai
bash scripts/setup.sh                 # cria .venv e instala dependências fixadas
source .venv/bin/activate
bash scripts/run-minimal.sh           # pipeline offline end-to-end
```

### B) Manual

```bash
cd vulnforge-ai
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt       # versões FIXADAS (reprodutível)
pip install -e .                      # registra o comando `protoforge`
# extras opcionais:  pip install -e ".[api,dev]"
bash scripts/run-minimal.sh
```

### C) Docker — sem instalar nada localmente

```bash
cd vulnforge-ai
docker compose up --build             # constrói a imagem e roda o teste mínimo
```

Os três caminhos terminam com `TESTE MINIMO CONCLUIDO COM SUCESSO` e geram cenário, dataset,
modelo IDS e relatório Markdown.

---

## Execução mínima passo a passo (com saída esperada)

Todos os comandos rodam **a partir da raiz do repositório** (`vulnforge-ai/`), com a venv ativada.
Equivalem exatamente ao que [`scripts/run-minimal.sh`](scripts/run-minimal.sh) automatiza.

### 1. Importar vulnerabilidades (JSON → SQLite)

```bash
protoforge import-vulns --file data/raw/vulns.json
```

```text
Importadas 4 vulnerabilidades:
  - CVE-2024-0001 | high   | XRCE-DDS Agent entity resource exhaustion via unbounded enti
  - CVE-2024-0002 | medium | Zenoh router memory exhaustion through maximum-size frames
  - CVE-2024-0003 | medium | XRCE-DDS malformed message parser robustness
  - CVE-2024-0004 | medium | Zenoh protocol fuzzing and KEEP_ALIVE flooding
```

### 2. Analisar o CVE (rule-based offline — sem chave de LLM)

```bash
protoforge analyze --vuln-id CVE-2024-0001 --protocol XRCE-DDS
```

```text
... | INFO | vulnforge.llm.adapter | OPENROUTER_API_KEY ausente; usando modo rule-based offline.
{
  "protocol": "XRCE-DDS",
  "likely_attack_type": "flooding",
  "dataset_label": "xrce_dds_flooding",
  "confidence": 0.6,
  "source": "rules"
}
```

### 3. Gerar o cenário YAML

```bash
protoforge generate-scenario --vuln-id CVE-2024-0001 --out scenarios/generated/cve_0001.yaml
```

```text
Cenario gerado: scenarios/generated/cve_0001.yaml
```

### 4. Executar o cenário em DRY-RUN (apenas imprime os comandos — nada é enviado)

```bash
protoforge run-scenario --file scenarios/examples/xrce_dds_flooding.yaml --dry-run
```

```text
# DRY-RUN cenario=xrce_dds_flooding run_id=run-AAAAMMDD-HHMMSS-xxxxxx
# comandos (NAO executados):
  $ tcpdump -i any -w data/runs/xrce_dds_flooding.pcap
  $ python -m vulnforge.traffic.attacks.flooding --target 127.0.0.1 --port 8888 ... --benign
  $ docker run --rm iotedu-attack-xrce-dds-udp-dos:latest 127.0.0.1 8888
run_id=run-AAAAMMDD-HHMMSS-xxxxxx status=dry-run
```

> Anote o `run_id` impresso: o run é **persistido mesmo em dry-run** e alimenta o relatório (passo 7).

### 5. Construir o dataset rotulado (CSV de flows → CSV rotulado + metadata)

```bash
protoforge build-dataset --flows data/flows/example.csv --label flooding --out data/datasets/out.csv
```

```text
Dataset: data/datasets/out.csv (30 linhas, labels=['flooding'])
```

### 6. Treinar o IDS baseline (RandomForest + LogisticRegression)

```bash
protoforge train-ids --dataset data/datasets/example_labeled.csv --label-column label
```

```text
IDS treinado. Melhor=RandomForest f1=1.000 -> data/models/example_labeled_RandomForest.joblib
{
  "best_model": "RandomForest",
  "rows": 120,
  "metrics": [ {"model": "RandomForest", "accuracy": 1.0, "f1": 1.0}, ... ]
}
```

> Os valores numéricos esperados estão na seção [Reprodutibilidade](#reprodutibilidade).

### 7. Gerar o relatório Markdown end-to-end

```bash
protoforge report --run-id <RUN_ID_DO_PASSO_4>
```

```text
Relatorio: reports/<RUN_ID>.md
```

Veja um relatório de exemplo em [`reports/example_report.md`](reports/example_report.md).

---

## Docker

A imagem é **Python 3.11-slim, sem GPU/CUDA**, com dependências fixadas. O `CMD` padrão executa
o teste mínimo completo (offline, dry-run).

```bash
# Construir e rodar o teste mínimo (resultados gravados em ./data e ./reports via volume)
docker compose up --build

# Abrir um shell interativo no container
docker compose run --rm vulnforge bash

# Rodar um comando específico da CLI dentro do container
docker compose run --rm vulnforge protoforge list-vulns
```

Detalhes alinhados às boas práticas de artefato:
- **Base fixada** (`python:3.11-slim`) e **uma única camada de instalação** (sem instalar a mesma
  lib duas vezes).
- `docker-compose.yml` **sem o campo `version:`** obsoleto e **sem caminhos pessoais** — os volumes
  usam paths relativos (`./data`, `./scenarios`, `./reports`).
- `.dockerignore` mantém o contexto de build leve (exclui `.venv/`, `.git/`, artefatos de execução).

---

## Reprodutibilidade

- **Dependências fixadas:** [`requirements.txt`](requirements.txt) trava as versões exatas do
  ambiente de referência testado. Use `pip install -r requirements.txt` (não `>=`) para reproduzir.
- **Determinismo do LLM:** no modo local/nuvem, `temperature=0` + `seed` (no `.env`) tornam a
  análise determinística. O **modelo e o seed usados são registrados** no `RunRecord` e no relatório.
  Sem chave/LLM, o modo offline rule-based é o caminho **citável e 100% determinístico**.
- **Ambiente de referência:** Python 3.12.3, Linux WSL2 (kernel 6.6).

### Resultados esperados — IDS baseline no dataset de exemplo

`protoforge train-ids --dataset data/datasets/example_labeled.csv --label-column label`
(120 linhas, `test_size=0.3`, dataset sintético linearmente separável):

| Modelo | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| **RandomForest** (selecionado) | 1.00 | 1.00 | 1.00 | 1.00 |
| LogisticRegression | 1.00 | 1.00 | 1.00 | 1.00 |

> Métricas perfeitas são esperadas: o dataset de exemplo é **sintético e separável**, servindo para
> validar o pipeline ponta a ponta — **não** como benchmark de detecção em tráfego real.

---

## Configuração de LLM (opcional)

Por padrão o provider é **OpenRouter**. Sem `OPENROUTER_API_KEY`, o analyzer cai automaticamente
para o modo **rule-based offline** (funciona sem rede). Copie e edite o `.env`:

```bash
cp .env.example .env
```

```ini
VULNFORGE_LLM_PROVIDER=openrouter        # openrouter | local | offline
OPENROUTER_API_KEY=sk-...
VULNFORGE_LLM_MODEL=anthropic/claude-sonnet-4
# Modelo local (Ollama/llama.cpp compatível com OpenAI):
# VULNFORGE_LLM_PROVIDER=local
# VULNFORGE_LLM_BASE_URL=http://localhost:11434/v1
```

---

## Uso completo da CLI (`protoforge`)

```bash
# 1. Importar vulnerabilidades (JSON/CSV)
protoforge import-vulns --file data/raw/vulns.json

# 2. Analisar (LLM ou rule-based) -> JSON estruturado
protoforge analyze --vuln-id CVE-2024-0001 --protocol XRCE-DDS

# 3. Gerar cenário YAML (reusa containers do repo ataques/; --native usa ataque Python)
protoforge generate-scenario --vuln-id CVE-2024-0001 --out scenarios/generated/cve_0001.yaml

# 4. Executar cenário — DRY-RUN por padrão (apenas imprime comandos)
protoforge run-scenario --file scenarios/examples/xrce_dds_flooding.yaml --dry-run

#    Execução REAL (lab only): exige --no-dry-run --execute --yes e alvo privado
protoforge run-scenario --file scenarios/examples/xrce_dds_flooding.yaml --no-dry-run --execute --yes

# 5. Construir dataset rotulado (CSV de flows ou PCAP via CICFlowMeter)
protoforge build-dataset --flows data/flows/example.csv --label flooding --out data/datasets/out.csv

# 6. Treinar IDS baseline (RandomForest + LogisticRegression)
protoforge train-ids --dataset data/datasets/example_labeled.csv --label-column label

# 7. Relatório Markdown end-to-end
protoforge report --run-id <RUN_ID>

# Utilitários
protoforge list-vulns                                   # lista vulns importadas
protoforge protocols                                    # lista plugins de protocolo
protoforge gen-attack-docker --type all --out docker/attacks   # Dockerfiles dos ataques nativos
```

---

## Síntese de ataque a partir do CVE (`forge-attack`)

Diferente do `gen-attack-docker` (templates fixos), o `forge-attack` **cria o ataque com base no
CVE/descrição**: a LLM sintetiza o código de criação do payload específico para a vulnerabilidade,
o código passa por um **sandbox de validação** (AST whitelist — sem imports/IO/exec) e é
**auto-testado** antes de ser escrito. Sem LLM, há fallback que adapta o payload ao tipo de
ataque inferido.

```bash
# A partir de um CVE já importado (gera .py + bundle Docker + cenário YAML)
protoforge forge-attack --vuln-id CVE-2024-0002 --scenario-out scenarios/generated/cve_0002.yaml

# A partir de uma descrição textual livre
protoforge forge-attack --text "XRCE-DDS agent crashes on malformed session headers" --protocol XRCE-DDS
```

Saídas:
- `generated/attacks/<id>.py` — ataque funcional parametrizado (`--target/--port/...`), com a guarda
  de IP privado/loopback embutida.
- `docker/attacks/<id>/` — `Dockerfile` + `entrypoint.sh` + **`docker-compose.yml`** ligando o
  atacante ao alvo de laboratório (`iotedu-attack-xrce-dds-agent` / `iotedu-attack-zenoh-router`).

> **Honestidade acadêmica:** o "exploit" é a síntese/parametrização de técnicas conhecidas
> (flood/fuzz/replay/oversized/malformed/injection) guiada pelo CVE — **não** geração de 0-day.
> O sandbox garante que o código gerado só constrói bytes de payload, sem acesso a IO/sistema.

Para usar a LLM (em vez do fallback offline), configure `OPENROUTER_API_KEY` no `.env`.

---

## Ataques nativos

Executáveis diretamente (aplicam a guarda de IP privado/loopback):

```bash
python -m vulnforge.traffic.attacks.flooding  --target 127.0.0.1 --port 8888 --transport udp --duration 10
python -m vulnforge.traffic.attacks.oversized --target 127.0.0.1 --port 7447 --transport tcp
python -m vulnforge.traffic.attacks.malformed --target 127.0.0.1 --port 8888
python -m vulnforge.traffic.attacks.fuzz      --target 127.0.0.1 --port 7447 --strategy all
python -m vulnforge.traffic.attacks.replay    --target 127.0.0.1 --port 8888 --pcap data/runs/xrce_dds_normal.pcap
```

Tipos: **flooding** (`--benign` = baseline), **replay** (de PCAP), **fuzz** (estratégias),
**oversized** (payload máximo), **malformed** (headers corrompidos).

---

## Validade protocolar e validação de efeito (Fase 2)

Para que os ataques sejam **academicamente válidos** (e não bytes aleatórios), o VulnForge
ancora cada ataque em um **plugin de protocolo real**:

```bash
protoforge protocols      # lista plugins e se a lib real (sessão válida) está instalada
```

- A **mensagem-base** é gerada pelo plugin com o **framing real** do protocolo (cookie `XRCE`,
  frame Zenoh, header `RTPS`). A LLM gera **apenas a mutação** maliciosa
  (`mutate(baseline, seq, rng)`), presa ao sandbox sem `import`/IO.
- Plugins usam a **lib oficial** quando instalada (extras `zenoh`/`dds`) para sessão/sonda fortes;
  sem ela, degradam para sonda de transporte e rotulam o ataque como `unvalidated`.
- Acoplar um **novo protocolo**: herde de `vulnforge.protocols.base.ProtocolPlugin`, implemente
  `baseline_message` e `health_probe`, e chame `registry.register(SeuPlugin())`.

O **harness de validação** confirma o efeito real no alvo do laboratório:

```bash
protoforge run-scenario --file scenarios/examples/xrce_dds_flooding.yaml --no-dry-run --execute --yes --validate
```

Faz **sonda antes** → ataque → captura → **sonda depois** → análise de PCAP, emitindo um
**veredito** (`valid` / `invalid` / `inconclusive`). Só cenários `valid` devem virar amostras
rotuladas de ataque no dataset — é isso que separa um ataque real de um "falso".

### Reuso do repositório `ataques/`

Os cenários XRCE-DDS/Zenoh reusam os containers Docker já prontos do repo irmão `ataques/`
(`iotedu-attack-xrce-dds-*`, `iotedu-attack-zenoh-pico-*`) e os alvos
(`servers/xrce-dds-agent` UDP 8888, `servers/zenoh-router` TCP 7447). Suba os alvos com os scripts
`build-images-servers.sh` daquele repositório antes de executar cenários reais.

---

## Estrutura

```
src/vulnforge/
├── vulnerability/   # normalizer, repository (SQLite), collector
├── llm/             # adapter (OpenRouter/local), rules offline, analyzer, exploit_synth (mutator)
├── protocols/       # plugins reais plugáveis: base, registry, xrce_dds, zenoh, dds
├── scenarios/       # schema (Pydantic), generator, examples/
├── traffic/         # safety, runner (probe+tcpdump), attacks/ nativos, codegen (sandbox), docker_gen
├── validation/      # harness (veredito de efeito), pcap_analysis
├── dataset/         # builder (CSV/PCAP→rotulado), cicflowmeter
├── ids/             # trainer (RF + LogReg, métricas, joblib, md)
└── reports/         # generator (Markdown end-to-end)

scripts/             # setup.sh (ambiente) + run-minimal.sh (teste mínimo)
Dockerfile, docker-compose.yml, .dockerignore   # execução em container
requirements.txt     # dependências FIXADAS (reprodutibilidade)
```

---

## API opcional (FastAPI)

```bash
pip install -e ".[api]"
uvicorn vulnforge.api:app --reload    # /health, /analyze, /generate-scenario
```

---

## Testes

```bash
pip install -e ".[dev]"      # ou: pip install -r requirements-dev.txt
pytest -q
```

Resultado esperado: **50 passed**.

---

## Segurança e limitações

- Runner é **dry-run por padrão**; execução real exige `--no-dry-run --execute --yes` + confirmação.
- Ataques restritos a **IP privado/loopback** (`vulnforge.traffic.safety`).
- Cenários sintéticos de laboratório; datasets/IDS são **baseline**, não produção.
- Sem frontend e sem autenticação neste MVP.

Licença: **GPL-3.0-or-later** (veja [LICENSE](LICENSE)).
