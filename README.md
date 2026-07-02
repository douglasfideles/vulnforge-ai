# VulnForge AI

**Artefato do artigo:** *VulnForge AI: Geração Controlada de Cenários de Ataque e Datasets Rotulados para Protocolos IoT Pub/Sub (DDS, XRCE-DDS, Zenoh)*

VulnForge AI é uma ferramenta de pesquisa acadêmica em cibersegurança para protocolos IoT publish/subscribe emergentes (**DDS, XRCE-DDS, Zenoh**). Ela transforma registros de vulnerabilidades em **cenários de laboratório controlados**, captura o tráfego de rede resultante, produz **datasets rotulados** e treina **modelos baseline de IDS** (Intrusion Detection System). O objetivo é produzir experimentos reprodutíveis, citáveis e seguros — não ferramentas ofensivas.

O pipeline implementado é:

```
vuln → análise (LLM/regras) → cenário YAML → execução + captura → dataset → IDS → relatório
```

## Resumo do artigo

O artigo apresenta uma abordagem para acelerar a criação de datasets de tráfego malicioso para protocolos IoT pub/sub, combinando análise automatizada de vulnerabilidades, geração de cenários de ataque controlados, captura de pacotes (PCAP), extração de *flows* e treinamento de classificadores baseline. A ferramenta prioriza a reproducibilidade e a segurança: ataques são restritos a alvos de laboratório, o código gerado por LLM é confinado por um sandbox AST, e o modo *dry-run* é o padrão.

---

## Estrutura do repositório

```
vulnforge-ai/
├── src/vulnforge/              # Código-fonte principal
│   ├── cli.py                  # Interface de linha de comando (protoforge)
│   ├── config.py               # Configurações via pydantic-settings
│   ├── models.py               # Modelos Pydantic v2 (Vulnerability, Scenario, etc.)
│   ├── db.py                   # Persistência SQLite
│   ├── api.py                  # API FastAPI opcional (somente leitura)
│   ├── vulnerability/          # Normalização e repositório de vulnerabilidades
│   ├── llm/                    # Adapter LLM, analisador de ameaças, síntese de ataques
│   ├── protocols/              # Plugins de protocolo (XRCE-DDS, Zenoh, DDS)
│   ├── scenarios/              # Geração e validação de cenários YAML
│   ├── traffic/                # Ataques nativos, runner, safety guard, sandbox AST
│   ├── validation/             # Análise PCAP e validação de efeito
│   ├── dataset/                # Construção de datasets via CSV/PCAP + CICFlowMeter
│   ├── ids/                    # Treinamento de IDS baseline
│   └── reports/                # Geração de relatórios Markdown
├── data/                       # Dados de exemplo e artefatos gerados
│   ├── raw/vulns.json          # Exemplo de vulnerabilidades
│   ├── flows/example.csv       # Exemplo de flows
│   └── datasets/               # Datasets rotulados de exemplo
├── scenarios/                  # Cenários YAML (exemplos e gerados)
├── scripts/                    # Scripts auxiliares
│   ├── setup.sh                # Instalação do ambiente
│   └── run-minimal.sh          # Teste mínimo offline
├── tests/                      # Suite pytest
├── Dockerfile                  # Imagem Docker (Python 3.11 slim)
├── docker-compose.yml          # Orquestração do teste mínimo
├── requirements.txt            # Dependências com versões fixas
├── pyproject.toml              # Configuração do pacote e entry-point
├── LICENSE                     # GPL-3.0-or-later
└── README.md                   # Este arquivo
```

---

## Selos considerados

Os selos considerados para avaliação pelo Comitê Técnico de Artefatos são:

- **Artefatos Disponíveis (SeloD)** — repositório público estável com README.md mínimo.
- **Artefatos Funcionais (SeloF)** — código executável, com dependências declaradas e teste mínimo.
- **Artefatos Sustentáveis (SeloS)** — código modularizado, documentado e de fácil compreensão.
- **Experimentos Reprodutíveis (SeloR)** — scripts automatizados para reproduzir as principais reivindicações.

---

## Informações básicas

### Ambiente de execução

- **Sistema operacional:** Linux, macOS ou Windows/WSL2.
- **Linguagem:** Python ≥3.11 (desenvolvido e testado em Python 3.12).
- **Hardware mínimo:** ~2 GB RAM, ~500 MB de disco (sem GPU/CUDA).
- **Rede:** O caminho mínimo não requer rede. A análise via LLM em nuvem requer conexão e uma chave de API.

### Componentes opcionais

- `tcpdump` — captura real de tráfego.
- Docker — execução de ataques em containers.
- `cicflowmeter` — conversão PCAP → CSV de flows (já incluído nas dependências).
- `scapy` — análise avançada de PCAP (já incluído).
- Bibliotecas de protocolo reais: `eclipse-zenoh`, `cyclonedds` (extras opcionais).

---

## Dependências

As dependências principais estão em `requirements.txt` com versões fixas:

```text
typer==0.15.3
click==8.1.8
pydantic==2.11.7
pydantic-settings==2.14.1
pandas==2.2.3
scikit-learn==1.6.1
joblib==1.4.2
requests==2.32.3
PyYAML==6.0.2
fastapi==0.115.12
uvicorn==0.34.2
scapy==2.6.1
pytest==8.3.5
cicflowmeter==0.5.0
```

Extras definidos em `pyproject.toml`:

- `api`: FastAPI + Uvicorn
- `traffic`: Scapy
- `zenoh`: eclipse-zenoh
- `dds`: cyclonedds
- `dev`: pytest

Para este artefato, as dependências de `api`, `traffic` e `cicflowmeter` já estão na `requirements.txt` base para facilitar a execução completa sem extras adicionais.

---

## Preocupações com segurança

VulnForge AI é uma ferramenta de **pesquisa acadêmica** para ambientes de laboratório isolados.

- O **safety guard** restringe alvos de ataque a redes loopback (`127.0.0.0/8`), privadas RFC1918 (`10/8`, `172.16/12`, `192.168/16`) e link-local (`169.254/16`). IPs ou hostnames públicos são rejeitados.
- O modo padrão é **dry-run**: nenhum tráfego é enviado.
- A execução real requer `--no-dry-run --execute` e confirmação explícita (`--yes` ou prompt interativo).
- Código gerado por LLM é validado por um sandbox AST antes de execução.
- **Não execute ataques contra redes que você não tem permissão para testar.**

---

## Instalação

### Opção 1: Ambiente virtual local

```bash
# Clonar o repositório
git clone <URL_DO_REPOSITORIO>
cd vulnforge-ai

# Executar script de setup
bash scripts/setup.sh

# Ativar ambiente
source .venv/bin/activate

# Verificar instalação
protoforge --help
```

### Opção 2: Docker

```bash
docker compose up --build
```

O container executa automaticamente `scripts/run-minimal.sh` e escreve artefatos em `./data`, `./scenarios` e `./reports`.

---

## Teste mínimo

O teste mínimo executa todo o pipeline em modo **offline e seguro**, sem rede, GPU, chave LLM, tcpdump ou Docker:

```bash
bash scripts/run-minimal.sh
```

Esse script realiza:

1. Importação de vulnerabilidades (`data/raw/vulns.json`).
2. Análise rule-based da CVE-2024-0001 (protocolo XRCE-DDS, ataque flooding).
3. Geração de cenário YAML em `scenarios/generated/cve_0001.yaml`.
4. Execução dry-run do cenário (apenas imprime comandos).
5. Construção de dataset rotulado em `data/datasets/out.csv`.
6. Treinamento de IDS baseline (RandomForest + LogisticRegression).
7. Geração de relatório Markdown em `reports/`.

Resultado esperado: mensagem `MINIMAL TEST PASSED.` com os caminhos dos artefatos gerados.

---

## Experimentos

### Reivindicação #1: Análise automatizada de vulnerabilidades identifica corretamente o tipo de ataque

**Comando:**

```bash
protoforge analyze --text "XRCE-DDS agent resource exhaustion via UDP flood" --protocol XRCE-DDS
```

**Resultado esperado:** `likely_attack_type=flooding`, `protocol=XRCE-DDS`, `confidence=0.6`, `source=rules`.

---

### Reivindicação #2: Geração de cenários controlados a partir da análise

**Comando:**

```bash
protoforge generate-scenario --vuln-id CVE-2024-0001 --out scenarios/generated/cve_0001.yaml
```

**Resultado esperado:** arquivo YAML em `scenarios/generated/cve_0001.yaml` com comandos de tráfego normal e ataque.

---

### Reivindicação #3: Execução segura em dry-run imprime comandos sem enviar tráfego

**Comando:**

```bash
protoforge run-scenario --file scenarios/generated/cve_0001.yaml --dry-run
```

**Resultado esperado:** lista dos comandos que seriam executados, sem envio real de pacotes.

---

### Reivindicação #4: Sandbox AST rejeita mutadores maliciosos

**Teste automatizado:**

```bash
pytest tests/test_codegen_sandbox.py -q
```

**Resultado esperado:** todos os testes passam, demonstrando que código com `import`, `open`, `eval`, atributos não permitidos, `while`, `**` e constantes grandes são rejeitados.

---

### Reivindicação #5: Treinamento de IDS baseline atinge F1 ≈ 1.00 em dataset linearmente separável

**Comando:**

```bash
protoforge train-ids --dataset data/datasets/example_labeled.csv --label-column label
```

**Resultado esperado:** `best_model=RandomForest`, `f1=1.00`, artefatos `data/models/example_labeled_RandomForest.joblib` e `data/models/example_labeled_ids_report.md`.

---

### Reivindicação #6: Todo o pipeline pode ser executado via Docker

```bash
docker compose up --build
```

**Resultado esperado:** container executa `scripts/run-minimal.sh` e gera artefatos nos volumes relativos `./data`, `./scenarios`, `./reports`.

---

## Execução dos testes

```bash
# Todos os testes
pytest -q

# Com cobertura detalhada
pytest -q --tb=short
```

**Resultado esperado:** 56 testes passando.

---

## Reprodutibilidade

- Todas as dependências estão fixadas em `requirements.txt`.
- O treinamento de IDS usa `random_state=42`.
- A análise via LLM usa `temperature=0` e seed fixa (`VULNFORGE_LLM_SEED=1337` por padrão).
- O caminho offline rule-based é 100% determinístico.
- O teste mínimo pode ser executado sem qualquer chave de API ou acesso externo.

---

## Apêndice

Recursos adicionais ou restritos (chaves, infraestrutura cloud, etc.) devem ser descritos no arquivo `APPENDIX.md`, se aplicável. Para este artefato, **não são necessários recursos adicionais** para a avaliação dos selos D/F/S/R.

---

## LICENSE

Este projeto é distribuído sob a licença **GPL-3.0-or-later**. Veja o arquivo `LICENSE` para detalhes.
