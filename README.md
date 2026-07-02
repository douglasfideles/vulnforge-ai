# VulnForge AI

VulnForge AI é um artefato acadêmico, offline-first, para transformar registros de
vulnerabilidades de protocolos publish/subscribe de IoT (DDS, XRCE-DDS e Zenoh) em cenários
controlados, conjuntos de dados rotulados, modelos IDS de referência e relatórios reproduzíveis.

**Título do artigo/artefato:** *VulnForge AI: geração controlada e reproduzível de cenários de
segurança para protocolos publish/subscribe de IoT*.

**Resumo:** o artefato implementa o pipeline
`vulnerabilidade → análise → cenário → execução controlada → dataset → IDS → relatório`.
A execução mínima é totalmente offline, não envia tráfego e não exige GPU, Docker, captura de
pacotes nem chave de LLM. O objetivo é apoiar experimentos científicos autorizados e
reproduzíveis; não é uma ferramenta para exploração de sistemas públicos.

## Estrutura do README.md

Este documento segue o modelo obrigatório do Comitê Técnico de Artefatos do SBRC 2026:

1. apresenta os selos solicitados e o ambiente de avaliação;
2. enumera dependências, riscos e instalação;
3. fornece um teste mínimo;
4. associa cada reivindicação a um experimento reproduzível, recursos, tempo e resultado;
5. identifica licença, limitações e evidências produzidas.

O mapa dos módulos e pontos de extensão está em
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), e a conformidade por selo está em
[`docs/ARTIFACT_CHECKLIST.md`](docs/ARTIFACT_CHECKLIST.md).

## Selos Considerados

Solicitam-se os quatro selos:

- **Artefatos Disponíveis (SeloD):** código, exemplos e testes possuem licença aberta. Para a
  submissão, os autores devem publicar a versão avaliada em repositório estável e arquivar uma
  release imutável (por exemplo, Zenodo), informando URL e DOI no HotCRP.
- **Artefatos Funcionais (SeloF):** instalação, teste mínimo, CLI e saídas esperadas são descritos
  abaixo.
- **Artefatos Sustentáveis (SeloS):** o código é modular, tipado, testado e documentado por
  responsabilidade.
- **Experimentos Reprodutíveis (SeloR):** `scripts/reproduce.sh` automatiza as reivindicações
  principais e produz um resumo verificável.

## Informações básicas

### Conteúdo do repositório

| Caminho | Conteúdo |
|---|---|
| `src/vulnforge/` | implementação do pacote e da CLI `protoforge` |
| `tests/` | testes unitários e de integração |
| `examples/` | vulnerabilidade e fluxos sintéticos pequenos usados na reprodução |
| `scripts/` | instalação, teste mínimo, testes completos e reprodução |
| `docs/` | arquitetura e checklist do CTA |
| `REQUIREMENTS.md` | especificação funcional e contratos de dados |
| `Dockerfile`, `docker-compose.yml` | ambiente reproduzível alternativo |

### Ambiente de referência

- Linux x86-64 (validado em Ubuntu/WSL2);
- Python 3.11 ou 3.12;
- 1 CPU (2 recomendadas), sem GPU;
- 2 GB de RAM;
- 1 GB de espaço livre durante a instalação;
- acesso à internet apenas para a instalação inicial das dependências.

O teste mínimo leva tipicamente **menos de 2 minutos** depois da instalação. A suíte completa leva
tipicamente **menos de 1 minuto**. Em volumes montados do Windows/WSL, a criação do ambiente
virtual pode ser consideravelmente mais lenta; prefira o sistema de arquivos Linux.

## Dependências

As dependências de execução estão fixadas por versão em `requirements.txt` e `pyproject.toml`:
Python ≥3.11, Typer 0.15.2, Click 8.1.8, Pydantic 2.10.6, pydantic-settings 2.7.1,
NumPy 2.2.2, pandas 2.2.3, SciPy 1.15.1, scikit-learn 1.6.1, joblib 1.4.2,
Requests 2.32.3 e PyYAML 6.0.2.
Pytest 8.3.4, HTTPX 0.28.1 e AnyIO 4.8.0 compõem o extra `dev`; as duas últimas versões
mantêm compatibilidade determinística do cliente de teste da API.

Dependências opcionais:

- `api`: FastAPI 0.115.8 e Uvicorn 0.34.0;
- `traffic`: Scapy 2.6.1 para análise de PCAP;
- `zenoh` e `dds`: bibliotecas oficiais dos protocolos;
- `tcpdump`, CICFlowMeter e Docker: somente para captura/execução real ou conversão de PCAP.

Nenhum benchmark ou serviço de terceiros é necessário para a reprodução padrão. Os CSVs em
`examples/` são entradas sintéticas, pequenas e versionáveis. LLMs em nuvem são opcionais e não
são usados nos resultados de referência.

## Preocupações com segurança

O artefato contém geradores de tráfego para pesquisa. Para uma avaliação segura:

1. execute apenas `scripts/run-minimal.sh`, `scripts/run-tests.sh` ou
   `scripts/reproduce.sh`; esses caminhos usam **dry-run** e não enviam pacotes;
2. não use `--no-dry-run --execute --yes` fora de laboratório isolado e autorizado;
3. a execução real só aceita loopback, RFC1918 e link-local; alvos públicos são recusados;
4. código de mutação gerado é limitado a transformação de bytes por uma whitelist AST;
5. nunca forneça credenciais no repositório. A reprodução não requer chave, nuvem ou SSH.

Para testes de tráfego real, use uma VM/rede sem rota para a Internet. O operador é responsável
pela autorização do ambiente. Consulte também o enquadramento ético em `REQUIREMENTS.md`.

## Instalação

### Opção A — ambiente virtual (recomendada)

Em uma máquina limpa:

```bash
git clone <URL-ESTAVEL-DO-ARTEFATO>
cd copy-vulnforge-ai
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev,api,traffic]'
protoforge --help
```

Substitua `<URL-ESTAVEL-DO-ARTEFATO>` pela URL registrada no HotCRP. Em Windows PowerShell, ative
com `.venv\Scripts\Activate.ps1`. Não use `sudo pip`.

O atalho equivalente para Linux/macOS é:

```bash
scripts/setup.sh
```

### Opção B — Docker

```bash
docker compose build
docker compose run --rm vulnforge
```

O Compose usa apenas volumes relativos (`./data`, `./scenarios`, `./reports`) e executa o teste
mínimo offline por padrão.

## Teste mínimo

Com o ambiente virtual ativo:

```bash
scripts/run-minimal.sh
```

O script executa importação, análise por regras, geração de YAML, dry-run, rotulação de fluxos,
treinamento de RandomForest/LogisticRegression e relatório. Não envia tráfego.

Saídas esperadas:

- `scenarios/minimal.yaml`;
- `data/vulnforge.db`;
- `data/datasets/demo.csv` e `data/datasets/demo.csv.meta.json`;
- `data/models/demo_RandomForest.joblib`;
- `data/models/demo_ids_report.md`;
- `reports/run-*.md`;
- mensagem final `Minimal pipeline complete`.

Para validar o código antes dos experimentos:

```bash
scripts/run-tests.sh
```

Resultado esperado: todos os testes aprovados e nenhum traceback. O script grava uma transcrição
em `results/test-report.txt`.

## Experimentos

Todos os experimentos principais podem ser reproduzidos de uma vez:

```bash
scripts/reproduce.sh
```

Tempo esperado: 1–3 minutos após a instalação; recursos máximos recomendados: 1 CPU, 2 GB RAM e
100 MB adicionais para resultados. O script limpa somente `results/reproduction/`, usa um banco
isolado nesse diretório e não altera resultados anteriores em `data/`.

Ao final, consulte:

- `results/reproduction/summary.json`, resumo legível por máquina;
- `results/reproduction/summary.md`, tabela para inspeção;
- `results/reproduction/commands.log`, transcrição da execução;
- datasets, modelo e relatório sob `results/reproduction/`.

### Reivindicação #1 — análise offline determinística

**Reivindicação:** uma descrição de esgotamento de recursos do XRCE-DDS é classificada como
`flooding`, com rótulo `xrce_dds_flooding`, fonte `rules` e confiança `0.6`.

```bash
VULNFORGE_LLM_PROVIDER=offline protoforge analyze \
  --text "XRCE-DDS agent resource exhaustion denial of service"
```

Resultado esperado: JSON contendo `"protocol": "XRCE-DDS"`,
`"likely_attack_type": "flooding"`, `"dataset_label": "xrce_dds_flooding"`,
`"confidence": 0.6` e `"source": "rules"`.

### Reivindicação #2 — segurança por construção

**Reivindicação:** o artefato recusa alvos fora das redes de laboratório e rejeita mutadores com
imports, I/O, avaliação dinâmica, atributos não permitidos, loops ilimitados ou constantes fora do
limite.

```bash
python -m pytest -q tests/test_codegen_safety.py
```

Resultado esperado: todos os casos aprovados. Os testes incluem `8.8.8.8`, `192.0.2.10`,
`100.64.0.1`, código com `import`, `open`, `eval`, `while`, `**` e mutadores válidos.

### Reivindicação #3 — pipeline reproduzível e IDS

**Reivindicação:** para o conjunto sintético linearmente separável, ambos os classificadores
atingem F1 `1.00`; em empate, RandomForest é selecionado e persistido.

```bash
scripts/reproduce.sh
python -m json.tool results/reproduction/summary.json
```

Resultado esperado:

```text
pipeline_status: passed
best_model: RandomForest
RandomForest.f1: 1.0
LogisticRegression.f1: 1.0
dry_run_status: dry-run
```

Os números validam a reprodutibilidade do pipeline, não representam desempenho em tráfego real.

### Reivindicação #4 — enquadramento real dos protocolos

**Reivindicação:** os plugins embutidos geram mensagens com enquadramento identificável de
XRCE-DDS (`XRCE`), DDS/RTPS (`RTPS`) e Zenoh, e expõem porta/transporte determinísticos.

```bash
protoforge protocols
python -m pytest -q tests/test_protocols_validation.py
```

Resultado esperado: XRCE-DDS `8888/udp`, Zenoh `7447/tcp`, DDS `7400/udp` e todos os testes
aprovados. A coluna `official-lib` pode ser `False`; isso indica degradação para framing/probe de
transporte e não falha do experimento offline.

## Limitações e interpretação

- Os fluxos de referência são sintéticos e deliberadamente separáveis.
- Dry-run valida comandos e persistência, mas não demonstra impacto em um alvo real.
- Resultados com LLM externa não fazem parte das reivindicações, pois dependem de serviço e modelo.
- Docker, tcpdump, bibliotecas oficiais e CICFlowMeter são extensões; ausência deles não invalida a
  reprodução offline.

## LICENSE

Copyright © 2026 autores do VulnForge AI.

Este artefato é distribuído sob a licença **GNU General Public License v3.0 ou posterior
(GPL-3.0-or-later)**. Consulte [`LICENSE`](LICENSE). Dependências mantêm suas próprias licenças.

## Citação

Os metadados de citação estão em [`CITATION.cff`](CITATION.cff). Antes da submissão pública, os
autores devem substituir os campos marcados como `TODO` pelos nomes, DOI e URL definitivos.
