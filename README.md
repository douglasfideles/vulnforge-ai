# VulnForge AI

Ferramenta de pesquisa acadêmica em cibersegurança de protocolos IoT emergentes — foco em
**DDS, XRCE-DDS e Zenoh**. Transforma informações de vulnerabilidades em **cenários controlados
de laboratório**, captura de tráfego, **datasets rotulados** e modelos **IDS baseline**.

> ⚠️ **Uso exclusivamente acadêmico, em laboratório isolado.** Os ataques só executam contra
> alvos com IP **privado/loopback**. Não use contra produção ou redes públicas.

Pipeline:
`vuln → análise (LLM/regras) → cenário YAML → execução + captura → dataset → IDS → relatório`

## Instalação

```bash
cd vulnforge-ai
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,traffic,api]"      # extras opcionais: traffic (scapy), api (FastAPI)
cp .env.example .env                       # opcional: configurar LLM
```

Requer Python 3.11+. `tcpdump` é necessário apenas para captura real (não para dry-run).

## Configuração de LLM (opcional)

Por padrão o provider é **OpenRouter**. Sem `OPENROUTER_API_KEY`, o analyzer cai automaticamente
para o modo **rule-based offline** (funciona sem rede). Edite o `.env`:

```ini
VULNFORGE_LLM_PROVIDER=openrouter        # openrouter | local | offline
OPENROUTER_API_KEY=sk-...
VULNFORGE_LLM_MODEL=anthropic/claude-3.5-sonnet
# Modelo local (Ollama/llama.cpp compatível com OpenAI):
# VULNFORGE_LLM_PROVIDER=local
# VULNFORGE_LLM_BASE_URL=http://localhost:11434/v1
```

## Uso (CLI `protoforge`)

```bash
# 1. Importar vulnerabilidades (JSON/CSV)
protoforge import-vulns --file data/raw/vulns.json

# 2. Analisar (LLM ou rule-based) -> JSON estruturado
protoforge analyze --vuln-id CVE-2024-0001 --protocol XRCE-DDS

# 3. Gerar cenário YAML (reusa containers do repo ataques/; --native usa ataque Python)
protoforge generate-scenario --vuln-id CVE-2024-0001 --out scenarios/generated/cve_0001.yaml

# 4. Executar cenário — DRY-RUN por padrão (apenas imprime comandos)
protoforge run-scenario --file scenarios/examples/xrce_dds_flooding.yaml --dry-run

#    Execução REAL (lab only): exige --execute --yes e alvo privado
protoforge run-scenario --file scenarios/examples/xrce_dds_flooding.yaml --no-dry-run --execute --yes

# 5. Construir dataset rotulado (CSV de flows ou PCAP via CICFlowMeter)
protoforge build-dataset --flows data/flows/example.csv --label flooding --out data/datasets/example.csv

# 6. Treinar IDS baseline (RandomForest + LogisticRegression)
protoforge train-ids --dataset data/datasets/example_labeled.csv --label-column label

# 7. Relatório Markdown end-to-end
protoforge report --run-id <RUN_ID>

# Extra: gerar Dockerfiles dos ataques nativos (genéricos)
protoforge gen-attack-docker --type all --out docker/attacks
```

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
protoforge run-scenario --file scenarios/examples/xrce_dds_flooding.yaml --execute --yes --validate
```

Faz **sonda antes** → ataque → captura → **sonda depois** → análise de PCAP, emitindo um
**veredito** (`valid` / `invalid` / `inconclusive`). Só cenários `valid` devem virar amostras
rotuladas de ataque no dataset — é isso que separa um ataque real de um "falso".

## Modelos LLM e reprodutibilidade

Suporta **nuvem** e **local** via flags (`--provider`, `--model`) ou `.env`:

```bash
protoforge analyze      --vuln-id CVE-2024-0001 --provider openrouter --model anthropic/claude-sonnet-4
protoforge forge-attack --vuln-id CVE-2024-0001 --provider local --model qwen2.5-coder:32b
```

Recomendações:
- **Local (reprodutível, citável):** `qwen2.5-coder:32b`, `deepseek-coder-v2:16b`, `llama3.3:70b`
  via Ollama/vLLM (`provider=local`, `base_url` no endpoint OpenAI-compatível). Com
  `temperature=0` + `seed`, os resultados são determinísticos.
- **Nuvem (qualidade):** `anthropic/claude-sonnet-4`, `openai/gpt-4.1`, `deepseek/deepseek-chat`
  via OpenRouter.

O **modelo e o seed usados** são registrados no `RunRecord` e no relatório (`protoforge report`),
para descrição de metodologia. Sem chave/LLM, o modo offline gera mutadores seguros por tipo de
ataque (rotulados como fallback).

## Reuso do repositório `ataques/`

Os cenários XRCE-DDS/Zenoh reusam os containers Docker já prontos do repo irmão `ataques/`
(`iotedu-attack-xrce-dds-*`, `iotedu-attack-zenoh-pico-*`) e os alvos
(`servers/xrce-dds-agent` UDP 8888, `servers/zenoh-router` TCP 7447). Suba os alvos com os scripts
`build-images-servers.sh` daquele repositório antes de executar cenários reais.

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
```

## API opcional (FastAPI)

```bash
uvicorn vulnforge.api:app --reload    # /health, /analyze, /generate-scenario
```

## Testes

```bash
pytest -q
```

## Segurança e limitações

- Runner é **dry-run por padrão**; execução real exige `--execute --yes` + confirmação.
- Ataques restritos a **IP privado/loopback** (`vulnforge.traffic.safety`).
- Cenários sintéticos de laboratório; datasets/IDS são **baseline**, não produção.
- Sem frontend e sem autenticação neste MVP.

Licença: GPL-3.0-or-later.
