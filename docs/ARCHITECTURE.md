# Arquitetura do artefato

O pacote segue uma arquitetura em pipeline, com dependências apontando para modelos e serviços
centrais, sem acoplamento dos componentes de análise à execução de tráfego.

```text
entrada JSON/CSV
      │
      ▼
normalização ──► SQLite ──► análise (regras/LLM)
                               │
                               ▼
                         cenário YAML
                               │
                 ┌─────────────┴─────────────┐
                 ▼                           ▼
              dry-run                 execução guardada
                 │                           │
                 └─────────────┬─────────────┘
                               ▼
                    flows/PCAP → dataset
                               │
                               ▼
                     IDS + relatório final
```

## Mapa de módulos

| Módulo | Responsabilidade e interfaces principais |
|---|---|
| `models.py` | contratos Pydantic de vulnerabilidade, análise, cenário, execução e efeito |
| `config.py` | configuração por ambiente com prefixo `VULNFORGE_` |
| `db.py` | schema SQLite e operações de persistência |
| `vulnerability/normalizer.py` | leitura JSON/CSV, aliases e normalização determinística |
| `llm/rules.py` | classificação offline reproduzível |
| `llm/analyzer.py` | adaptador OpenAI-compatible com fallback para regras |
| `scenarios/generator.py` | geração, serialização e validação YAML |
| `protocols/` | classe base, registro e plugins XRCE-DDS, Zenoh e DDS |
| `traffic/safety.py` | resolução e whitelist explícita de redes de laboratório |
| `traffic/codegen.py` | validação AST, compilação restrita e autoteste de mutadores |
| `traffic/runner.py` | dry-run, gates de execução, captura e persistência |
| `validation/` | análise opcional de PCAP e decisão de efeito |
| `dataset/builder.py` | rotulação e união de fluxos |
| `ids/trainer.py` | RandomForest, LogisticRegression, métricas e persistência |
| `reports/generator.py` | relatório Markdown ponta a ponta |
| `cli.py` | comandos públicos `protoforge` |
| `api.py` | API HTTP opcional e somente leitura |

## Pontos de extensão

- Protocolos implementam `ProtocolPlugin` e são registrados por nome normalizado.
- Provedores LLM usam o contrato OpenAI-compatible; falhas não interrompem o caminho offline.
- Novos mutadores devem passar `validate_mutator` e `self_test`.
- Novos modelos IDS devem preservar a separação treino/teste e registrar métricas.

## Rastreabilidade das reivindicações

| Reivindicação | Implementação | Testes |
|---|---|---|
| análise determinística | `llm/rules.py` | `test_rules_scenarios.py` |
| segurança de alvos/código | `traffic/safety.py`, `traffic/codegen.py` | `test_codegen_safety.py` |
| pipeline e IDS | `dataset/`, `ids/`, `reports/` | `test_dataset_db.py`, testes de integração |
| framing de protocolos | `protocols/` | `test_protocols_validation.py` |

