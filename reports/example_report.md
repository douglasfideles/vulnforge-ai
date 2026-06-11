# Relatorio VulnForge AI - run-20240601-101500-a1b2c3

_Exemplo gerado pelo pipeline (`protoforge report --run-id ...`)._

## 1. Vulnerabilidade

- **ID:** CVE-2024-0001
- **Titulo:** XRCE-DDS Agent entity resource exhaustion via unbounded entity creation
- **CVSS:** 7.5  | **Severidade:** high
- **CWE:** CWE-400  | **Produto:** eProsima Micro XRCE-DDS Agent
- **Fonte:** example-feed  | **Publicado:** 2024-02-10

> The Micro XRCE-DDS Agent allows a client to create an unbounded number of DDS entities
> (participants, topics, publishers, datawriters) using predictable session keys, leading to
> memory/CPU exhaustion and possible denial of service of the agent on UDP port 8888.

## 2. Analise (LLM / regras)

- **Fonte da analise:** rules
- **Protocolo:** XRCE-DDS
- **Tipo de ataque:** flooding
- **Confianca:** 0.60
- **Pre-condicoes:** Laboratorio isolado com o broker/agent alvo em execucao e alcancavel; trafego normal de baseline disponivel para comparacao.
- **Comportamento esperado:** Alto volume de pacotes/conexoes por segundo; crescimento de uso de CPU/memoria no alvo; possivel perda de pacotes legitimos.
- **Label do dataset:** xrce_dds_flooding
- **Notas de seguranca:** Cenario exclusivamente para laboratorio controlado. Nao executar contra alvos de producao ou redes publicas. Alvo deve ser IP privado/loopback.

## 3. Cenario gerado

- **scenario_id:** cve_2024_0001_xrce_dds_flooding
- **attack_type:** flooding
- **duracao:** 30s
- **comando normal:** `python -m vulnforge.traffic.attacks.flooding --target 127.0.0.1 --port 8888 --transport udp --rate 5 --duration 20 --benign`
- **comando ataque:** `docker run --rm iotedu-attack-xrce-dds-udp-dos:latest 127.0.0.1 8888`
- **interface:** any

## 4. Execucao e artefatos

- **Status:** done
- **Iniciado em:** 2024-06-01T10:15:00+00:00
- **PCAP:** `data/runs/cve_2024_0001_xrce_dds_flooding.pcap`
- **Log:** `data/runs/run-20240601-101500-a1b2c3.log`

## 5. Dataset

- **Nome:** example_labeled
- **Registros:** 120
- **Labels:** flooding, normal

## 6. IDS Baseline

Treinado com `protoforge train-ids --dataset data/datasets/example_labeled.csv --label-column label`.

| Modelo | Accuracy | Precision | Recall | F1 |
|--------|----------|-----------|--------|----|
| RandomForest | 1.000 | 1.000 | 1.000 | 1.000 |
| LogisticRegression | 1.000 | 1.000 | 1.000 | 1.000 |

> As classes `normal` e `flooding` deste dataset sintetico sao linearmente separaveis, por isso as
> metricas saturam. Em dados reais espera-se desempenho inferior.

## 7. Limitacoes

- Cenarios sao sinteticos e executados em laboratorio isolado; nao refletem todas as condicoes de redes reais.
- Datasets podem ser pequenos/desbalanceados; metricas do IDS sao baseline, nao producao.
- Ataques sao controlados e restritos a alvos privados; cobertura de variantes e parcial.
- A analise via LLM/regras e um apoio heuristico e pode conter imprecisoes.
