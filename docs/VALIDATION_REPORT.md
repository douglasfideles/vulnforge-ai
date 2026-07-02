# Relatório de validação local

Data: 2 de julho de 2026  
Ambiente: Python 3.12.3, Linux/WSL2 x86-64, sem GPU

## Resultados

| Verificação | Resultado |
|---|---|
| resolução e instalação `.[dev,api,traffic]` | PASS |
| CLI da instalação limpa | PASS |
| suíte a partir da árvore de fontes | 73 PASS |
| suíte a partir de pacote instalado isoladamente | 73 PASS |
| reprodução offline | PASS (16/16 verificações) |
| RandomForest | F1 = 1.00 |
| LogisticRegression | F1 = 1.00 |
| modelo selecionado | RandomForest |
| dry-run | persistido, nenhum tráfego enviado |

Após a inclusão do teste estrutural do Compose, a suíte contém 74 casos; o resultado definitivo
deve ser consultado em `results/test-report.txt`, gerado por `scripts/run-tests.sh`.

## Defeitos encontrados e corrigidos durante a auditoria

1. compatibilidade entre Typer 0.15.2 e Click: Click fixado em 8.1.8;
2. deriva NumPy/SciPy: versões compatíveis fixadas em 2.2.2/1.15.1;
3. API síncrona dependia de threadpool indisponível em sandboxes restritos: endpoints convertidos
   para assíncronos;
4. Scapy podia lançar `PermissionError` ao descobrir interfaces: degradação agora captura falha
   operacional e retorna nota acionável;
5. classificação genérica `ip.is_private` aceitava blocos além do laboratório: whitelist explícita
   para loopback, RFC1918 e link-local;
6. Docker bundle podia registrar caminho absoluto: caminho agora é relativo ao contexto.

## Limitação da validação

O executável do Docker Desktop existe no host, mas a integração Docker/WSL desta sessão está
desativada. Portanto, `docker compose up --build` não pôde ser executado aqui. O Compose,
Dockerfile, volumes relativos e ausência do campo obsoleto `version` são validados pela suíte. A
construção real do container permanece um passo obrigatório da auditoria em VM/host com Docker
ativo antes do envio ao HotCRP.

