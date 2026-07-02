# Checklist de avaliação — SBRC 2026

Este checklist registra o estado local do artefato. Itens que dependem de publicação devem ser
concluídos pelos autores no momento da submissão.

## Requisitos obrigatórios do README

- [x] título e resumo do artigo/artefato;
- [x] estrutura do README e do repositório;
- [x] selos considerados;
- [x] ambiente, hardware, software, tempo e disco;
- [x] dependências obrigatórias e opcionais com versões;
- [x] preocupações e procedimento de segurança;
- [x] instalação nativa e Docker;
- [x] teste mínimo com saídas esperadas;
- [x] experimentos separados por reivindicação;
- [x] licença.

## SeloD — Disponível

- [x] licença aberta identificada;
- [x] código, testes e entradas pequenas incluídos;
- [ ] publicar em repositório estável;
- [ ] criar release imutável e DOI;
- [ ] substituir URL/DOI/autores em `README.md` e `CITATION.cff`.

## SeloF — Funcional

- [x] versões fixadas;
- [x] instalação documentada;
- [x] teste mínimo automatizado;
- [x] saídas esperadas documentadas;
- [x] erros opcionais degradam com orientação acionável.

## SeloS — Sustentável

- [x] layout modular;
- [x] mapa arquitetural e interfaces;
- [x] testes por responsabilidade;
- [x] rastreabilidade entre reivindicações, módulos e testes;
- [x] changelog e metadados de citação.

## SeloR — Reproduzível

- [x] script único de reprodução;
- [x] modo offline determinístico;
- [x] parâmetros e sementes registrados;
- [x] resultados em JSON e Markdown;
- [x] verificação automática das métricas/reivindicações;

## Auditoria recomendada antes do HotCRP

1. Fazer clone da release em VM limpa.
2. Seguir somente o README.
3. Executar `scripts/run-tests.sh`.
4. Executar `scripts/reproduce.sh`.
5. Conferir `results/reproduction/summary.md`.
6. Arquivar a release testada sem `data/`, `results/`, `.venv/`, caches ou segredos.

