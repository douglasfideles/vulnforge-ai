# Revisão do Artefato — Ember (SBRC 2026 · Submissão #19762)
**Revisor:** Douglas Rodrigues Fideles

---

## Tipo do Artefato

Software.

---

## Resumo da Revisão

O Ember é um framework de treinamento distribuído que desacopla o carregamento de dados da sincronização do modelo via gRPC assíncrono. A arquitetura é bem estruturada, separando claramente as responsabilidades entre um servidor de dados e workers de treinamento, com configuração externalizada em JSON e suporte a imagens e texto. O código subjacente parece funcionalmente correto e a proposta é coerente com as afirmações do artigo.

O problema central é que o repositório foi publicado diretamente a partir do ambiente de desenvolvimento pessoal dos autores, sem passar por um teste de "primeira execução por terceiros". Três erros básicos na documentação impedem que qualquer revisor execute sequer o teste mínimo sem modificar arquivos não documentados: o volume do dataset aponta para o diretório pessoal de um dos autores, o README instrui o revisor a executar comandos no diretório errado dentro do container, e o segundo worker recebe uma configuração incorreta que causa colisão de rank no processo distribuído. São erros de publicação, não de implementação.

Para os experimentos centrais do artigo — comparação com Ray e redução de 36% no uso de memória — faltam a especificação do hardware utilizado, instruções para configurar o baseline Ray, scripts com os parâmetros exatos dos experimentos e resultados numéricos esperados para validação.

---

## Descrição do Artefato Disponível (SeloD)

**Recomendação: CONCEDER**

O repositório está publicamente disponível no GitHub com estrutura clara, README presente, licença MIT declarada e badges dos selos solicitados. Os arquivos de configuração JSON estão versionados e as definições Protocol Buffer estão incluídas junto com os arquivos gerados.

A ressalva principal é que o README não especifica requisitos mínimos de hardware. O container NVIDIA PyTorch 23.05 sozinho consome entre 25 e 30 GB; incluindo dependências pip e datasets, o total ultrapassa 40 GB. Revisores sem GPU dedicada não conseguem avaliar antecipadamente se o ambiente é viável. O docker-compose.yml também usa o campo `version` que está obsoleto nas versões recentes do Docker Compose, gerando aviso explícito na execução.

---

## Descrição do Artefato Funcional (SeloF)

**Recomendação: NÃO CONCEDER**

Há três problemas bloqueadores que impedem a execução do teste mínimo seguindo estritamente o README.

O primeiro é o volume do dataset configurado com o caminho absoluto do diretório pessoal de um dos autores no docker-compose.yml. Em qualquer outra máquina esse caminho não existe, o Docker monta um volume vazio e o servidor falha ao inicializar com erro de arquivo não encontrado. O README não menciona em nenhum momento que esse campo precisa ser alterado antes de executar.

O segundo é que o README instrui o revisor a executar os comandos diretamente dentro do container sem navegar ao subdiretório correto. O diretório de trabalho padrão do container é `/workspace`, mas os arquivos estão em `/workspace/files`. O comando falha imediatamente com erro de arquivo não encontrado.

O terceiro é que o README instrui o segundo worker a usar o mesmo arquivo de configuração do primeiro worker. Esse arquivo define rank zero para ambos os processos, impedindo que o grupo distribuído do PyTorch inicialize. O arquivo de configuração correto para o segundo worker já existe no repositório com rank um, mas o README aponta para o arquivo errado.

Há ainda um quarto problema grave: o Dockerfile do servidor instala o PyTorch sem fixar a versão, o que resulta no download de um pacote de 888 MB. Em conexões instáveis o pip encerra com timeout. O Dockerfile do worker fixa a versão corretamente, mas o servidor não tem tratamento equivalente.

---

## Prova de Execução Funcional

Não foi possível obter prova de execução bem-sucedida do teste mínimo sem modificar arquivos não documentados no README. Os erros são os documentados acima, reproduzindo fielmente os relatos dos demais revisores. Após corrigir manualmente os três bloqueadores, a arquitetura gRPC servidor-worker é tecnicamente viável.

---

## Descrição do Artefato Sustentável (SeloS)

**Recomendação: CONCEDER PARCIALMENTE**

A separação entre servidor e workers é clara e reflete bem a arquitetura descrita no artigo. A configuração por JSON desacopla parâmetros do código de forma consistente nos módulos principais. Os nomes de arquivos e funções são descritivos e auto-explicativos, e a existência de variantes distintas como `ember_control.py` para baseline e `ember_mem.py` para profiling facilita a compreensão do artefato.

Os problemas de sustentabilidade são de médio impacto. A classe `RPCIterableDataset` é redefinida com pequenas variações em cinco arquivos diferentes, sendo que uma versão canônica já existe em `utils/ember_dataset.py` e não é usada pelos demais. O arquivo `utils/image_loader.py` duplica funções já presentes em `server.py` com uma variante parcialmente incompleta. O módulo `ember_text.py` hardcoda valores de épocas, batch size, learning rate e nome do modelo, ao contrário de todos os outros módulos que leem esses valores do JSON de configuração. O arquivo `text.json` usa transforms de imagem para configurar um pipeline de dados textuais, o que é conceitualmente incorreto. O arquivo `utils/modelFile.py` tem mais de 11 mil linhas sem qualquer comentário de cabeçalho ou menção no README. Nenhuma das funções centrais do framework possui docstring.

---

## Descrição do Artefato Reprodutível (SeloR)

**Recomendação: NÃO CONCEDER**

Os experimentos centrais do artigo não são reproduzíveis a partir das instruções do repositório. O bloqueio começa pelos problemas de SeloF, que impedem chegar ao ponto de execução dos benchmarks, mas mesmo resolvidos esses bloqueadores, a seção de experimentos é insuficiente.

O artigo reporta redução de 36% no uso de memória e tempos de treinamento competitivos com Ray, mas o repositório não especifica o hardware utilizado nos experimentos originais: modelo de GPU, quantidade de VRAM, RAM do host, número de nós e largura de banda de rede. Sem isso, não é possível reproduzir as condições experimentais.

O baseline Ray, que é a comparação central do artigo, não tem instruções de instalação ou configuração. O README menciona que foi substituído por `ember_control.py` para facilitar a execução, mas isso significa que o resultado reportado no artigo não é reproduzível com o artefato disponibilizado.

Não há tabelas nem valores numéricos esperados para que o revisor valide se seus resultados correspondem ao artigo. O arquivo `instrumented_test.py`, mencionado como responsável pela visualização dos resultados, não tem instruções de execução nem referência às figuras do artigo que reproduz. O arquivo `ember_train_main.py` é referenciado na seção de experimentos mas não existe no repositório. O ambiente de execução original não está documentado: sistema operacional, versão do kernel, driver NVIDIA e versão do CUDA não são informados.

---

## Prova de Execução Reprodutível

Não foi possível reproduzir nenhum experimento do artigo. Os bloqueadores de SeloF impedem chegar ao ponto de execução dos benchmarks e não há scripts, parâmetros nem resultados de referência documentados para os experimentos de comparação com Ray.

---

## Experiência do Revisor

Conhecedor (3). Experiência com sistemas distribuídos, treinamento distribuído com PyTorch DDP e FSDP, gRPC e Protocol Buffers, conteinerização Docker e frameworks de ML em cenários multi-GPU. Familiaridade com Ray para treinamento distribuído.

---

## Sugestões de Melhorias para os Autores

Os três bloqueadores de SeloF exigem correção imediata e são simples de resolver. O campo `volumes` do docker-compose.yml deve ser substituído por um path relativo ou variável de ambiente, com instrução explícita no README para que o revisor aponte ao diretório local dos datasets antes de executar. Os comandos do README dentro dos containers devem incluir `cd /workspace/files` antes de qualquer execução. O comando do worker 2 deve referenciar `config2.json` em vez de `config1.json`. O Dockerfile do servidor deve fixar a versão do PyTorch com flag de timeout e retry, igualando o tratamento já feito no Dockerfile do worker.

Para SeloS, recomenda-se adicionar docstrings nas funções centrais, consolidar `RPCIterableDataset` no módulo `utils/ember_dataset.py` eliminando as cinco reimplementações, remover o código duplicado de `utils/image_loader.py`, mover os valores hardcoded de `ember_text.py` para JSON de configuração, corrigir `text.json` para refletir corretamente um pipeline de texto, e adicionar um comentário de cabeçalho em `utils/modelFile.py` com menção no README.

Para SeloR, os autores precisam adicionar uma seção de reprodução dos experimentos com hardware exato, versão de SO, driver NVIDIA e CUDA, instruções completas para configurar o ambiente Ray equivalente, scripts com os parâmetros exatos dos experimentos do artigo, tabela com resultados esperados para cada experimento, e adicionar `ember_train_main.py` ao repositório ou corrigir a referência para `ember_train_mem.py`.

---

## Comentários para o Comitê Técnico de Artefatos (CTA)

O artefato tem base técnica sólida. Os problemas identificados são majoritariamente de documentação e preparação para revisão externa, não de qualidade do código ou da proposta. Recomendo que o CTA notifique os autores dos três bloqueadores críticos e conceda um período de revisão curto antes da decisão final sobre SeloF e SeloR. Com as correções de documentação, SeloF provavelmente seria atendido sem alterações de código. SeloR requer trabalho adicional substancial envolvendo a documentação dos experimentos de comparação com Ray e especificação do ambiente experimental. SeloD pode ser concedido imediatamente. SeloS pode ser concedido com as ressalvas documentadas, dado que a estrutura geral é modular e legível.

---

---

# Revisão Final (r2) — Pós-Rebuttal

**Data:** 14 de maio de 2026

---

## Resumo da revisão final (r2) da avaliação do artefato SBRC'26

Os autores responderam ao rebuttal corrigindo os três bloqueadores de SeloF identificados na revisão r1. O README agora inclui a instrução `cd /workspace/files` antes de cada comando de execução; o `docker-compose.yml` passou a usar o caminho relativo `./datasets:/workspace/datasets` no lugar do path pessoal hardcoded do desenvolvedor; e o worker 2 é corretamente instruído a usar `config2.json` (rank 1), eliminando a colisão de rank que impedia a inicialização do grupo distribuído. Os caminhos de dataset nos arquivos JSON de configuração também foram corrigidos para os nomes reais dos diretórios gerados na extração do dataset (`MNIST - JPG - training` e `MNIST - JPG - testing`). O README recebeu seção de requisitos mínimos de hardware (60 GB de disco, ≥8 GB VRAM, CUDA 12.6+, Driver ≥525), seção descrevendo a saída esperada em cada terminal durante o teste mínimo, e orientações para contornar timeouts de pip durante o build.

Em termos de execução, o build dos containers workers (`grworker1` e `grworker2`) foi concluído com sucesso no meu ambiente após aproximadamente 75 minutos. O timeout que interrompeu o build na revisão r1 não se repetiu, provavelmente em razão de melhores condições de rede. A falha no runtime ocorreu ao tentar iniciar os containers workers, com a mensagem `nvidia-container-cli: initialization error: WSL environment detected but no adapters were found`. Essa falha é atribuível ao ambiente de testes do revisor (WSL2 sem GPU física com passthrough NVIDIA configurado) e não ao artefato — GPU é um requisito documentado. Não foi possível executar o teste mínimo completo por essa limitação de ambiente.

Uma questão de médio impacto permanece sem correção: o `worker/Dockerfile` ainda realiza duas instalações sequenciais do PyTorch. A linha 7 instala `torch` e `torchvision` via PyPI (versão genérica, ~888 MB), e a linha 8 imediatamente sobrescreve essa instalação com a versão CUDA específica (`torch==2.7.0+cu126`, ~2 GB). Além disso, a imagem base `nvcr.io/nvidia/pytorch:23.05-py3` já inclui PyTorch e CUDA, tornando ambas as instalações adicionais redundantes ou desnecessariamente duplicadas. O autor reconheceu o problema no rebuttal ("a versão não utilizada pode ser removida"), mas o Dockerfile não foi alterado. Esse padrão infla o espaço temporário de armazenamento durante o build e explica em parte os erros `no space left on device` que impediram o Revisor A de concluir o build em um host com 40 GB livres.

Não houve progresso em relação ao SeloR: nenhum script de reprodução dos experimentos centrais foi adicionado, o hardware dos experimentos originais ainda não está especificado, e não há instruções para configurar o baseline Ray utilizado na comparação do artigo.

**Decisões por selo:**
- **SeloD:** Concedido. README agora cumpre os requisitos de documentação mínima.
- **SeloF:** Concedido com ressalva. Os três bloqueadores foram resolvidos. A GPU é requisito mandatório documentado; a falha no meu ambiente é de infraestrutura local. A instalação redundante do PyTorch no Dockerfile do worker permanece como risco para ambientes com disco limitado.
- **SeloS:** Concedido. A estrutura modular e a configuração por JSON permanecem adequadas; os problemas de sustentabilidade apontados na r1 continuam presentes mas não foram agravados.
- **SeloR:** Não concedido. Sem progresso nos requisitos de reprodutibilidade dos experimentos de comparação.

---

## Comentários r2 para o Comitê Técnico de Artefatos (CTA) SBRC'26

Os autores responderam de forma direta e objetiva ao rebuttal. Os três erros de publicação que bloqueavam completamente o SeloF foram resolvidos no commit `e088f0a`. O `docker-compose.yml` usa agora caminho relativo para o volume do dataset. O README cobre os passos ausentes (diretório de trabalho dentro do container, rank correto dos workers, requisitos de hardware, saída esperada, workaround de timeout). A base de código permanece tecnicamente sólida e a arquitetura é coerente com o artigo.

Há duas questões remanescentes que o CTA deve considerar. Primeira: o `worker/Dockerfile` ainda executa duas instalações do PyTorch sequencialmente (linhas 7 e 8), aumentando desnecessariamente o consumo de armazenamento temporário durante o build. Foi exatamente esse comportamento que impediu o Revisor A de concluir o build em um host com 40 GB livres. Os autores reconheceram o problema sem corrigi-lo. A correção seria consolidar as duas linhas `RUN` em uma única, instalando diretamente a versão CUDA com `pip3 install "torch==2.7.0+cu126" --index-url https://download.pytorch.org/whl/cu126` e removendo a instalação prévia de `torch` via PyPI. Segunda: o SeloR continua integralmente não atendido. Não foram adicionados scripts de reprodução dos experimentos de comparação com Ray, não há especificação do hardware dos experimentos originais, não há instruções para configurar o baseline Ray, e não há resultados numéricos esperados para validação.

**Recomendação ao CTA:**
- SeloD: conceder.
- SeloF: conceder — os bloqueadores foram resolvidos; a GPU é requisito documentado e a falha de runtime em ambiente WSL2 sem GPU é responsabilidade do ambiente de teste.
- SeloS: conceder — estrutura modular clara com os problemas de sustentabilidade da r1 inalterados (não agravados).
- SeloR: não conceder neste ciclo — requer trabalho substancial adicional na documentação dos experimentos de comparação.
