# VulnForge AI - imagem do app para o pipeline minimo offline.
# Python puro, sem GPU/CUDA. Base FIXADA para build reprodutivel.
FROM python:3.11-slim

# Evita prompts e .pyc; saida de log sem buffer.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# 1) Dependencias fixadas primeiro (camada cacheavel). UM unico RUN, sem
#    instalacoes duplicadas (licao do REVIEW: nada de instalar a mesma lib 2x).
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# 2) Codigo + instalacao do pacote (registra o entrypoint `protoforge`).
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-deps -e .

# 3) Dados/cenarios/scripts necessarios para o teste minimo.
COPY scenarios ./scenarios
COPY scripts ./scripts
COPY data/raw ./data/raw
COPY data/flows ./data/flows
COPY data/datasets ./data/datasets

# Usuario nao-root.
RUN useradd --create-home --uid 10001 forge \
    && mkdir -p data/runs data/models reports scenarios/generated \
    && chown -R forge:forge /app
USER forge

# Por padrao roda o TESTE MINIMO completo (offline, dry-run, sem GPU/rede).
CMD ["bash", "scripts/run-minimal.sh"]
