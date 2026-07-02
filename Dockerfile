FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt pyproject.toml README.md LICENSE ./
COPY src ./src
COPY scripts ./scripts
COPY examples ./examples
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir --no-deps .
CMD ["bash", "scripts/run-minimal.sh"]

