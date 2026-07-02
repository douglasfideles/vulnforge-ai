FROM python:3.11-slim

WORKDIR /app

# Install tcpdump for optional real capture.
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir -e .

# Default: run the minimal offline smoke test.
CMD ["bash", "scripts/run-minimal.sh"]
