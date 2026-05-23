FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN pip install --no-cache-dir -e .

RUN useradd -m -u 1000 auditor \
    && chown -R auditor:auditor /app

USER auditor

ENTRYPOINT ["mcp-tool-auditor"]
CMD ["scan", "--help"]
