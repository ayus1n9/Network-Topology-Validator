FROM python:3.12-slim AS builder

WORKDIR /build

COPY pyproject.toml README.md ./
COPY topology_validator/ ./topology_validator/

RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim

LABEL org.opencontainers.image.title="topology-validator"
LABEL org.opencontainers.image.description="Validate network topologies for security design flaws"
LABEL org.opencontainers.image.source="https://github.com/ayus1n9/topology-validator"
LABEL org.opencontainers.image.licenses="MIT"

COPY --from=builder /install /usr/local

RUN useradd --create-home --shell /bin/bash app
USER app
WORKDIR /home/app

ENTRYPOINT ["topology-validator"]
CMD ["--help"]