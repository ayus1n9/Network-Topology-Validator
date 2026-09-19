# ---- Build stage ----
FROM python:3.12-slim AS builder

WORKDIR /build

# Copy only what's needed to install the package
COPY pyproject.toml README.md ./
COPY topology_validator/ ./topology_validator/

# Install into a virtual env we can copy over
RUN pip install --no-cache-dir --prefix=/install .


# ---- Runtime stage ----
FROM python:3.12-slim

LABEL org.opencontainers.image.title="topology-validator"
LABEL org.opencontainers.image.description="Validate network topologies for security design flaws"
LABEL org.opencontainers.image.source="https://github.com/YOUR_USERNAME/topology-validator"
LABEL org.opencontainers.image.licenses="MIT"

# Copy the installed package from the builder stage
COPY --from=builder /install /usr/local

# Run as a non-root user (security best practice)
RUN useradd --create-home --shell /bin/bash app
USER app
WORKDIR /home/app

# Default command
ENTRYPOINT ["topology-validator"]
CMD ["--help"]