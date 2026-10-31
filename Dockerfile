# Anubis Security Scanner Container
# Python 3.12 slim base image for a minimal, non-root CLI container.
#
#   docker build -t anubis-scanner:latest .
#   docker run --rm -v "$PWD":/scan:ro anubis-scanner:latest scan /scan/model.gguf

# Pinned by digest so a re-pointed tag cannot change the image (python 3.12-slim-bookworm, 2026-10-28).
FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337

# Debian security fixes published after the base image (the image build's Trivy
# gate fails on fixable CRITICAL/HIGH findings, e.g. OpenSSL CVE-2026-84782).
RUN apt-get update \
    && apt-get -y upgrade --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Optional extras, e.g. --build-arg EXTRAS=judge for `anubis redteam --provider anthropic`
ARG EXTRAS=""

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# pyproject.toml reads README.md as the package description, so both are needed to build
COPY pyproject.toml README.md ./
COPY src ./src

RUN if [ -n "$EXTRAS" ]; then pip install ".[${EXTRAS}]"; else pip install .; fi \
    && rm -rf /build \
    && useradd --create-home --uid 10001 anubis

LABEL org.opencontainers.image.title="anubis" \
      org.opencontainers.image.description="Security scanner for local AI models (GGUF, MLX, Safetensors, Ollama)" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.licenses="MIT"

USER anubis
WORKDIR /scan

ENTRYPOINT ["anubis"]
CMD ["--help"]
