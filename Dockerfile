# Anubis Security Scanner Container
# Python 3.12 slim base image for a minimal, non-root CLI container.
#
#   docker build -t anubis-scanner:latest .
#   docker run --rm -v "$PWD":/scan:ro anubis-scanner:latest scan /scan/model.gguf

# Pinned by digest so a re-pointed tag cannot change the image (python 3.12-slim-bookworm, 2026-10-21).
FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70

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
