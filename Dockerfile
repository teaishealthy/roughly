FROM ghcr.io/astral-sh/uv:trixie-slim AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

ENV UV_PYTHON_INSTALL_DIR=/python

ENV UV_PYTHON_PREFERENCE=only-managed

ENV UV_PYTHON=3.13

RUN uv python install 3.13

WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-dev --extra cli

COPY pyproject.toml uv.lock README.md LICENSE ./
COPY roughly/ ./roughly/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable --extra cli

RUN mv /app/.venv/lib/python3.13/site-packages /app/deps

FROM gcr.io/distroless/python3-debian13

COPY --from=builder /app/deps /app/deps

WORKDIR /app

ENV PYTHONPATH=/app/deps
ENV PYTHONUNBUFFERED=1

EXPOSE 2002/udp

CMD ["-m", "roughly.cli", "-v", "server", "run"]
