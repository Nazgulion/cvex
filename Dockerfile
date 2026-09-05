FROM node:22-slim AS frontend
WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend ./
RUN npm run build

FROM python:3.12-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv

COPY cvex ./cvex
COPY pyproject.toml ./
COPY uv.lock ./
RUN uv sync --frozen --no-dev
ENV PATH="/app/.venv/bin:$PATH"

COPY alembic.ini ./
COPY migrations ./migrations
COPY config ./config
COPY tools ./tools
COPY --from=frontend /frontend/dist /app/frontend/dist

ENTRYPOINT ["cvex"]
