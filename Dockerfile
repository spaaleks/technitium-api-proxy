# syntax=docker/dockerfile:1.6

FROM --platform=$TARGETPLATFORM python:3.12-slim AS builder
ARG TARGETPLATFORM
WORKDIR /build
RUN apt-get update \
 && apt-get install -y --no-install-recommends binutils curl \
 && rm -rf /var/lib/apt/lists/*
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"
COPY pyproject.toml uv.lock ./
COPY proxy ./proxy
COPY src ./src
RUN uv run --with pyinstaller pyinstaller --onefile --name technitium-api-proxy src/technitium_api_proxy.py

FROM debian:trixie-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY config.example.yml /app/config.example.yml
COPY --from=builder /build/dist/technitium-api-proxy /usr/local/bin/technitium-api-proxy

ENV CONFIG_PATH=/app/config.yml \
    HOST=0.0.0.0 \
    PORT=31399 \
    PATH=/usr/local/bin:$PATH
EXPOSE 31399
ENTRYPOINT ["/usr/local/bin/technitium-api-proxy"]
