# syntax=docker/dockerfile:1
# rung API image: build a wheel, then install it into a slim runtime that has git.

FROM python:3.15-slim AS builder
WORKDIR /build
RUN pip install --no-cache-dir build==1.2.2
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m build --wheel --outdir /dist

FROM python:3.15-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RUNG_DB=/data/rung.sqlite3

# git is needed at runtime: rung clones and reads repository history.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /dist /tmp/dist
RUN pip install --no-cache-dir "$(ls /tmp/dist/rung-*.whl)[api]" \
    && rm -rf /tmp/dist \
    && groupadd --system --gid 10001 rung \
    && useradd --system --uid 10001 --gid rung --home-dir /home/rung --create-home rung \
    && mkdir /data \
    && chown rung:rung /data

USER rung
WORKDIR /home/rung
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).status == 200 else 1)"]

CMD ["rung", "serve", "--host", "0.0.0.0", "--port", "8000"]
