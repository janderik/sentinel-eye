FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user --upgrade pip && \
    pip install --no-cache-dir --user -r requirements.txt


FROM python:3.11-slim AS runtime

RUN groupadd -r sentinel && useradd -r -g sentinel -d /opt/sentinel -s /sbin/nologin sentinel

RUN mkdir -p /opt/sentinel/data /opt/sentinel/rules /opt/sentinel/logs && \
    chown -R sentinel:sentinel /opt/sentinel

COPY --from=builder /root/.local /usr/local
COPY --chown=sentinel:sentinel . /opt/sentinel/

WORKDIR /opt/sentinel

ENV PYTHONPATH=/opt/sentinel \
    SENTINEL_DB_URL=sqlite:////opt/sentinel/data/sentinel.db \
    SENTINEL_RULES_DIR=/opt/sentinel/examples/rules \
    SENTINEL_MODE=all \
    SENTINEL_HOST=0.0.0.0 \
    SENTINEL_PORT=8000

EXPOSE 514/udp
EXPOSE 5140/tcp
EXPOSE 8000/tcp

USER sentinel

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')" || exit 1

ENTRYPOINT ["python", "-m", "src.main"]

CMD ["--mode", "all"]
