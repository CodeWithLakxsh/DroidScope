# DroidScope backend image.
#
# Includes the JVM-based analysis tools (JADX, apktool) because the backend is
# useless without them. Ghidra is deliberately excluded: it adds well over a
# gigabyte and only the full profile uses it, so it is mounted in by operators
# who need it (see docker-compose.yml).
FROM python:3.12-slim-bookworm AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    DROIDSCOPE_DATA_DIR=/data

# --- tools ------------------------------------------------------------------
FROM base AS tools

ARG JADX_VERSION=1.5.1
ARG APKTOOL_VERSION=2.11.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/jadx.zip \
      "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
    && mkdir -p /opt/jadx && unzip -q /tmp/jadx.zip -d /opt/jadx && rm /tmp/jadx.zip \
    && chmod +x /opt/jadx/bin/jadx

RUN curl -fsSL -o /opt/apktool.jar \
      "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
    && printf '#!/bin/sh\nexec java -jar /opt/apktool.jar "$@"\n' > /opt/apktool \
    && chmod +x /opt/apktool

# --- runtime ----------------------------------------------------------------
FROM base AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        openjdk-17-jre-headless \
        libyara9 \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=tools /opt/jadx /opt/jadx
COPY --from=tools /opt/apktool.jar /opt/apktool.jar
COPY --from=tools /opt/apktool /usr/local/bin/apktool
RUN ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx

WORKDIR /app

COPY backend/pyproject.toml backend/README.md ./
COPY backend/app ./app
RUN pip install --no-cache-dir ".[postgres,redis,yara]"

COPY rules /rules
# An installed package has no repository layout beside it, so the rule
# directory must be stated explicitly.
ENV DROIDSCOPE_RULES_DIR=/rules
ENV DROIDSCOPE_YARA_RULES_DIR=/rules/yara

# The analysis worker handles untrusted input, so it never runs as root.
RUN useradd --create-home --uid 10001 droidscope \
    && mkdir -p /data && chown -R droidscope:droidscope /data /app
USER droidscope

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/v1/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
