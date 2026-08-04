FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps for building optional native packages (whois, etc.) if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements.txt* /app/
COPY phishguard /app/phishguard
COPY tests /app/tests

RUN pip install --upgrade pip && pip install .[dev]

# Runtime data (reports db, intel cache) persisted via volume
VOLUME ["/app/reports", "/app/.cache"]

EXPOSE 8080

ENV PG_REPORT_DIR=/app/reports \
    PG_WEB_HOST=0.0.0.0 \
    PG_WEB_PORT=8080

CMD ["python", "-m", "phishguard", "serve", "--host", "0.0.0.0", "--port", "8080"]
