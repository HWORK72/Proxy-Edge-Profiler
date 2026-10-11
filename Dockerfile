FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY core/ /app/core/
COPY models/ /app/models/
COPY profiler/ /app/profiler/
COPY scoring/ /app/scoring/
COPY storage/ /app/storage/
COPY api/ /app/api/
COPY ui/ /app/ui/
COPY benchmark/ /app/benchmark/
COPY main.py /app/main.py

RUN pip install --upgrade pip && \
    pip install \
    "pydantic>=2.7.0" \
    "pydantic-settings>=2.2.0" \
    "curl_cffi>=0.7.0" \
    "aiohttp>=3.9.0" \
    "rich>=13.7.0" \
    "asyncpg>=0.29.0" \
    "sqlalchemy>=2.0.30" \
    "sqlalchemy[asyncio]" \
    "greenlet" \
    "redis>=5.0.4" \
    "fastapi>=0.111.0" \
    "uvicorn[standard]>=0.30.0" \
    "python-dotenv>=1.0.1"

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]