FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Unprivileged runtime user (api, worker and beat all run as it)
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin app

COPY --chown=app:app . .

USER app

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
