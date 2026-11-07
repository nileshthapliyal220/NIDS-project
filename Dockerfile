FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements-docker.txt .
RUN pip install --no-cache-dir -r requirements-docker.txt

COPY . .

RUN useradd -m appuser && mkdir -p uploads instance && chown -R appuser /app
USER appuser

EXPOSE 8000
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-8000} --workers 1 --timeout 120 app:app"]