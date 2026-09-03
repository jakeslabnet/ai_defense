FROM python:3.12-slim

WORKDIR /app
COPY sender.py healthcheck.py ./

ENV PYTHONUNBUFFERED=1
ENV HEALTH_STATUS_PATH=/app/health_status.json

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "/app/healthcheck.py"]

ENTRYPOINT ["python", "/app/sender.py"]
