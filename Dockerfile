FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY server.py protocols.py searching.py monitoring.py dataops.py access.py deployment.py ./
COPY static/ ./static/
COPY LICENSE ./LICENSE
RUN mkdir -p /data && chown 10001:10001 /data
USER 10001:10001
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/healthz', timeout=3).read()"
CMD ["python", "server.py", "--config", "/app/config.json"]
