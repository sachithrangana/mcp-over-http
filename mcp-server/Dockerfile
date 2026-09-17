FROM python:3.12-slim
WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Dependencies first so code edits do not reinstall them.
COPY pyproject.toml .
RUN pip install --no-cache-dir "mcp>=2.2.0" "httpx>=0.28" "pyjwt[crypto]>=2.9" "uvicorn>=0.30"

# Only what the remote server needs; the stdio entry point and its browser login
# are for local installs and have no place in a deployed image.
COPY tools.py remote_server.py ./

RUN useradd --system --create-home --uid 10001 app
USER app

EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
  CMD ["python", "-c", "import urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:3000/.well-known/oauth-protected-resource', timeout=3); sys.exit(0 if r.status==200 else 1)"]

CMD ["python", "remote_server.py"]
