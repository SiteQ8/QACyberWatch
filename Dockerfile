FROM python:3.12-slim

LABEL maintainer="Ali AlEnezi <Site@hotmail.com>"
LABEL description="QACyberWatch - Qatar Phishing Detection & Brand Protection Suite"
LABEL org.opencontainers.image.source="https://github.com/SiteQ8/QACyberWatch"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    QCW_DB_PATH=/app/data/qacyberwatch.db

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN groupadd --system kcw && useradd --system --gid kcw --home /app kcw && \
    mkdir -p /app/data && chown -R kcw:kcw /app
USER kcw

EXPOSE 5000

# python is always available in the image; curl is not.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/api/v1/health', timeout=4).status == 200 else 1)" || exit 1

ENTRYPOINT ["python", "main.py", "--no-banner"]
CMD ["api"]
