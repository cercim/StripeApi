FROM python:3.11-slim

# system deps curl_cffi needs
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates gcc libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# install deps first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy source
COPY . .

ENV PORT=80 \
    HOST=0.0.0.0 \
    WORKERS=4 \
    LOG_LEVEL=info

EXPOSE 80

CMD ["python3", "server.py"]
