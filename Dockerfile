FROM python:3.13-slim

WORKDIR /app

COPY requirements-docker.txt .

RUN pip install --no-cache-dir \
    --index-url https://download.pytorch.org/whl/cpu \
    torch==2.13.0+cpu

RUN pip install --no-cache-dir -r requirements-docker.txt

ARG NVD_API_KEY

COPY . .

RUN python -m ingest.nvd && \
    python -m ingest.osv && \
    python -m ingest.normalize && \
    python -m rag.chunk && \
    python -m rag.store

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]