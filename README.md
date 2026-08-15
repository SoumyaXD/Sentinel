# Sentinel

**A CVE research and patch-prioritization RAG pipeline.**

Live: https://sentinel-rag.onrender.com/

Sentinel retrieves vulnerability facts from NVD and OSV.dev, combines them
into a local knowledge base, and generates grounded answers with cited CVE
records instead of relying on an LLM's training knowledge.

## What has been done

### Stage A: Hand-built RAG

- NVD and OSV.dev ingestion
- Data normalization and deduplication
- Document chunking
- `all-MiniLM-L6-v2` embeddings
- Persistent Chroma vector store
- Exact CVE-ID lookup
- Semantic retrieval
- Grounded answer generation
- Hand-verified deterministic evaluation

Results:

| Metric | Result |
|---|---:|
| Correct CVE retrieval | 94.4% |
| Factual accuracy | 94.4% |
| Citation correctness | 94.4% |
| Trap-question handling | 100% |

### Stage B: LangChain

The retrieval and generation path was refactored into LangChain while retaining
the original implementation as a reference. The LangChain path was evaluated
against the Stage A baseline with zero regression in the deterministic results.

The generation provider is configurable through `LLM_PROVIDER`, with OpenAI
`gpt-4o-mini` used for the deployed service.

### Stage C: Evaluation, API, Docker, Deployment

- RAGAS evaluation
- FastAPI service
- `/ask` live RAG endpoint
- `/ask/demo` cached, zero-cost demo endpoint
- `/health` service health check
- Per-IP rate limiting on `/ask`
- OpenAI spend cap for cost control
- Dockerized service
- CPU-only PyTorch
- BuildKit secret handling for `NVD_API_KEY`
- Runtime `OPENAI_API_KEY`
- Live deployment on Render
- Portfolio web interface at `/`

RAGAS results:

| Metric | Score |
|---|---:|
| Mean faithfulness | 94.7% |
| Mean answer relevancy | 84.3% |

The live rate limiter has been independently verified to return `429` after
the configured request limit is reached.

## Architecture

The complete system pipeline, component responsibilities, data flow, and
technical decisions are documented in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

The development history, including implementation decisions, bugs, root causes,
and fixes, is documented in [`docs/BUILD_LOG.md`](docs/BUILD_LOG.md).

## Quick start

```bash
git clone https://github.com/SoumyaXD/Sentinel.git
cd Sentinel
python -m venv venv
```

Windows:

```powershell
venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create `.env`:

```env
OPENAI_API_KEY=your_key_here
NVD_API_KEY=your_key_here
```

Run the data pipeline:

```bash
python -m ingest.nvd
python -m ingest.osv
python -m ingest.normalize
python -m rag.chunk
python -m rag.store
```

Run tests:

```bash
python -m unittest discover -s tests
```

Run evaluations:

```bash
python -m eval.run_eval
python -m eval.run_eval_langchain
python -m eval.run_ragas
```

## Docker

Build:

```powershell
docker buildx build `
  --secret id=nvd_api_key,env=NVD_API_KEY `
  -t sentinel:latest `
  --load .
```

Run:

```powershell
docker run --rm -p 8000:8000 `
  -e OPENAI_API_KEY=$env:OPENAI_API_KEY `
  sentinel:latest
```

Then open `http://localhost:8000/`.

## Scope

Sentinel v1 is intentionally scoped to the evaluated CVE RAG system described
above. Agent workflows, MCP integrations, and model fine-tuning are not part
of this version.
