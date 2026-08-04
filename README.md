# Sentinel

**A CVE research and patch-prioritization RAG pipeline.**

Sentinel answers questions about known software vulnerabilities (CVEs) by
retrieving grounded facts from real NVD/OSV.dev data and generating a cited,
factually-checked answer — instead of relying on an LLM's own (often stale or
imprecise) knowledge of specific vulnerabilities.

Example: *"What CVEs affect lodash version 4.17.10?"* → Sentinel retrieves
the actual matching CVE records, and answers with the correct CVSS scores,
affected-version ranges, and a citation for every claim.


## Status

**Stage A — Hand-Built RAG Pipeline: Complete **

The core retrieval-augmented generation pipeline is built and evaluated
end-to-end: CVE data ingestion (NVD + OSV.dev) → normalization → chunking →
embedding (`all-MiniLM-L6-v2`) → retrieval (Chroma + exact CVE-ID lookup) →
grounded answer generation (OpenAI `gpt-4o-mini`).

### Evaluation results

Scored against an 18-question hand-verified evaluation set, with ground
truth independently checked against live NVD/OSV.dev (not against this
project's own pipeline output):

| Metric | Score |
|---|---|
| Retrieved correct CVE | 94.4% |
| **Factual accuracy** | **94.4%** |
| **Citation correctness** | **94.4%** |
| Trap-question handling | 100% |

Target: ≥90% factual accuracy and citation correctness — both met.

One known, documented limitation: a single evaluation entry is not reliably
retrieved due to older, generically-phrased advisory text ranking low in
semantic similarity — deliberately not force-fixed, since doing so would risk
degrading retrieval quality globally to resolve one specific case. Full
reasoning in [`docs/BUILD_LOG.md`](docs/BUILD_LOG.md).

### Roadmap

- **Stage B** *(next)* — refactor the hand-built retrieval/generation logic
  into LangChain, re-validated against the same eval set as a regression check
- **Stage C** — FastAPI service + Docker deployment
- **v2** — MCP tools, a LangGraph agent (router + verifier)

See [`docs/PRD.md`](docs/PRD.md) for the full staged roadmap.


## Quick start

```bash
git clone https://github.com/SoumyaXD/Sentinel.git
cd Sentinel
python -m venv venv
venv\Scripts\Activate.ps1        # Windows
# source venv/bin/activate       # macOS/Linux

pip install -r requirements.txt
```

Create a `.env` file (see `.env.example`) with:
```
OPENAI_API_KEY=your_key_here
NVD_API_KEY=your_key_here        # optional, raises NVD rate limit
```

Run the full pipeline from scratch:
```bash
python -m ingest.nvd
python -m ingest.osv
python -m ingest.normalize
python -m rag.chunk
python -m rag.store
python -m rag.generate            # try the 5 built-in test queries
```

Run the evaluation suite:
```bash
python -m eval.run_eval
```

Run tests:
```bash
python -m unittest discover -s tests
```


## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — system design, data flow,
  component reference, tech stack
- [`docs/BUILD_LOG.md`](docs/BUILD_LOG.md) — full checkpoint-by-checkpoint
  development history, including every bug found and how it was root-caused
  and fixed (data-quality defects, encoding bugs, prompt-engineering
  iterations, and more)
- [`docs/PRD.md`](docs/PRD.md) — the original staged roadmap (v1: hand-built
  RAG → LangChain → FastAPI/Docker; v2: MCP tools → LangGraph agent →
  LoRA/QLoRA fine-tune)

## Why this project

Built as a demonstration of the full modern RAG/LLM engineering stack — RAG,
vector databases, LangChain, LangGraph, MCP tools, agent workflows — staged so each layer is learned and built on top of a working, evaluated foundation rather than assembled all at once. Full
reasoning behind the staging decisions is in `docs/PRD.md`.
