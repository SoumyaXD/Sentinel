# Sentinel

**A CVE research and patch-prioritization RAG pipeline.**

Sentinel answers questions about known software vulnerabilities (CVEs) by
retrieving grounded facts from real NVD/OSV.dev data and generating a cited,
factually-checked answer, instead of relying on an LLM's own (often stale or
imprecise) knowledge of specific vulnerabilities.

Example: *"What CVEs affect lodash version 4.17.10?"* → Sentinel retrieves
the actual matching CVE records, and answers with the correct CVSS scores,
affected-version ranges, and a citation for every claim.

---

## Status

**Stage A, Hand-Built RAG Pipeline: Complete**
**Stage B, LangChain Refactor: Core Complete**
**Stage C, FastAPI + Docker + Deploy: In Progress**

The core retrieval-augmented generation pipeline is built, refactored into
LangChain, and evaluated end-to-end: CVE data ingestion (NVD + OSV.dev) →
normalization → chunking → embedding (`all-MiniLM-L6-v2`) → retrieval
(LangChain-wrapped Chroma + exact CVE-ID lookup) → grounded answer
generation (OpenAI `gpt-4o-mini`, provider-swappable via configuration).

### Evaluation results

**Deterministic evaluation** (18-question hand-verified set, ground truth
independently checked against live NVD/OSV.dev):

| Metric | Stage A | Stage B (LangChain) |
|---|---|---|
| Retrieved correct CVE | 94.4% | 94.4% |
| **Factual accuracy** | **94.4%** | **94.4%** |
| **Citation correctness** | **94.4%** | **94.4%** |
| Trap-question handling | 100% | 100% |

Target: ≥90% factual accuracy and citation correctness, met in both
Stage A and Stage B, with **zero regression** from the LangChain refactor.

**RAGAS evaluation** (LLM-as-judge, complementary to the deterministic
harness above, catches a different failure class: correct citations
paired with unsupported prose claims):

| Metric | Score |
|---|---|
| Mean faithfulness | 94.7% |
| Mean answer relevancy | 84.3% |

One known, documented limitation carried through both evaluation layers: a
single question is not reliably retrieved due to older, generically-phrased
advisory text ranking low in semantic similarity, deliberately not
force-fixed, since doing so would risk degrading retrieval quality globally
to resolve one specific case. Full reasoning in
[`docs/BUILD_LOG.md`](docs/BUILD_LOG.md).

### Roadmap

- **Stage C** *(in progress)*, RAGAS evaluation, FastAPI `/ask`
endpoint, rate limiting, Docker, deployment
- **v2**, MCP tools, a LangGraph agent (router + verifier + conversation
memory), and a LoRA/QLoRA fine-tune for hedged, analyst-style severity
language

See [`docs/PRD.md`](docs/PRD.md) for the full staged roadmap.

---

## Quick start

```bash
git clone https://github.com/SoumyaXD/Sentinel.git
cd Sentinel
python -m venv venv
venv\Scripts\Activate.ps1 # Windows
# source venv/bin/activate # macOS/Linux

pip install -r requirements.txt
```

Create a `.env` file (see `.env.example`) with:
```
OPENAI_API_KEY=your_key_here
NVD_API_KEY=your_key_here # optional, raises NVD rate limit
```

Run the full pipeline from scratch:
```bash
python -m ingest.nvd
python -m ingest.osv
python -m ingest.normalize
python -m rag.chunk
python -m rag.store
python -m rag.generate # Stage A hand-built path (reference)
```

Ask a question via the production (Stage B, LangChain) path:
```bash
python -c "
from rag.chains import get_retriever
from rag.retriever import retrieve, CVE_ID_RE
from rag.generation_chain import generate_answer

question = 'What is CVE-2020-28500?'
chunks = retrieve(question) if CVE_ID_RE.search(question) else [
{'text': d.page_content, 'metadata': d.metadata} for d in get_retriever().invoke(question)
]
print(generate_answer(question, chunks))
"
```

Run the evaluation suites:
```bash
python -m eval.run_eval # Stage A deterministic eval
python -m eval.run_eval_langchain # Stage B deterministic eval (regression check)
python -m eval.run_ragas # RAGAS faithfulness + answer relevancy
```

Run tests:
```bash
python -m unittest discover -s tests
```

---

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), system design, data flow,
component reference, tech stack
- [`docs/BUILD_LOG.md`](docs/BUILD_LOG.md), full checkpoint-by-checkpoint
development history, including every bug found and how it was root-caused
and fixed (data-quality defects, encoding bugs, prompt-engineering
iterations, and more)
- [`docs/PRD.md`](docs/PRD.md), the original staged roadmap (v1: hand-built
RAG → LangChain → FastAPI/Docker; v2: MCP tools → LangGraph agent →
LoRA/QLoRA fine-tune)

## Why this project

Built as a demonstration of the full modern RAG/LLM engineering stack: RAG,
vector databases, LangChain, LangGraph, MCP tools, agent workflows, and
LoRA/QLoRA fine-tuning, staged so each layer is learned and built on top of
a working, evaluated foundation rather than assembled all at once. Full
reasoning behind the staging decisions is in `docs/PRD.md`.