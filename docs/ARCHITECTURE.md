# Sentinel Architecture

This document describes how Sentinel's Stage A pipeline is structured: what each
component does, how data flows through the system, and why each piece was built
the way it was.

For the staged v1/v2 roadmap and design rationale, see [`PRD.md`](PRD.md).
For a full checkpoint-by-checkpoint account of how this was built (including
every bug found and fixed), see [`BUILD_LOG.md`](BUILD_LOG.md).

---

## System overview

Sentinel answers questions about known software vulnerabilities (CVEs) by
retrieving grounded facts from a local knowledge base and generating a cited,
factually-checked answer. It does **not** rely on an LLM's training-data
knowledge of CVEs. Every answer is required to trace back to a specific,
retrievable source record.

The pipeline exists in two parallel implementations sharing the same
underlying data: a **hand-built version** (`rag/retriever.py` +
`rag/generate.py`, Stage A) kept as a reference/baseline, and a
**LangChain-based version** (`rag/chains.py` + `rag/generation_chain.py`,
Stage B) that is the current production path, validated to exactly match
Stage A's evaluation scores with zero regression.

```
USER QUERY
│
▼
┌─────────────────────┐
│ rag/retriever.py │ ← exact CVE-ID regex
│ (shared by both bypass, used by both
│ Stage A and B) Stage A and B paths
└───────────┬───────────┘
│
CVE-ID found? ──yes──► direct lookup against
│ data/normalized/all_cves.json
no
│
┌───────────▼───────────────────────┐
│ Stage A: rag/store.py │
│ Stage B: rag/chains.py │ (LangChain-
│ get_retriever() wrapped
│ (same Chroma store, Chroma,
│ same embeddings) production)
└───────────┬───────────────────────┘
│
┌───────────▼───────────┐
│ retrieved chunks + │
│ metadata │
└───────────┬───────────┘
│
┌───────────▼───────────────────────┐
│ Stage A: rag/generate.py │
│ Stage B: rag/generation_chain.py │ (provider-
│ (LLM_PROVIDER env var, swappable,
│ OpenAI gpt-4o-mini) production)
└───────────┬───────────────────────┘
│
▼
grounded, cited answer
│
┌───────────▼───────────────────────┐
│ Evaluation (two independent layers) │
│ 1. Deterministic (eval/run_eval*.py) │
│ exact CVSS/citation match against │
│ hand-verified ground truth │
│ 2. RAGAS (eval/run_ragas.py) │
│ LLM-judge faithfulness + relevancy │
└─────────────────────────────────────────┘
```

## Data pipeline (build-time, run once / re-run on data refresh)

```
NVD API + OSV.dev API
│
▼
ingest/nvd.py, ingest/osv.py → raw JSON cached in data/raw/
│
▼
ingest/normalize.py → merged, deduplicated CVE records
in data/normalized/all_cves.json
│
▼
rag/chunk.py → embeddable text chunks with metadata
│
▼
rag/embed.py + rag/store.py → vectors persisted in data/chroma/
```

## Component reference

| Module | Responsibility |
|---|---|
| `ingest/config.py` | Single source of truth for the 7 tracked packages (lodash, log4j-core, openssl, django, express, flask, axios) and their ecosystems. |
| `ingest/nvd.py` | Pulls CVE records from the NVD API using CPE-based product matching (not free-text keyword search, which produces false positives. See `BUILD_LOG.md`, Checkpoint A2). |
| `ingest/osv.py` | Pulls vulnerability records from OSV.dev, using ecosystem-specific queries (npm/PyPI/Maven) and a `generic` purl for OpenSSL, which isn't distributed via a language package manager. |
| `ingest/normalize.py` | Merges NVD and OSV records per CVE. NVD is authoritative for CVSS score/severity; OSV is preferred for descriptive text when both sources cover a CVE (OSV's advisories are typically richer). Parses OSV's `ranges`/`events` structure for version matching. |
| `rag/chunk.py` | Converts normalized records into embeddable chunks. Short/NVD-style records become one chunk; long, multi-section OSV advisories are split by logical section, with code blocks kept intact as atomic units. |
| `rag/embed.py` | Wraps `sentence-transformers` (`all-MiniLM-L6-v2`), a free, local embedding model requiring no API key. Used directly by both Stage A's `rag/store.py` and Stage B's `SentinelEmbeddings` LangChain adapter, guaranteeing identical embeddings across both paths. |
| `rag/store.py` | **(Stage A)** Persistent Chroma vector store client, hand-written. Fails loudly (not silently) if Chroma is unavailable, retrieval never silently substitutes a different mechanism. |
| `rag/retriever.py` | **(shared by Stage A and B)** Exact CVE-ID regex detection and direct lookup against normalized data, bypassing semantic search entirely for ID-based queries. Used identically by both the Stage A and Stage B generation paths. |
| `rag/generate.py` | **(Stage A)** Retrieved chunks + query → hand-written LLM call → grounded, cited answer. Kept as the reference implementation. |
| `rag/chains.py` | **(Stage B)** Wraps the same persisted Chroma store in LangChain's retriever interface via a custom `SentinelEmbeddings` adapter (calls `rag/embed.py` directly, rather than a separate embedding reimplementation, to guarantee compatibility with already-stored vectors). |
| `rag/generation_chain.py` | **(Stage B, production)** LangChain-based generation, provider-swappable via an `LLM_PROVIDER` environment variable (currently OpenAI `gpt-4o-mini` implemented; adding a new provider requires one new branch rather than a rewrite. See `BUILD_LOG.md` for why this was made a hard requirement). Preserves Stage A's exact system prompt and grounding/citation logic. |
| `eval/eval_set.json` | 18 hand-verified question/answer pairs, ground truth independently checked against live NVD/OSV.dev. Shared by all evaluation harnesses below. |
| `eval/run_eval.py` | Deterministic evaluation of the Stage A (hand-built) pipeline: CVSS/citation exact-match scoring against ground truth. |
| `eval/run_eval_langchain.py` | Deterministic evaluation of the Stage B (LangChain) pipeline, using identical scoring logic, the regression check confirming the refactor introduced no behavioral change. |
| `eval/run_ragas.py` | LLM-as-judge evaluation (faithfulness, answer relevancy) of the Stage B pipeline, catches a different failure class than the deterministic harnesses: correct citations paired with prose claims not fully supported by retrieved context. |

## Why RAG, not just an LLM's training knowledge

CVE data changes constantly (new vulnerabilities are published daily) and
requires precise, verifiable facts (exact CVSS scores, exact affected-version
ranges), the kind of thing LLMs are known to get subtly wrong or go stale on.
Sentinel's design principle throughout: **facts come from retrieval, never
from the model's own knowledge.** This is enforced at the prompt level (the
system prompt explicitly forbids citing anything not present in retrieved
context) and validated at the evaluation level (the eval harness checks that
generated CVSS scores match independently-verified ground truth, and that
cited CVE IDs are always grounded in what was actually retrieved).

## Why two data sources (NVD + OSV), not one

NVD and OSV have complementary, not redundant, coverage. Cross-comparing counts
across all 7 tracked packages found genuine asymmetries: NVD has stronger
historical coverage for non-package-manager software (e.g. OpenSSL, a C
library with 294 NVD records vs. only 10 in OSV), while OSV has more granular,
faster-updated coverage for actively-maintained package-manager-native software
(e.g. Django, 313 OSV records vs. 153 in NVD). Merging both sources yields
materially more complete coverage than either alone. See `BUILD_LOG.md`,
Checkpoint A3, for the full comparison.

## Repository structure

```
sentinel/
├── ingest/ # Data ingestion + normalization
│ ├── config.py Tracked package list
│ ├── nvd.py NVD API client (CPE-based matching)
│ ├── osv.py OSV.dev API client
│ └── normalize.py Merges NVD + OSV into one schema
│
├── rag/ # Core RAG pipeline
│ ├── chunk.py Record → embeddable chunks
│ ├── embed.py Embedding model wrapper (shared by both paths)
│ ├── store.py Stage A: hand-written Chroma client
│ ├── retriever.py Exact-ID + semantic retrieval (shared)
│ ├── generate.py Stage A: hand-written generation
│ ├── chains.py Stage B: LangChain-wrapped vector store
│ └── generation_chain.py Stage B: LangChain generation (production)
│
├── eval/ # Evaluation harnesses (two independent layers)
│ ├── eval_set.json 18 hand-verified Q&A pairs (independently
│ │ checked against live NVD/OSV, not against
│ │ this project's own pipeline output)
│ ├── run_eval.py Deterministic eval: Stage A pipeline
│ ├── run_eval_langchain.py Deterministic eval: Stage B pipeline
│ │ (regression check against Stage A)
│ ├── run_ragas.py RAGAS faithfulness + answer relevancy
│ └── results/ Timestamped eval run outputs (gitignored)
│
├── notebooks/
│ └── 00_explore_raw_data.ipynb Manual data inspection (Checkpoint A4)
│ the source of the chunking/precedence/
│ version-parsing decisions used throughout
│
├── scripts/
│ └── compare_counts.py NVD vs. OSV count comparison utility
│
├── tests/ # Unit tests for ingest, chunk, retriever, generate
│
├── data/ # Gitignored, regenerable from source APIs
│ ├── raw/ Cached raw NVD/OSV API responses
│ ├── normalized/ Merged CVE records
│ └── chroma/ Persisted vector store
│
├── agent/, mcp/, finetune/, app/ # v2 scope, empty, reserved for
│ Stage D (MCP tools), Stage E
│ (LangGraph agent), Stage F (LoRA/QLoRA
│ fine-tune), and Stage C (FastAPI) work
│
├── docs/
│ ├── PRD.md Full v1/v2 roadmap and design rationale
│ ├── ARCHITECTURE.md This file
│ └── BUILD_LOG.md Full checkpoint-by-checkpoint build history
│
└── README.md
```

## Tech stack

| Layer | Choice | Why |
|---|---|---|
| Data sources | NVD API 2.0, OSV.dev API | Free, authoritative, no auth required for OSV |
| Embedding | `sentence-transformers` (`all-MiniLM-L6-v2`) | Free, runs locally, no GPU required |
| Vector DB | Chroma | Simple local setup, persistent storage |
| Orchestration | Hand-written (Stage A) → LangChain (Stage B, production) | Every step built and understood manually before the framework abstraction was introduced; Stage B validated to exactly match Stage A's behavior with zero regression |
| Generation | OpenAI `gpt-4o-mini`, provider-swappable via `LLM_PROVIDER` env var | Cheapest capable option evaluated. Provider-swappability was made a hard Stage B requirement after generation logic needed manual rewriting three times across OpenAI/Ollama/Gemini due to billing and quota issues. See `BUILD_LOG.md`, Checkpoints A10 and B2 |
| Evaluation | Deterministic (custom harness) + RAGAS (LLM-as-judge) | Two independent, complementary layers: exact fact/citation matching against hand-verified ground truth, plus faithfulness/relevancy scoring that catches correct-citation-with-unsupported-claims failures the deterministic harness cannot |

## Known limitations

- **One evaluation entry (`eval-012`, Django 3.1.8 / CVE-2021-31542) is not
reliably retrieved.** The record exists, is correctly chunked and embedded,
but ranks around position 75 in semantic similarity, its older, more
generic advisory phrasing embeds less closely to the query than more
recently-written advisories for other CVEs. This was deliberately **not**
fixed by widening the retrieval candidate pool, since doing so would risk
degrading retrieval quality globally to resolve one specific case. Confirmed
identical in both Stage A and Stage B (LangChain) evaluation runs, and
correctly excluded from RAGAS faithfulness/relevancy scoring as a genuine
refusal rather than scored as a spurious 0.0. See `BUILD_LOG.md`,
Checkpoint A11 Round 6 and the Checkpoint C1 follow-ups, for the full
reasoning.
- **RAGAS faithfulness scores a small, consistent gap on version-inference
answers** (e.g. `eval-007`, `eval-008`, `eval-009`, faithfulness 0.75–0.89):
the pipeline correctly infers that a CVE affecting "versions before X"
therefore affects a specific version Y < X, but RAGAS's literal-entailment
faithfulness metric doesn't fully credit valid inference the way it credits
direct textual restatement. Investigated and confirmed to be a metric/
behavior mismatch, not a generation defect. No fix was applied. See
`BUILD_LOG.md`, Checkpoint C1 follow-ups.
- **Dataset is scoped to 7 packages** (lodash, log4j-core, openssl, django,
express, flask, axios), not a general CVE search engine. This was a
deliberate scoping decision to keep the dataset small enough for exhaustive
manual verification, see `PRD.md`.