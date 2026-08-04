# Sentinel — Architecture

This document describes how Sentinel's Stage A pipeline is structured: what each
component does, how data flows through the system, and why each piece was built
the way it was.

For a full checkpoint-by-checkpoint account of how this was built (including
every bug found and fixed), see [`BUILD_LOG.md`](BUILD_LOG.md).


## System overview

Sentinel answers questions about known software vulnerabilities (CVEs) by
retrieving grounded facts from a local knowledge base and generating a cited,
factually-checked answer. It does **not** rely on an LLM's training-data
knowledge of CVEs — every answer is required to trace back to a specific,
retrievable source record.

```
                         USER QUERY
                              │
                              ▼
                    ┌─────────────────────┐
                    │   rag/retriever.py    │
                    │                        │
                    │  CVE-ID regex match?   │
                    │   ├─ yes → exact lookup │──────┐
                    │   └─ no  → semantic      │      │
                    │            search         │      │
                    └───────────┬───────────────┘      │
                                │                        │
                    ┌───────────▼───────────┐            │
                    │  rag/store.py           │            │
                    │  (Chroma vector store)   │            │
                    └───────────┬───────────┘            │
                                │                        │
                                ▼                        ▼
                    ┌─────────────────────────────────────┐
                    │        retrieved chunks + metadata     │
                    └───────────────────┬─────────────────┘
                                        │
                                        ▼
                            ┌─────────────────────┐
                            │   rag/generate.py      │
                            │  (OpenAI gpt-4o-mini)   │
                            │  grounded, cited answer  │
                            └─────────────────────┘
```

## Data pipeline (build-time, run once / re-run on data refresh)

```
NVD API + OSV.dev API
        │
        ▼
ingest/nvd.py, ingest/osv.py     → raw JSON cached in data/raw/
        │
        ▼
ingest/normalize.py              → merged, deduplicated CVE records
                                    in data/normalized/all_cves.json
        │
        ▼
rag/chunk.py                     → embeddable text chunks with metadata
        │
        ▼
rag/embed.py + rag/store.py      → vectors persisted in data/chroma/
```

## Component reference

| Module | Responsibility |
|---|---|
| `ingest/config.py` | Single source of truth for the 7 tracked packages (lodash, log4j-core, openssl, django, express, flask, axios) and their ecosystems. |
| `ingest/nvd.py` | Pulls CVE records from the NVD API using CPE-based product matching (not free-text keyword search, which produces false positives — see `BUILD_LOG.md`, Checkpoint A2). |
| `ingest/osv.py` | Pulls vulnerability records from OSV.dev, using ecosystem-specific queries (npm/PyPI/Maven) and a `generic` purl for OpenSSL, which isn't distributed via a language package manager. |
| `ingest/normalize.py` | Merges NVD and OSV records per CVE. NVD is authoritative for CVSS score/severity; OSV is preferred for descriptive text when both sources cover a CVE (OSV's advisories are typically richer). Parses OSV's `ranges`/`events` structure for version matching. |
| `rag/chunk.py` | Converts normalized records into embeddable chunks. Short/NVD-style records become one chunk; long, multi-section OSV advisories are split by logical section, with code blocks kept intact as atomic units. |
| `rag/embed.py` | Wraps `sentence-transformers` (`all-MiniLM-L6-v2`) — a free, local embedding model requiring no API key. |
| `rag/store.py` | Persistent Chroma vector store client. Fails loudly (not silently) if Chroma is unavailable — retrieval never silently substitutes a different mechanism. |
| `rag/retriever.py` | Combines exact CVE-ID lookup (regex-detected, bypasses semantic search entirely) with semantic top-k search, plus package-name-aware reranking. |
| `rag/generate.py` | Retrieved chunks + query → LLM call (OpenAI `gpt-4o-mini`) → grounded, cited answer. Citations are extracted only from `[CVE-YYYY-NNNN]` bracket format, and any cited ID not actually present in retrieved context is stripped as a hard grounding-violation check. |
| `eval/run_eval.py` | Runs the hand-verified evaluation set against the full pipeline, scoring retrieval accuracy, factual accuracy, citation correctness, and trap-question handling. |

## Why RAG, not just an LLM's training knowledge

CVE data changes constantly (new vulnerabilities are published daily) and
requires precise, verifiable facts (exact CVSS scores, exact affected-version
ranges) — the kind of thing LLMs are known to get subtly wrong or go stale on.
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
materially more complete coverage than either alone — see `BUILD_LOG.md`,
Checkpoint A3, for the full comparison.

## Repository structure

```
sentinel/
├── ingest/              # Data ingestion + normalization
│   ├── config.py          Tracked package list
│   ├── nvd.py              NVD API client (CPE-based matching)
│   ├── osv.py               OSV.dev API client
│   └── normalize.py          Merges NVD + OSV into one schema
│
├── rag/                 # Core RAG pipeline
│   ├── chunk.py            Record → embeddable chunks
│   ├── embed.py             Embedding model wrapper
│   ├── store.py              Chroma vector store client
│   ├── retriever.py           Exact-ID + semantic retrieval
│   └── generate.py             Grounded answer generation
│
├── eval/                # Evaluation harness
│   ├── eval_set.json       18 hand-verified Q&A pairs (independently
│   │                        checked against live NVD/OSV, not against
│   │                        this project's own pipeline output)
│   ├── run_eval.py           Scores the pipeline against eval_set.json
│   └── results/               Timestamped eval run outputs (gitignored)
│
├── notebooks/
│   └── 00_explore_raw_data.ipynb   Manual data inspection (Checkpoint A4) —
│                                    the source of the chunking/precedence/
│                                    version-parsing decisions used throughout
│
├── scripts/
│   └── compare_counts.py    NVD vs. OSV count comparison utility
│
├── tests/                # Unit tests for ingest, chunk, retriever, generate
│
├── data/                 # Gitignored — regenerable from source APIs
│   ├── raw/                 Cached raw NVD/OSV API responses
│   ├── normalized/            Merged CVE records
│   └── chroma/                  Persisted vector store
│
├── agent/, mcp/, finetune/, app/    # v2 scope — empty, reserved for
│                                     Stage D (MCP tools), Stage E
│                                     (LangGraph agent), Stage F (LoRA/QLoRA
│                                     fine-tune), and Stage C (FastAPI) work
│
├── docs/
│   ├── PRD.md              Full v1/v2 roadmap and design rationale
│   ├── ARCHITECTURE.md      This file
│   └── BUILD_LOG.md          Full checkpoint-by-checkpoint build history
│
└── README.md
```

## Tech stack

| Layer | Choice | Why |
|---|---|---|
| Data sources | NVD API 2.0, OSV.dev API | Free, authoritative, no auth required for OSV |
| Embedding | `sentence-transformers` (`all-MiniLM-L6-v2`) | Free, runs locally, no GPU required |
| Vector DB | Chroma | Simple local setup, persistent storage |
| Generation | OpenAI `gpt-4o-mini` | Cheapest capable option evaluated (a Gemini free-tier attempt hit a 20 requests/day cap that made a full 18-question eval run impractical — see `BUILD_LOG.md`, Checkpoint A11) |
| Orchestration | Hand-written (Stage A) | Every step built and understood manually before any framework abstraction is introduced (Stage B: LangChain refactor, planned) |

## Known limitations

- **One evaluation entry (`eval-012`, Django 3.1.8 / CVE-2021-31542) is not
  reliably retrieved.** The record exists, is correctly chunked and embedded,
  but ranks around position 75 in semantic similarity — its older, more
  generic advisory phrasing embeds less closely to the query than more
  recently-written advisories for other CVEs. This was deliberately **not**
  fixed by widening the retrieval candidate pool, since doing so would risk
  degrading retrieval quality globally to resolve one specific case. See
  `BUILD_LOG.md`, Checkpoint A11, Round 6, for the full reasoning.
- **Dataset is scoped to 7 packages** (lodash, log4j-core, openssl, django,
  express, flask, axios), not a general CVE search engine. This was a
  deliberate scoping decision to keep the dataset small enough for exhaustive
  manual verification — see `PRD.md`.
