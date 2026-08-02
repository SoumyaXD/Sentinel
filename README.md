## Status

**Stage A — Hand-Built RAG Pipeline: Complete**

Sentinel's core retrieval-augmented generation pipeline is built and 
evaluated end-to-end: CVE data ingestion (NVD + OSV.dev) → normalization → 
chunking → embedding (all-MiniLM-L6-v2) → retrieval (Chroma + exact CVE-ID 
lookup) → grounded answer generation (OpenAI gpt-4o-mini).

### Evaluation Results (18-question hand-verified eval set)

| Metric | Score |
|---|---|
| Retrieved correct CVE | 94.4% |
| Factual accuracy | 94.4% |
| Citation correctness | 94.4% |
| Trap-question handling | 100% |

Target: ≥90% factual accuracy and citation correctness — both met.

One known, documented limitation: a single evaluation entry (Django 
3.1.8 / CVE-2021-31542) is not reliably retrieved due to older, generically-
phrased advisory text ranking low in semantic similarity. This was 
deliberately not force-fixed by widening the retrieval candidate pool, 
since doing so would have risked degrading retrieval quality globally to 
resolve one specific case.

### Next Steps

- **Stage B**: refactor the hand-built retrieval/generation logic into 
  LangChain, re-validated against the same eval set as a regression check
- **Stage C**: FastAPI service + Docker deployment
- **v2**: MCP tools, LangGraph agent, LoRA/QLoRA fine-tuning for hedged 
  security-analyst language