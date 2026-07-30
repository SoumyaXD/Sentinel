import json
from rag.store import query

topics = [
    "prototype pollution",
    "denial of service via regex",
    "security bug",
]

for topic in topics:
    print(f"\n{'='*60}")
    print(f"QUERY: {topic}")
    print('='*60)
    results = query(topic, k=3)
    for i, r in enumerate(results):
        print(f"\n--- Result {i+1} ---")
        print("CVE:", r["metadata"].get("cve_id"))
        print("Text (first 200 chars):", r["text"][:200])
        print("Score/distance:", r.get("score") or r.get("distance"))