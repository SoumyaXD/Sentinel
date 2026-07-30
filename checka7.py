import json
from rag.chunk import chunk_cve_record

# Load normalized data
data = json.load(open("data/normalized/all_cves.json", encoding="utf-8"))

# --- Check 1: CVE-2020-28500 should split into multiple chunks ---
record = next((r for r in data if r["cve_id"] == "CVE-2020-28500"), None)
chunks = chunk_cve_record(record)
print(f"=== CVE-2020-28500 produced {len(chunks)} chunk(s) ===")
for i, c in enumerate(chunks):
    print(f"\n--- Chunk {i+1} ---")
    print("Metadata:", c["metadata"])
    print("Text (first 200 chars):", c["text"][:200])

# --- Check 2: CVE-1999-0428 (OpenSSL, NVD-only) should produce ONE chunk ---
record2 = next((r for r in data if r["cve_id"] == "CVE-1999-0428"), None)
chunks2 = chunk_cve_record(record2)
print(f"\n\n=== CVE-1999-0428 produced {len(chunks2)} chunk(s) ===")
for i, c in enumerate(chunks2):
    print(f"\n--- Chunk {i+1} ---")
    print("Metadata:", c["metadata"])
    print("Text:", c["text"])