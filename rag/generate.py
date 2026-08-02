"""Grounded answer generation on top of retrieved CVE chunks."""

from __future__ import annotations

import json
import os
import re
from typing import Any

import httpx
from dotenv import load_dotenv

from rag.retriever import retrieve


load_dotenv()

CVE_ID_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")


def _normalize_cve_id(value: str) -> str:
    return value.upper()


def _unique_cve_ids(text: str) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for match in CVE_ID_RE.findall(text):
        normalized = _normalize_cve_id(match)
        if normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered




def _format_affected_packages(metadata: dict[str, Any]) -> str:
    packages = metadata.get("affected_packages", [])
    if not isinstance(packages, list) or not packages:
        return ""

    labels: list[str] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = str(package.get("name", "")).strip()
        ecosystem = str(package.get("ecosystem", "")).strip()
        if not name and not ecosystem:
            continue
        if name and ecosystem:
            labels.append(f"{name} ({ecosystem})")
        else:
            labels.append(name or ecosystem)

    if not labels:
        return ""

    if len(labels) == 1:
        return f"Affected package: {labels[0]}"
    return "Affected packages: " + "; ".join(labels)


def _format_chunk_context(chunk: dict[str, Any], index: int) -> str:
    metadata = chunk.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    cve_id = str(metadata.get("cve_id", "UNKNOWN-CVE")).strip() or "UNKNOWN-CVE"
    chunk_type = str(metadata.get("chunk_type", f"chunk_{index}")).strip() or f"chunk_{index}"
    lines = [f"[Chunk {index}] CVE ID: {cve_id}", f"Chunk type: {chunk_type}"]

    affected_packages = _format_affected_packages(metadata)
    if affected_packages:
        lines.append(affected_packages)

    text = str(chunk.get("text", "")).strip()
    if text:
        lines.append("Evidence:")
        lines.append(text)

    return "\n".join(lines)


def _build_context(retrieved_chunks: list[dict[str, Any]]) -> str:
    formatted_chunks = [
        _format_chunk_context(chunk, index)
        for index, chunk in enumerate(retrieved_chunks, start=1)
        if isinstance(chunk, dict)
    ]
    return "\n\n---\n\n".join(formatted_chunks)


def _build_messages(query: str, context: str) -> list[dict[str, str]]:
    system_prompt = (
        "You are a security assistant answering questions about CVEs.\n"
        "Answer ONLY using the provided CVE context below. Do not use outside knowledge or guess.\n"
        "Cite the specific CVE ID(s) actually used in every answer.\n"
        "If the provided context does not actually answer the question, say so explicitly rather than forcing an answer.\n"
        "When you do answer, include inline citations in the form [CVE-YYYY-NNNN] for every factual claim.\n"
        "Keep the answer concise and grounded in the evidence."
    )

    user_prompt = (
        f"Question:\n{query}\n\n"
        f"Provided CVE context:\n{context}\n\n"
        "Respond with a grounded answer using only the context."
    )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


def _extract_message_content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices", [])
    if not isinstance(choices, list) or not choices:
        raise RuntimeError("OpenAI response did not include any choices")

    message = choices[0].get("message", {})
    if not isinstance(message, dict):
        raise RuntimeError("OpenAI response missing message")

    content = message.get("content", "")
    if isinstance(content, str):
        return content.strip()

    return str(content).strip()


def _call_llm(query: str, retrieved_chunks: list[dict[str, Any]]) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is required to generate grounded answers. Get a key at https://platform.openai.com/api-keys")

    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")

    context = _build_context(retrieved_chunks)
    messages = _build_messages(query, context)
    payload = {
        "model": DEFAULT_MODEL,
        "messages": messages,
        "temperature": 0,
        "max_tokens": 500,
    }

    with httpx.Client(timeout=60.0) as client:
        response = client.post(
            f"{base_url}/chat/completions",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            json=payload,
        )
        response.raise_for_status()

    data = response.json()
    return _extract_message_content(data)


def generate_answer(query: str, retrieved_chunks: list[dict[str, Any]]) -> dict[str, Any]:
    if not retrieved_chunks:
        return {
            "answer": f"No matching CVE found for query: {query}",
            "cited_cve_ids": [],
        }

    answer = _call_llm(query, retrieved_chunks)
    return {
        "answer": answer,
        "cited_cve_ids": _unique_cve_ids(answer),
    }


def _print_query(query: str) -> None:
    retrieved_chunks = retrieve(query)
    result = generate_answer(query, retrieved_chunks)
    print(json.dumps({"query": query, **result}, indent=2, ensure_ascii=False))
    print()


def main() -> None:
    queries = [
        "What is CVE-2020-28500?",
        "lodash regex denial of service",
        "What is CVE-9999-99999?",
        "remote code execution vulnerability",
        "What is CVE-2008-2302?",
    ]

    for query in queries:
        _print_query(query)


if __name__ == "__main__":
    main()
