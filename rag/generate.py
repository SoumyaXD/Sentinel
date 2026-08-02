"""Grounded answer generation on top of retrieved CVE chunks."""

from __future__ import annotations

import json
import os
import re
import logging
from typing import Any

import httpx
from dotenv import load_dotenv

from rag.retriever import retrieve


load_dotenv()

logger = logging.getLogger(__name__)

BRACKET_CVE_CITATION_RE = re.compile(r"\[(CVE-\d{4}-\d+)\]", re.IGNORECASE)
DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")


def _normalize_cve_id(value: str) -> str:
    return value.upper()


def _unique_cve_ids(text: str) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for match in BRACKET_CVE_CITATION_RE.findall(text):
        normalized = _normalize_cve_id(match)
        if normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


def _retrieved_context_cve_ids(retrieved_chunks: list[dict[str, Any]]) -> set[str]:
    context_cve_ids: set[str] = set()
    for chunk in retrieved_chunks:
        if not isinstance(chunk, dict):
            continue
        metadata = chunk.get("metadata", {})
        if not isinstance(metadata, dict):
            continue
        cve_id = metadata.get("cve_id")
        if isinstance(cve_id, str) and cve_id.strip():
            context_cve_ids.add(_normalize_cve_id(cve_id))
    return context_cve_ids


def _filter_cited_cve_ids(
    cited_cve_ids: list[str],
    retrieved_chunks: list[dict[str, Any]],
    *,
    query: str,
) -> list[str]:
    context_cve_ids = _retrieved_context_cve_ids(retrieved_chunks)
    if not context_cve_ids:
        return []

    valid_cited_ids: list[str] = []
    invalid_cited_ids: list[str] = []

    for cve_id in cited_cve_ids:
        normalized = _normalize_cve_id(cve_id)
        if normalized in context_cve_ids:
            valid_cited_ids.append(normalized)
        else:
            invalid_cited_ids.append(normalized)

    if invalid_cited_ids:
        logger.warning(
            "Dropping CVE citation(s) not present in retrieved context for query %r: %s",
            query,
            ", ".join(invalid_cited_ids),
        )

    return valid_cited_ids




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
        "You must NEVER mention or cite any CVE ID that does not appear verbatim in the CONTEXT section above, even if you recognize it from other knowledge.\n"
        "If you are not fully confident a CVE ID appears in the provided context, do not include it.\n"
        "Whenever you state that a specific CVE applies to the question being asked, you MUST wrap that CVE ID in square brackets in this exact format: [CVE-YYYY-NNNN], immediately after mentioning it in your answer.\n"
        "This applies EVERY time you assert a CVE is relevant, not just once, and not only in a separate citations list.\n"
        "Do not write a bare CVE ID by itself as a citation; the bracketed form is required for every asserted CVE mention.\n"
        "Example of CORRECT format: CVE-2020-28500 [CVE-2020-28500] is a ReDoS vulnerability affecting lodash.\n"
        "Do NOT use bracket format when explaining that a CVE does NOT apply to the question.\n"
        "If the question asks about an exact version, only cite CVEs whose affected-version range actually includes that exact version.\n"
        "If a retrieved CVE does not apply to the asked version, state that explicitly instead of citing it.\n"
        "Always include the CVSS score and severity for every CVE you cite, unless the provided context genuinely has no CVSS for that record.\n"
        "If the context contains multiple CVEs that are genuinely relevant to the question, synthesize them all into one answer instead of refusing to answer.\n"
        "Do not say 'No relevant CVE found.' merely because some retrieved CVEs are irrelevant or because you are seeing more than one candidate.\n"
        "Only say 'No relevant CVE found.' when none of the retrieved CVEs actually apply to the question.\n"
        "If no relevant CVE applies, say exactly 'No relevant CVE found.'\n"
        "If the provided context does not actually answer the question, say so explicitly rather than forcing an answer.\n"
        "Keep the answer concise and grounded in the evidence."
    )

    user_prompt = (
        f"Question:\n{query}\n\n"
        f"Provided CVE context:\n{context}\n\n"
        "Respond with a grounded answer using only the context."
    )

    example_user_prompt = (
        "Question:\nWhat is CVE-2020-28500?\n\n"
        "Provided CVE context:\n"
        "[Chunk 1] CVE ID: CVE-2020-28500\n"
        "Chunk type: full\n"
        "Evidence:\n"
        "CVE-2020-28500 (CVSS 5.3, MEDIUM): lodash is vulnerable to regular expression denial of service.\n\n"
        "Respond with a grounded answer using only the context."
    )
    example_assistant_response = (
        "CVE-2020-28500 [CVE-2020-28500] is a ReDoS vulnerability affecting lodash. "
        "It has CVSS 5.3 and is MEDIUM severity."
    )

    example_user_prompt_2 = (
        "Question:\nWhat is CVE-2008-2302?\n\n"
        "Provided CVE context:\n"
        "[Chunk 1] CVE ID: CVE-2008-2302\n"
        "Chunk type: full\n"
        "Evidence:\n"
        "CVE-2008-2302 (CVSS 4.3, MEDIUM): Django login form XSS vulnerability.\n\n"
        "Respond with a grounded answer using only the context."
    )
    example_assistant_response_2 = (
        "CVE-2008-2302 [CVE-2008-2302] is a Django login form XSS vulnerability. "
        "It has CVSS 4.3 and is MEDIUM severity."
    )

    example_user_prompt_3 = (
        "Question:\nAre there any remote code execution vulnerabilities in OpenSSL?\n\n"
        "Provided CVE context:\n"
        "[Chunk 1] CVE ID: CVE-2002-0656\n"
        "Chunk type: full\n"
        "Evidence:\n"
        "CVE-2002-0656 (CVSS 7.5, HIGH): Buffer overflows in OpenSSL allow remote attackers to execute arbitrary code.\n\n"
        "---\n\n"
        "[Chunk 2] CVE ID: CVE-2007-5135\n"
        "Chunk type: full\n"
        "Evidence:\n"
        "CVE-2007-5135 (CVSS 6.8, MEDIUM): Off-by-one error in OpenSSL might allow remote attackers to execute arbitrary code.\n\n"
        "Respond with a grounded answer using only the context."
    )
    example_assistant_response_3 = (
        "Yes. CVE-2002-0656 [CVE-2002-0656] is a HIGH-severity remote code execution issue in OpenSSL with CVSS 7.5, and CVE-2007-5135 [CVE-2007-5135] is a MEDIUM-severity issue with CVSS 6.8 that might allow arbitrary code execution."
    )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": example_user_prompt},
        {"role": "assistant", "content": example_assistant_response},
        {"role": "user", "content": example_user_prompt_2},
        {"role": "assistant", "content": example_assistant_response_2},
        {"role": "user", "content": example_user_prompt_3},
        {"role": "assistant", "content": example_assistant_response_3},
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
    cited_cve_ids = _unique_cve_ids(answer)
    cited_cve_ids = _filter_cited_cve_ids(cited_cve_ids, retrieved_chunks, query=query)
    return {
        "answer": answer,
        "cited_cve_ids": cited_cve_ids,
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
