"""Pydantic request/response models for the /ask endpoint."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AskRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=500, description="Natural-language CVE question or exact CVE ID.")


class AskResponse(BaseModel):
    answer: str
    cited_cve_ids: list[str]
    retrieved_count: int