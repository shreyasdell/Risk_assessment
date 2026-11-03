"""
Pydantic schemas for agent API requests and responses.
Used by FastAPI for request validation and response serialization.
"""

from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime


# ── Request Schemas ──

class ComponentInput(BaseModel):
    """Component input for CVE filtering."""
    name: str = Field(..., description="Component name", example="carbon")
    version: str = Field(..., description="Component version", example="2.1.1")
    purl: Optional[str] = Field(
        None,
        description="Package URL",
        example="pkg:npm/carbon@2.1.1",
    )
    ecosystem: Optional[str] = Field(
        None,
        description="Package ecosystem (derived from PURL if not provided)",
        example="npm",
    )


class MarkFalsePositiveRequest(BaseModel):
    """Request to mark a CVE as false positive."""
    reason: Optional[str] = Field(
        None,
        description="Optional reason for marking as false positive",
    )


# ── Response Schemas ──

class StageDetailResponse(BaseModel):
    """Detail from a single pipeline stage."""
    stage: str
    verdict: str
    confidence: int
    reasoning: str
    matched_cpe: Optional[str] = None


class AgentHealthResponse(BaseModel):
    """Health check response for the agent."""
    agent_status: str
    ollama_status: str
    ollama_url: str
    model: str
    stages: List[str]
