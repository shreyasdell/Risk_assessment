"""
FastAPI router for CVE Agent endpoints.

Provides:
- GET  /api/agent/health       — Check agent and Ollama health
- POST /api/cves/{id}/false-positive — Mark CVE as false positive
"""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.agent.cve_filter_agent import CVEFilterAgent
from app.agent.schemas import (
    AgentHealthResponse,
    MarkFalsePositiveRequest,
)
from app.core.database import get_db
from app.models.cve import CVE
from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/agent", tags=["CVE Agent"])

# ──────────────────────────────────────────────────────────────
# Agent singleton — initialize once, reuse across requests
# ──────────────────────────────────────────────────────────────

_agent_instance: Optional[CVEFilterAgent] = None


def get_agent() -> CVEFilterAgent:
    """Get or create the CVEFilterAgent singleton."""
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = CVEFilterAgent(
            ollama_url=settings.OLLAMA_URL,
            model=settings.OLLAMA_MODEL,
            ollama_timeout=settings.OLLAMA_TIMEOUT,
            display_threshold=settings.CVE_DISPLAY_THRESHOLD,
        )
    return _agent_instance


# ──────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────

@router.get("/health", response_model=AgentHealthResponse)
async def agent_health_check():
    """
    Check the health of the CVE filtering agent and Ollama service.
    """
    agent = get_agent()

    # Check Ollama connectivity
    ollama_healthy = agent.llm_reasoner._check_ollama_health()

    return AgentHealthResponse(
        agent_status="healthy",
        ollama_status="connected" if ollama_healthy else "disconnected",
        ollama_url=settings.OLLAMA_URL,
        model=settings.OLLAMA_MODEL,
        stages=[
            "cpe_matcher",
            "purl_resolver",
            "version_validator",
            "llm_reasoner",
            "confidence_aggregator",
        ],
    )


@router.post("/cves/{cve_db_id}/false-positive")
async def mark_cve_false_positive(
    cve_db_id: int,
    request: MarkFalsePositiveRequest,
    db: Session = Depends(get_db),
):
    """
    Allow users to override the agent decision and mark
    a CVE as a false positive.
    """
    cve = db.query(CVE).filter(CVE.id == cve_db_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")

    cve.is_false_positive = True
    if request.reason:
        cve.agent_reasoning = (
            f"{cve.agent_reasoning or ''}\n\n"
            f"[USER OVERRIDE] Marked as false positive: {request.reason}"
        )

    db.commit()

    return {
        "status": "success",
        "message": f"CVE {cve.cve_id} marked as false positive",
        "cve_id": cve.cve_id,
    }


@router.post("/cves/{cve_db_id}/undo-false-positive")
async def undo_false_positive(
    cve_db_id: int,
    db: Session = Depends(get_db),
):
    """Undo a false positive marking."""
    cve = db.query(CVE).filter(CVE.id == cve_db_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")

    cve.is_false_positive = False
    db.commit()

    return {
        "status": "success",
        "message": f"False positive marking removed for {cve.cve_id}",
    }
