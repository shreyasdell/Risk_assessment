"""
Database model additions for CVE Agent fields.

These fields should be added to your existing CVE model.
If you use Alembic for migrations, generate a migration after adding these.
"""

from sqlalchemy import (
    Column, Integer, String, Text, Boolean,
    Float, JSON, ForeignKey, DateTime,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func


# ──────────────────────────────────────────────────────────────
# OPTION A: If you want a mixin you can add to your existing model
# ──────────────────────────────────────────────────────────────

class CVEAgentMixin:
    """
    Mixin class containing all agent-related columns.

    Usage:
        class CVE(Base, CVEAgentMixin):
            __tablename__ = "cves"
            # ... your existing columns ...
    """
    agent_confidence = Column(
        Integer,
        default=0,
        nullable=False,
        index=True,
        comment="Agent confidence score 0-100",
    )
    agent_verdict = Column(
        String(20),
        default="UNPROCESSED",
        nullable=False,
        index=True,
        comment="RELEVANT | NOT_RELEVANT | NEEDS_REVIEW | UNPROCESSED",
    )
    agent_reasoning = Column(
        Text,
        nullable=True,
        comment="Human-readable explanation of agent decision",
    )
    match_method = Column(
        String(50),
        nullable=True,
        comment="How match was determined: cpe_exact, ecosystem_mismatch, llm_analysis, etc.",
    )
    stage_details = Column(
        JSON,
        nullable=True,
        comment="Full stage-by-stage breakdown as JSON array",
    )
    is_false_positive = Column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
        comment="User override: manually marked as false positive",
    )
    agent_processing_time = Column(
        Float,
        nullable=True,
        comment="Time taken by agent pipeline in seconds",
    )
    agent_processed_at = Column(
        DateTime,
        nullable=True,
        comment="Timestamp when agent last processed this CVE",
    )
