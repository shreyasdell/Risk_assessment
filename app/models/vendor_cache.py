from sqlalchemy import Column, Integer, String, DateTime, Index, Boolean
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.core.database import Base


class VendorProductCache(Base):
    """
    Cache table for vendor/product mappings resolved by LangGraph agent.
    
    Hybrid caching approach:
    - Database: Persistent storage across server restarts
    - In-memory: Fast lookups during runtime (loaded on startup)
    """
    __tablename__ = "vendor_product_cache"

    id = Column(Integer, primary_key=True, index=True)
    component_name = Column(String, nullable=False, index=True)  # Raw component name from SBOM
    nvd_vendor = Column(String, nullable=False, index=True)  # NVD vendor name
    nvd_product = Column(String, nullable=False, index=True)  # NVD product name
    ecosystem = Column(String, nullable=True, index=True)  # Ecosystem (npm, pypi, maven, etc.)
    confidence = Column(Integer, nullable=False)  # 0-100 confidence in this mapping
    resolution_method = Column(String, nullable=False)  # purl_only, purl_cache, llm
    source_purl = Column(String, nullable=True)  # Original PURL that helped resolve this
    hit_count = Column(Integer, default=0)  # How many times this mapping has been used
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Composite index for fast lookups
    __table_args__ = (
        Index('idx_component_ecosystem', 'component_name', 'ecosystem'),
        Index('idx_vendor_product', 'nvd_vendor', 'nvd_product'),
    )


class CPEValidationCache(Base):
    """
    Cache table for NVD CPE dictionary validation results.
    
    Purpose: Reduce repeated NVD CPE API calls by caching validation results.
    TTL: 24 hours (NVD CPE dictionary changes infrequently)
    """
    __tablename__ = "cpe_validation_cache"

    id = Column(Integer, primary_key=True, index=True)
    vendor = Column(String, nullable=False, index=True)
    product = Column(String, nullable=False, index=True)
    validation_status = Column(String, nullable=False)  # VALIDATED, NOT_VALIDATED, VALIDATION_ERROR, RATE_LIMITED
    checked_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)  # TTL for cache entry
    hit_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Composite unique constraint
    __table_args__ = (
        Index('idx_vendor_product_unique', 'vendor', 'product', unique=True),
    )
