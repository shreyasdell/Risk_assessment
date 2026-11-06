from sqlalchemy import Column, Integer, String, DateTime, Index
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
