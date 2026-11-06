from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.core.database import Base


class Component(Base):
    __tablename__ = "components"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    version = Column(String, index=True, nullable=False)
    component_type = Column(String, default="library")  # Changed from Enum to String for PostgreSQL compatibility
    purl = Column(String, index=True, nullable=True)  # Package URL (not unique - can exist in multiple applications)
    supplier = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    license = Column(String, nullable=True)
    cpe = Column(String, nullable=True)  # Common Platform Enumeration
    application_id = Column(Integer, ForeignKey("applications.id"), nullable=True)
    sbom_id = Column(String, index=True, nullable=True)  # Track which SBOM this came from
    
    # Normalization fields (legacy, kept for backward compatibility)
    normalized_name = Column(String, nullable=True, index=True)  # Canonical NVD-searchable name
    identified_vendor = Column(String, nullable=True)  # Identified vendor organization
    normalization_method = Column(String, nullable=True)  # How normalization was done (tier1_purl, tier2_lookup, tier3_llm, fallback)
    
    # LangGraph Agent enriched fields (NEW)
    nvd_vendor = Column(String, nullable=True, index=True)  # NVD vendor name for CPE construction
    nvd_product = Column(String, nullable=True, index=True)  # NVD product name for CPE construction
    search_name = Column(String, nullable=True, index=True)  # Optimized search term for NVD keyword API
    clean_version = Column(String, nullable=True)  # Cleaned version for CPE (no -r0, v prefix, etc.)
    constructed_cpe = Column(String, nullable=True)  # Full CPE string constructed by agent
    ecosystem = Column(String, nullable=True, index=True)  # Ecosystem (npm, pypi, maven, etc.)
    enrichment_status = Column(String, nullable=True, default="pending")  # pending, completed, failed
    enrichment_confidence = Column(Integer, nullable=True)  # 0-100 confidence in enrichment
    enrichment_method = Column(String, nullable=True)  # purl_only, purl_cache, llm, fallback_1, fallback_2, fallback_3
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    application = relationship("Application", back_populates="components")
    cves = relationship("CVE", secondary="component_cve", back_populates="components")
    remediations = relationship(
        "Remediation",
        back_populates="component"
    )
