from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime


class SummaryCard(BaseModel):
    label: str
    value: int
    trend: Optional[str] = None  # "up", "down", "stable"


class DashboardSummary(BaseModel):
    total_applications: int
    total_vendors: int
    total_components: int
    total_cves: int = 0
    critical_applications: int
    high_risk_applications: int = 0
    internet_facing_apps: int
    production_apps: int
    open_remediations: int = 0
    overdue_remediations: int = 0
    average_risk_score: float = 0.0


class CriticalityDistribution(BaseModel):
    criticality: str
    count: int
    percentage: float


class EnvironmentDistribution(BaseModel):
    environment: str
    count: int
    percentage: float


class ComponentTypeDistribution(BaseModel):
    component_type: str
    count: int
    percentage: float


class TopVendor(BaseModel):
    vendor_id: int
    vendor_name: str
    application_count: int
    component_count: int


class TopApplication(BaseModel):
    application_id: int
    application_name: str
    component_count: int
    criticality: str
    internet_facing: bool


class RecentActivity(BaseModel):
    type: str  # "application", "vendor", "component"
    name: str
    created_at: datetime


class DashboardData(BaseModel):
    summary: DashboardSummary
    criticality_distribution: List[CriticalityDistribution]
    environment_distribution: List[EnvironmentDistribution]
    component_type_distribution: List[ComponentTypeDistribution]
    top_vendors: List[TopVendor]
    top_applications: List[TopApplication]
    recent_activity: List[RecentActivity]


class VendorDashboard(BaseModel):
    vendor_id: int
    vendor_name: str
    total_applications: int
    total_components: int
    critical_applications: int
    internet_facing_apps: int
    applications: List[TopApplication]


class ApplicationDashboard(BaseModel):
    application_id: int
    application_name: str
    component_count: int
    criticality: str
    internet_facing: bool
    environment: str
    data_classification: str
    vendor_name: Optional[str] = None
    component_type_distribution: List[ComponentTypeDistribution]


# New enhanced dashboard schemas
class SummaryStats(BaseModel):
    total_applications: int = 0
    total_vendors: int = 0
    total_components: int = 0
    total_cves: int = 0
    critical_applications: int = 0
    high_risk_applications: int = 0
    open_remediations: int = 0
    overdue_remediations: int = 0
    average_risk_score: float = 0.0


class DistributionItem(BaseModel):
    label: str
    value: int
    percentage: float = 0.0


class RiskDistribution(BaseModel):
    low: int = 0
    moderate: int = 0
    high: int = 0
    very_high: int = 0
    critical: int = 0


class TopVulnerableApp(BaseModel):
    application_id: int
    application_name: str
    risk_score: float
    risk_rating: str
    cve_count: int
    critical_cve_count: int


class TopVulnerableComponent(BaseModel):
    component_name: str
    version: str
    cve_count: int
    max_cvss: float
    affected_applications: int


class VendorRiskSummary(BaseModel):
    vendor_id: int
    vendor_name: str
    application_count: int
    average_risk_score: float
    highest_risk_rating: str
    total_cves: int


class RecentCVE(BaseModel):
    cve_id: str
    severity: str
    cvss_score: float
    component_name: str
    application_name: str
    published_date: Optional[datetime] = None


class ActivityItem(BaseModel):
    timestamp: datetime
    action: str
    description: str
    resource_type: str
    user: Optional[str] = None


class RiskTrendPoint(BaseModel):
    date: str
    average_score: float
    critical_count: int
    high_count: int


class RemediationStats(BaseModel):
    total: int = 0
    open: int = 0
    in_progress: int = 0
    resolved: int = 0
    mitigated: int = 0
    risk_accepted: int = 0
    false_positive: int = 0
    overdue: int = 0
    average_resolution_days: float = 0.0


class EnhancedDashboardResponse(BaseModel):
    summary: SummaryStats
    risk_distribution: RiskDistribution
    criticality_distribution: List[DistributionItem] = []
    environment_distribution: List[DistributionItem] = []
    component_type_distribution: List[DistributionItem] = []
    top_vulnerable_apps: List[TopVulnerableApp] = []
    top_vulnerable_components: List[TopVulnerableComponent] = []
    vendor_risk_summary: List[VendorRiskSummary] = []
    recent_cves: List[RecentCVE] = []
    recent_activity: List[ActivityItem] = []
    risk_trend: List[RiskTrendPoint] = []
    remediation_stats: RemediationStats = RemediationStats()

