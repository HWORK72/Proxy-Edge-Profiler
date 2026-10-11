from enum import StrEnum
from pydantic import BaseModel, Field
from models.proxy import ProxyRecord


class ProxyQualityTier(StrEnum):
    GOD_TIER_ASHBURN = "God-Tier Ashburn"
    CLEAN_RESIDENTIAL = "Clean Residential"
    STANDARD_DATACENTER = "Standard Datacenter"
    DISCARDED = "Discarded"


class LatencyBreakdown(BaseModel):
    dns_resolution_ms: float = Field(default=0.0, ge=0.0)
    tcp_handshake_ms: float = Field(default=0.0, ge=0.0)
    tls_handshake_ms: float = Field(default=0.0, ge=0.0)
    ttfb_ms: float = Field(default=0.0, ge=0.0)
    total_rtt_ms: float = Field(default=0.0, ge=0.0)


class EdgePoPTelemetry(BaseModel):
    colo_code: str = Field(min_length=3, max_length=4)
    colo_city: str = Field(default="Unknown")
    is_ashburn_route: bool = Field(default=False)
    http_protocol: str = Field(default="http/1.1")
    tls_version: str = Field(default="Unknown")
    egress_ip: str = Field(min_length=7)
    is_ip_leaked: bool = Field(default=False)
    raw_trace_payload: dict[str, str] = Field(default_factory=dict)


class ASNVerificationResult(BaseModel):
    asn_number: int | None = Field(default=None)
    as_organization: str = Field(default="Unknown")
    claimed_type: str = Field(default="Residential")
    actual_type: str = Field(default="Unknown")
    is_spoofed_residential: bool = Field(default=False)
    fraud_penalty_score: float = Field(default=0.0, ge=0.0, le=100.0)


class SubnetRiskProfile(BaseModel):
    cidr_24: str = Field(min_length=7)
    cidr_16: str = Field(min_length=7)
    pool_concentration_percentage: float = Field(default=0.0, ge=0.0, le=100.0)
    cascade_ban_risk_warning: bool = Field(default=False)


class ProxyAuditVerdict(BaseModel):
    proxy: ProxyRecord
    is_alive: bool = Field(default=False)
    error_reason: str | None = Field(default=None)
    latency: LatencyBreakdown = Field(default_factory=LatencyBreakdown)
    edge_pop: EdgePoPTelemetry | None = Field(default=None)
    asn: ASNVerificationResult = Field(default_factory=ASNVerificationResult)
    subnet: SubnetRiskProfile | None = Field(default=None)
    quality_score: float = Field(default=0.0, ge=0.0, le=100.0)
    tier: ProxyQualityTier = Field(default=ProxyQualityTier.DISCARDED)