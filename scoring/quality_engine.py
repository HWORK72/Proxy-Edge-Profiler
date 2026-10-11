from models.telemetry import (
    ProxyAuditVerdict,
    ProxyQualityTier,
    LatencyBreakdown,
    EdgePoPTelemetry,
    ASNVerificationResult,
    SubnetRiskProfile
)


class QualityScoringEngine:
    BASE_SCORE: float = 100.0
    ASHBURN_BONUS: float = 15.0
    IP_LEAK_PENALTY: float = 20.0
    HIGH_LATENCY_THRESHOLD_MS: float = 200.0
    EXTREME_LATENCY_THRESHOLD_MS: float = 400.0

    @classmethod
    def evaluate(
        cls,
        is_alive: bool,
        latency: LatencyBreakdown,
        edge_pop: EdgePoPTelemetry | None,
        asn: ASNVerificationResult,
        subnet: SubnetRiskProfile | None
    ) -> tuple[float, ProxyQualityTier]:
        if not is_alive or edge_pop is None:
            return 0.0, ProxyQualityTier.DISCARDED

        score: float = cls.BASE_SCORE

        if edge_pop.is_ashburn_route:
            score += cls.ASHBURN_BONUS

        if edge_pop.is_ip_leaked:
            score -= cls.IP_LEAK_PENALTY

        if latency.total_rtt_ms > cls.EXTREME_LATENCY_THRESHOLD_MS:
            score -= 35.0
        elif latency.total_rtt_ms > cls.HIGH_LATENCY_THRESHOLD_MS:
            score -= 15.0
        elif latency.total_rtt_ms < 60.0:
            score += 5.0

        if latency.tls_handshake_ms > 150.0:
            score -= 10.0

        if asn.is_spoofed_residential:
            score -= asn.fraud_penalty_score

        if subnet and subnet.cascade_ban_risk_warning:
            penalty: float = min(30.0, subnet.pool_concentration_percentage * 0.5)
            score -= penalty

        final_score: float = max(0.0, min(100.0, round(score, 1)))

        tier: ProxyQualityTier = ProxyQualityTier.DISCARDED
        if (
            final_score >= 88.0
            and edge_pop.is_ashburn_route
            and not asn.is_spoofed_residential
            and not (subnet and subnet.cascade_ban_risk_warning)
        ):
            tier = ProxyQualityTier.GOD_TIER_ASHBURN
        elif final_score >= 70.0 and not asn.is_spoofed_residential:
            tier = ProxyQualityTier.CLEAN_RESIDENTIAL
        elif final_score >= 45.0:
            tier = ProxyQualityTier.STANDARD_DATACENTER
        else:
            tier = ProxyQualityTier.DISCARDED

        return final_score, tier