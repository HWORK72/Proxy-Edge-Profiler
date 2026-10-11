import sys
from core.config import get_settings
from core.logger import app_logger
from models.proxy import ProxyRecord, ProxyProtocol
from models.telemetry import (
    ProxyAuditVerdict,
    LatencyBreakdown,
    EdgePoPTelemetry,
    ASNVerificationResult,
    SubnetRiskProfile,
    ProxyQualityTier
)


def verify_foundation() -> None:
    try:
        settings = get_settings()
        app_logger.info(f"Loaded configuration for environment: [bold green]{settings.APP_ENV}[/bold green]")
        app_logger.info(f"Target workers concurrency limit: [bold cyan]{settings.MAX_CONCURRENT_WORKERS}[/bold cyan]")

        raw_test_line: str = "192.168.1.100:8080:testuser:supersecret"
        proxy_record: ProxyRecord = ProxyRecord.parse_raw_line(raw_test_line, ProxyProtocol.HTTP)
        app_logger.info(f"Parsed raw proxy correctly: [bold yellow]{proxy_record.export_format}[/bold yellow]")
        app_logger.info(f"Generated connection URL: [dim]{proxy_record.connection_url}[/dim]")

        mock_verdict: ProxyAuditVerdict = ProxyAuditVerdict(
            proxy=proxy_record,
            is_alive=True,
            latency=LatencyBreakdown(
                dns_resolution_ms=1.2,
                tcp_handshake_ms=4.8,
                tls_handshake_ms=8.5,
                ttfb_ms=12.1,
                total_rtt_ms=18.4
            ),
            edge_pop=EdgePoPTelemetry(
                colo_code="IAD",
                colo_city="Ashburn, VA",
                is_ashburn_route=True,
                http_protocol="http/2",
                tls_version="TLSv1.3",
                egress_ip="192.168.1.100",
                is_ip_leaked=False
            ),
            asn=ASNVerificationResult(
                asn_number=7018,
                as_organization="AT&T Services, Inc.",
                claimed_type="Residential",
                actual_type="Residential",
                is_spoofed_residential=False,
                fraud_penalty_score=0.0
            ),
            subnet=SubnetRiskProfile(
                cidr_24="192.168.1.0/24",
                cidr_16="192.168.0.0/16",
                pool_concentration_percentage=1.2,
                cascade_ban_risk_warning=False
            ),
            quality_score=98.5,
            tier=ProxyQualityTier.GOD_TIER_ASHBURN
        )

        app_logger.info(
            f"Verdict verified successfully! Assigned tier: [bold green]{mock_verdict.tier.value}[/bold green] "
            f"with score [bold cyan]{mock_verdict.quality_score}/100[/bold cyan]"
        )

    except Exception as error:
        app_logger.exception(f"Verification pipeline failed: {error}")
        sys.exit(1)


if __name__ == "__main__":
    verify_foundation()