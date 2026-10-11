import asyncio
from core.config import get_settings
from core.logger import app_logger
from models.proxy import ProxyRecord
from models.telemetry import (
    ProxyAuditVerdict,
    ProxyQualityTier,
    LatencyBreakdown,
    EdgePoPTelemetry,
    ASNVerificationResult,
    SubnetRiskProfile
)
from profiler.pop_detector import EdgePoPDetector
from profiler.asn_validator import ASNValidator
from profiler.subnet_analyzer import SubnetAnalyzer


class ProfilerEngine:
    def __init__(self, concurrency_limit: int | None = None) -> None:
        settings = get_settings()
        self._concurrency_limit: int = concurrency_limit or settings.MAX_CONCURRENT_WORKERS
        self._timeout_seconds: float = settings.REQUEST_TIMEOUT_SECONDS
        self._semaphore: asyncio.Semaphore = asyncio.Semaphore(self._concurrency_limit)

    async def profile_single_proxy(
        self,
        proxy: ProxyRecord,
        subnet_profile: SubnetRiskProfile | None = None,
        claimed_type: str = "Residential"
    ) -> ProxyAuditVerdict:
        async with self._semaphore:
            try:
                pop_telemetry, latency = await EdgePoPDetector.inspect_edge(
                    proxy=proxy,
                    timeout_seconds=self._timeout_seconds
                )

                asn_result: ASNVerificationResult = await ASNValidator.verify_ip_asn(
                    ip_address=pop_telemetry.egress_ip,
                    claimed_type=claimed_type,
                    timeout_seconds=self._timeout_seconds
                )

                score: float = 100.0

                if pop_telemetry.is_ashburn_route:
                    score += 15.0

                if latency.total_rtt_ms > 250.0:
                    score -= 30.0
                elif latency.total_rtt_ms > 100.0:
                    score -= 15.0

                if asn_result.is_spoofed_residential:
                    score -= asn_result.fraud_penalty_score

                if subnet_profile and subnet_profile.cascade_ban_risk_warning:
                    score -= 20.0

                score = max(0.0, min(100.0, round(score, 1)))

                assigned_tier: ProxyQualityTier = ProxyQualityTier.DISCARDED
                if score >= 90.0 and pop_telemetry.is_ashburn_route:
                    assigned_tier = ProxyQualityTier.GOD_TIER_ASHBURN
                elif score >= 75.0 and not asn_result.is_spoofed_residential:
                    assigned_tier = ProxyQualityTier.CLEAN_RESIDENTIAL
                elif score >= 50.0:
                    assigned_tier = ProxyQualityTier.STANDARD_DATACENTER

                return ProxyAuditVerdict(
                    proxy=proxy,
                    is_alive=True,
                    error_reason=None,
                    latency=latency,
                    edge_pop=pop_telemetry,
                    asn=asn_result,
                    subnet=subnet_profile,
                    quality_score=score,
                    tier=assigned_tier
                )

            except Exception as error:
                app_logger.debug(f"Audit failed for proxy {proxy.export_format}: {error}")
                return ProxyAuditVerdict(
                    proxy=proxy,
                    is_alive=False,
                    error_reason=str(error),
                    latency=LatencyBreakdown(),
                    edge_pop=None,
                    asn=ASNVerificationResult(claimed_type=claimed_type),
                    subnet=subnet_profile,
                    quality_score=0.0,
                    tier=ProxyQualityTier.DISCARDED
                )

    async def audit_pool(
        self,
        raw_proxies: list[str],
        claimed_type: str = "Residential"
    ) -> list[ProxyAuditVerdict]:
        parsed_records: list[ProxyRecord] = []
        for line in raw_proxies:
            cleaned: str = line.strip()
            if not cleaned:
                continue
            try:
                parsed_records.append(ProxyRecord.parse_raw_line(cleaned))
            except Exception as parse_error:
                app_logger.warning(f"Skipping malformed proxy line '{cleaned}': {parse_error}")

        if not parsed_records:
            return []

        subnet_map: dict[str, SubnetRiskProfile] = SubnetAnalyzer.analyze_pool_subnets(parsed_records)

        tasks = [
            self.profile_single_proxy(
                proxy=record,
                subnet_profile=subnet_map.get(record.host),
                claimed_type=claimed_type
            )
            for record in parsed_records
        ]

        app_logger.info(f"Dispatching audit pipeline for [bold cyan]{len(tasks)}[/bold cyan] proxies...")
        verdicts: list[ProxyAuditVerdict] = await asyncio.gather(*tasks)
        return verdicts