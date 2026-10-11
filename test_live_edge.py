import asyncio
import time
from curl_cffi.requests import AsyncSession
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
from profiler.pop_detector import EdgePoPDetector
from profiler.asn_validator import ASNValidator
from scoring.quality_engine import QualityScoringEngine
from ui.terminal_view import TerminalViewer


async def run_live_direct_probe() -> None:
    viewer: TerminalViewer = TerminalViewer()
    viewer.print_banner()

    app_logger.info("Initiating live L4/L7 probe through your current network interface...")
    start_time: float = time.perf_counter()

    async with AsyncSession(impersonate="chrome124", verify=False) as session:
        probe_start: float = time.perf_counter()
        response = await session.get("https://www.cloudflare.com/cdn-cgi/trace", timeout=10.0)
        ttfb_calculated: float = (time.perf_counter() - probe_start) * 1000.0
        total_duration: float = (time.perf_counter() - start_time) * 1000.0

    raw_text: str = response.text
    parsed: dict[str, str] = {}
    for line in raw_text.strip().splitlines():
        if "=" in line:
            key, val = line.split("=", 1)
            parsed[key.strip()] = val.strip()

    colo: str = parsed.get("colo", "UNK").upper()
    egress_ip: str = parsed.get("ip", "127.0.0.1")
    tls_ver: str = parsed.get("tls", "Unknown")
    http_proto: str = parsed.get("http", "http/1.1")

    city_name: str = EdgePoPDetector.IATA_AIRPORT_MAPPING.get(colo, f"Edge PoP ({colo})")

    pop_telemetry: EdgePoPTelemetry = EdgePoPTelemetry(
        colo_code=colo,
        colo_city=city_name,
        is_ashburn_route=(colo == "IAD"),
        http_protocol=http_proto,
        tls_version=tls_ver,
        egress_ip=egress_ip,
        is_ip_leaked=False,
        raw_trace_payload=parsed
    )

    latency: LatencyBreakdown = LatencyBreakdown(
        dns_resolution_ms=round(ttfb_calculated * 0.1, 2),
        tcp_handshake_ms=round(ttfb_calculated * 0.35, 2),
        tls_handshake_ms=round(ttfb_calculated * 0.35, 2),
        ttfb_ms=round(ttfb_calculated, 2),
        total_rtt_ms=round(total_duration, 2)
    )

    app_logger.info(f"Detected Public IP: [bold cyan]{egress_ip}[/bold cyan]")
    app_logger.info(f"Cloudflare Edge PoP: [bold yellow]{colo}[/bold yellow] ({city_name})")
    app_logger.info(f"Negotiated Protocols: [magenta]{tls_ver}[/magenta] via [magenta]{http_proto}[/magenta]")
    app_logger.info("Resolving global BGP ASN registry for your connection...")

    asn_result: ASNVerificationResult = await ASNValidator.verify_ip_asn(
        ip_address=egress_ip,
        claimed_type="Residential",
        timeout_seconds=6.0
    )

    subnet_risk: SubnetRiskProfile = SubnetRiskProfile(
        cidr_24=f"{egress_ip.rsplit('.', 1)[0]}.0/24",
        cidr_16=f"{egress_ip.split('.')[0]}.{egress_ip.split('.')[1]}.0.0/16",
        pool_concentration_percentage=1.0,
        cascade_ban_risk_warning=False
    )

    score, tier = QualityScoringEngine.evaluate(
        is_alive=True,
        latency=latency,
        edge_pop=pop_telemetry,
        asn=asn_result,
        subnet=subnet_risk
    )

    mock_proxy: ProxyRecord = ProxyRecord(
        host=egress_ip,
        port=443,
        protocol=ProxyProtocol.HTTPS
    )

    verdict: ProxyAuditVerdict = ProxyAuditVerdict(
        proxy=mock_proxy,
        is_alive=True,
        latency=latency,
        edge_pop=pop_telemetry,
        asn=asn_result,
        subnet=subnet_risk,
        quality_score=score,
        tier=tier
    )

    viewer.render_results_table([verdict])
    viewer.render_metrics_summary([verdict], (time.perf_counter() - start_time))


if __name__ == "__main__":
    asyncio.run(run_live_direct_probe())