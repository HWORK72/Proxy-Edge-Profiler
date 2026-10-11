import asyncio
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
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
from scoring.quality_engine import QualityScoringEngine


class HighLoadStressRunner:
    POP_SAMPLES: list[tuple[str, str, bool]] = [
        ("IAD", "Ashburn, VA, US", True),
        ("ORD", "Chicago, IL, US", False),
        ("LHR", "London, UK", False),
        ("FRA", "Frankfurt, DE", False),
        ("EWR", "Newark, NJ, US", False)
    ]

    ASN_SAMPLES: list[tuple[int, str, str, bool]] = [
        (7018, "AT&T Services", "Residential", False),
        (7922, "Comcast Cable", "Residential", False),
        (24940, "Hetzner Online GmbH", "Datacenter", True),
        (14061, "DigitalOcean LLC", "Datacenter", True)
    ]

    def __init__(self, target_volume: int = 2000, concurrency: int = 500) -> None:
        self.target_volume: int = target_volume
        self.concurrency: int = concurrency
        self.semaphore: asyncio.Semaphore = asyncio.Semaphore(concurrency)
        self.console: Console = Console()
        self.loop_lag_records: list[float] = []

    def generate_synthetic_pool(self) -> list[ProxyRecord]:
        pool: list[ProxyRecord] = []
        for index in range(self.target_volume):
            oct1: int = 185 if index % 3 == 0 else (192 if index % 3 == 1 else 104)
            oct2: int = (index // 256) % 255
            oct3: int = (index // 32) % 255
            oct4: int = (index % 254) + 1
            ip: str = f"{oct1}.{oct2}.{oct3}.{oct4}"
            pool.append(
                ProxyRecord(
                    host=ip,
                    port=8000 + (index % 1000),
                    username=f"user_{index}",
                    password=f"pass_{index}",
                    protocol=ProxyProtocol.HTTP
                )
            )
        return pool

    async def _monitor_loop_lag(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            expected_wake: float = time.perf_counter() + 0.01
            await asyncio.sleep(0.01)
            lag_ms: float = max(0.0, (time.perf_counter() - expected_wake) * 1000.0)
            self.loop_lag_records.append(lag_ms)

    async def _simulate_profiling_task(self, proxy: ProxyRecord) -> ProxyAuditVerdict:
        async with self.semaphore:
            jitter: float = random.uniform(0.001, 0.004)
            await asyncio.sleep(jitter)

            pop_data = random.choice(self.POP_SAMPLES)
            asn_data = random.choice(self.ASN_SAMPLES)
            total_rtt: float = random.uniform(15.0, 180.0)

            latency = LatencyBreakdown(
                dns_resolution_ms=round(total_rtt * 0.1, 2),
                tcp_handshake_ms=round(total_rtt * 0.3, 2),
                tls_handshake_ms=round(total_rtt * 0.3, 2),
                ttfb_ms=round(total_rtt * 0.8, 2),
                total_rtt_ms=round(total_rtt, 2)
            )

            pop = EdgePoPTelemetry(
                colo_code=pop_data[0],
                colo_city=pop_data[1],
                is_ashburn_route=pop_data[2],
                egress_ip=proxy.host
            )

            asn = ASNVerificationResult(
                asn_number=asn_data[0],
                as_organization=asn_data[1],
                actual_type=asn_data[2],
                is_spoofed_residential=asn_data[3],
                fraud_penalty_score=45.0 if asn_data[3] else 0.0
            )

            subnet = SubnetRiskProfile(
                cidr_24=f"{proxy.host.rsplit('.', 1)[0]}.0/24",
                cidr_16=f"{proxy.host.split('.')[0]}.{proxy.host.split('.')[1]}.0.0/16",
                pool_concentration_percentage=random.uniform(0.5, 4.0),
                cascade_ban_risk_warning=False
            )

            score, tier = QualityScoringEngine.evaluate(
                is_alive=True,
                latency=latency,
                edge_pop=pop,
                asn=asn,
                subnet=subnet
            )

            return ProxyAuditVerdict(
                proxy=proxy,
                is_alive=True,
                latency=latency,
                edge_pop=pop,
                asn=asn,
                subnet=subnet,
                quality_score=score,
                tier=tier
            )

    async def execute_stress_run(self) -> None:
        self.console.print(
            Panel(
                f"[bold cyan]STRESS BENCHMARK DISPATCHER[/bold cyan]\n"
                f"Generating and auditing [bold yellow]{self.target_volume}[/bold yellow] proxies "
                f"under [bold magenta]{self.concurrency}[/bold magenta] concurrency workers...",
                border_style="cyan"
            )
        )

        pool: list[ProxyRecord] = self.generate_synthetic_pool()
        stop_event: asyncio.Event = asyncio.Event()
        lag_task: asyncio.Task = asyncio.create_task(self._monitor_loop_lag(stop_event))

        start_time: float = time.perf_counter()
        tasks = [self._simulate_profiling_task(proxy) for proxy in pool]
        verdicts: list[ProxyAuditVerdict] = await asyncio.gather(*tasks)
        total_time: float = time.perf_counter() - start_time

        stop_event.set()
        await lag_task

        throughput: float = round(len(verdicts) / total_time, 1)
        avg_lag: float = round(sum(self.loop_lag_records) / max(1, len(self.loop_lag_records)), 3)
        max_lag: float = round(max(self.loop_lag_records, default=0.0), 3)

        god_tier_count: int = sum(1 for v in verdicts if v.tier == ProxyQualityTier.GOD_TIER_ASHBURN)
        clean_count: int = sum(1 for v in verdicts if v.tier == ProxyQualityTier.CLEAN_RESIDENTIAL)
        spoofed_count: int = sum(1 for v in verdicts if v.asn.is_spoofed_residential)

        table: Table = Table(title="High-Load Benchmark Telemetry Results", header_style="bold green")
        table.add_column("Metric Description", style="cyan")
        table.add_column("Measurement Value", justify="right", style="bold yellow")

        table.add_row("Total Processed Proxies", f"{len(verdicts):,}")
        table.add_row("Concurrency Level", f"{self.concurrency} async workers")
        table.add_row("Execution Duration", f"{total_time:.3f} seconds")
        table.add_row("System Throughput", f"[bold green]{throughput:,} proxies/sec[/bold green]")
        table.add_row("Average Event Loop Lag", f"{avg_lag} ms")
        table.add_row("Max Event Loop Lag", f"{max_lag} ms")
        table.add_row("Identified God-Tier Ashburn", f"{god_tier_count}")
        table.add_row("Identified Clean Residential", f"{clean_count}")
        table.add_row("Intercepted Spoofed ASNs", f"[bold red]{spoofed_count}[/bold red]")

        self.console.print(table)


if __name__ == "__main__":
    runner: HighLoadStressRunner = HighLoadStressRunner(target_volume=2500, concurrency=500)
    asyncio.run(runner.execute_stress_run())