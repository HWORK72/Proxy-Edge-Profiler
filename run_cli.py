import asyncio
import time
from pathlib import Path
from models.proxy import ProxyRecord
from models.telemetry import ProxyAuditVerdict
from profiler.engine import ProfilerEngine
from scoring.quality_engine import QualityScoringEngine
from scoring.exporter import ProxyPoolExporter
from ui.terminal_view import TerminalViewer
from core.logger import app_logger


DEMO_PROXIES: list[str] = [
    "1.1.1.1:8080:demo_user:secret_pass",
    "1.0.0.1:8080:demo_user:secret_pass",
    "8.8.8.8:8080:demo_user:secret_pass",
    "8.8.4.4:8080:demo_user:secret_pass",
    "104.16.123.96:8080:demo_user:secret_pass",
    "104.16.123.97:8080:demo_user:secret_pass",
    "142.250.190.46:8080:demo_user:secret_pass"
]


async def execute_cli_audit() -> None:
    viewer: TerminalViewer = TerminalViewer()
    viewer.print_banner()

    input_file: Path = Path("proxies.txt")
    raw_proxies: list[str] = []

    if input_file.exists():
        app_logger.info(f"Reading proxy list from [bold green]{input_file.name}[/bold green]...")
        raw_proxies = [line.strip() for line in input_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    else:
        app_logger.warning("File 'proxies.txt' not found. Executing audit with built-in demonstration pool.")
        raw_proxies = DEMO_PROXIES

    app_logger.info(f"Loaded [bold cyan]{len(raw_proxies)}[/bold cyan] proxies for edge profiling.")

    engine: ProfilerEngine = ProfilerEngine()
    start_time: float = time.perf_counter()

    verdicts: list[ProxyAuditVerdict] = await engine.audit_pool(
        raw_proxies=raw_proxies,
        claimed_type="Residential"
    )

    for item in verdicts:
        score, tier = QualityScoringEngine.evaluate(
            is_alive=item.is_alive,
            latency=item.latency,
            edge_pop=item.edge_pop,
            asn=item.asn,
            subnet=item.subnet
        )
        item.quality_score = score
        item.tier = tier

    elapsed_duration: float = time.perf_counter() - start_time

    viewer.render_results_table(verdicts)
    viewer.render_metrics_summary(verdicts, elapsed_duration)

    ProxyPoolExporter.export_all(verdicts)


if __name__ == "__main__":
    asyncio.run(execute_cli_audit())