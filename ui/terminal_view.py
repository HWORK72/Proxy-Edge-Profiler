from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from models.telemetry import ProxyAuditVerdict, ProxyQualityTier


class TerminalViewer:
    def __init__(self) -> None:
        self.console: Console = Console()

    def print_banner(self) -> None:
        banner_text: str = (
            "[bold cyan]PROXY-EDGE-PROFILER[/bold cyan] v1.0.0\n"
            "[dim]High-Performance Anycast CDN Route & BGP ASN Security Analyzer[/dim]"
        )
        self.console.print(Panel(banner_text, border_style="cyan", expand=False))

    def render_results_table(self, verdicts: list[ProxyAuditVerdict]) -> None:
        table: Table = Table(
            title="Proxy Audit & Edge Telemetry Summary",
            header_style="bold magenta",
            show_lines=True
        )
        table.add_column("Proxy Endpoint", style="white")
        table.add_column("PoP Location", justify="center")
        table.add_column("Total RTT", justify="right")
        table.add_column("ASN Provider", style="dim")
        table.add_column("Network Type", justify="center")
        table.add_column("Fraud Status", justify="center")
        table.add_column("Score", justify="right")
        table.add_column("Assigned Tier", justify="center")

        for item in verdicts:
            if not item.is_alive:
                table.add_row(
                    item.proxy.export_format,
                    "[red]DEAD[/red]",
                    "-",
                    "-",
                    "-",
                    "[red]UNREACHABLE[/red]",
                    "[red]0.0[/red]",
                    "[bold red]DISCARDED[/bold red]"
                )
                continue

            colo_name: str = item.edge_pop.colo_city if item.edge_pop else "Unknown"
            colo_str: str = f"[green]{colo_name}[/green]" if item.edge_pop and item.edge_pop.is_ashburn_route else f"[yellow]{colo_name}[/yellow]"

            rtt_val: float = item.latency.total_rtt_ms
            rtt_style: str = "green" if rtt_val < 100.0 else ("yellow" if rtt_val < 250.0 else "red")
            rtt_str: str = f"[{rtt_style}]{rtt_val:.1f} ms[/{rtt_style}]"

            asn_org: str = item.asn.as_organization[:22] if item.asn else "Unknown"

            is_dc: bool = "Datacenter" in item.asn.actual_type
            type_str: str = f"[bold red]{item.asn.actual_type}[/bold red]" if is_dc else f"[bold green]{item.asn.actual_type}[/bold green]"

            if item.asn.is_spoofed_residential:
                fraud_str: str = "[bold red]FAKE RESIDENTIAL 🚨[/bold red]"
            else:
                fraud_str: str = "[bold green]VERIFIED ISP ✔[/bold green]"

            score_style: str = "bold green" if item.quality_score >= 85.0 else ("yellow" if item.quality_score >= 50.0 else "red")
            score_str: str = f"[{score_style}]{item.quality_score:.1f}[/{score_style}]"

            tier_style: str = "bold green" if item.tier == ProxyQualityTier.GOD_TIER_ASHBURN else (
                "cyan" if item.tier == ProxyQualityTier.CLEAN_RESIDENTIAL else (
                    "yellow" if item.tier == ProxyQualityTier.STANDARD_DATACENTER else "bold red"
                )
            )
            tier_str: str = f"[{tier_style}]{item.tier.value}[/{tier_style}]"

            table.add_row(
                item.proxy.export_format,
                colo_str,
                rtt_str,
                asn_org,
                type_str,
                fraud_str,
                score_str,
                tier_str
            )

        self.console.print(table)

    def render_forensic_dossier(self, verdicts: list[ProxyAuditVerdict]) -> None:
        spoofed_items = [v for v in verdicts if v.asn.is_spoofed_residential or ("Datacenter" in v.asn.actual_type and v.is_alive)]
        if not spoofed_items:
            return

        for item in spoofed_items:
            city = item.edge_pop.colo_city if item.edge_pop else "Unknown"
            colo = item.edge_pop.colo_code if item.edge_pop else "UNK"
            dossier_text: str = (
                f"[bold yellow]Endpoint:[/bold yellow] {item.proxy.export_format}\n"
                f"[bold yellow]Claimed Type:[/bold yellow] Residential (Home ISP)\n"
                f"[bold red]BGP ASN Org:[/bold red] {item.asn.as_organization} (Commercial Hosting / Datacenter)\n"
                f"[bold red]CDN Edge PoP:[/bold red] {colo} ({city})\n\n"
                f"[bold red]FORENSIC TECHNICAL VERDICT:[/bold red]\n"
                f"🚨 [bold white on red] SELLER FRAUD DETECTED [/bold white on red]\n"
                f"Physical traffic terminates at a commercial server rack in {city}, NOT a residential internet connection.\n"
                f"Anti-bot systems (Cloudflare, Akamai, Datadome) will identify this as a datacenter IP and issue instant blocks."
            )
            self.console.print(Panel(dossier_text, title="Technical Forensic Audit Dossier", border_style="red"))

    def render_metrics_summary(self, verdicts: list[ProxyAuditVerdict], elapsed_seconds: float) -> None:
        total: int = len(verdicts)
        alive: int = sum(1 for v in verdicts if v.is_alive)
        ashburn_count: int = sum(1 for v in verdicts if v.edge_pop and v.edge_pop.is_ashburn_route)
        god_tier_count: int = sum(1 for v in verdicts if v.tier == ProxyQualityTier.GOD_TIER_ASHBURN)
        throughput: float = round(total / elapsed_seconds, 1) if elapsed_seconds > 0 else 0.0

        summary_text: str = (
            f"[bold]Total Scanned:[/bold] {total}  |  "
            f"[bold green]Alive:[/bold green] {alive}  |  "
            f"[bold cyan]IAD/Ashburn Routes:[/bold cyan] {ashburn_count}  |  "
            f"[bold magenta]God-Tier Count:[/bold magenta] {god_tier_count}\n"
            f"[bold yellow]Audit Duration:[/bold yellow] {elapsed_seconds:.2f}s  |  "
            f"[bold green]Throughput:[/bold green] {throughput} req/sec"
        )
        self.console.print(Panel(summary_text, title="Audit Execution Metrics", border_style="green"))