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
        for item in verdicts:
            if not item.is_alive:
                continue

            city = item.edge_pop.colo_city if item.edge_pop else "Unknown Location"
            colo = item.edge_pop.colo_code if item.edge_pop else "UNK"
            org = item.asn.as_organization

            if item.asn.is_spoofed_residential or "Datacenter" in item.asn.actual_type:
                title = "Technical Forensic Audit Dossier (Anomaly Detected)"
                border = "red"
                verdict_badge = "🚨 [bold white on red] SELLER FRAUD DETECTED [/bold white on red]"
                verdict_desc = (
                    f"Physical traffic terminates at a commercial server rack in {city}, NOT a residential internet connection.\n"
                    f"Autonomous System '{org}' is registered to a datacenter/hosting provider.\n"
                    f"Anti-bot engines (Cloudflare, Akamai, Datadome) will identify this as an automated IP and issue instant blocks."
                )
            elif item.tier == ProxyQualityTier.GOD_TIER_ASHBURN:
                title = "Elite Asset Verification Certificate"
                border = "bright_green"
                verdict_badge = "🏆 [bold white on green] GOD-TIER ASHBURN ROUTE VERIFIED [/bold white on green]"
                verdict_desc = (
                    f"Direct physical landing detected at Ashburn, VA (IAD PoP).\n"
                    f"Provides the lowest theoretical round-trip latency to Shopify and Nike AWS us-east-1 clusters.\n"
                    f"BGP Autonomous System '{org}' is verified as clean with zero datacenter leaks."
                )
            else:
                title = "ISP Integrity Certificate"
                border = "green"
                verdict_badge = "✔ [bold white on green] GENUINE RESIDENTIAL BROADBAND [/bold white on green]"
                verdict_desc = (
                    f"Physical traffic originates from a verified residential ISP network in {city}.\n"
                    f"Autonomous System '{org}' belongs to a legitimate domestic broadband provider.\n"
                    f"Low probability of automated bot classification."
                )

            if item.subnet and item.subnet.cascade_ban_risk_warning:
                verdict_desc += (
                    f"\n\n[bold yellow]⚠️ WARNING: Subnet concentration ({item.subnet.pool_concentration_percentage}%) "
                    f"exceeds safety threshold on {item.subnet.cidr_24}. Elevated cascade ban risk.[/bold yellow]"
                )

            dossier_text = (
                f"[bold yellow]Endpoint:[/bold yellow] {item.proxy.export_format}\n"
                f"[bold yellow]Claimed Type:[/bold yellow] {item.asn.claimed_type}\n"
                f"[bold cyan]BGP ASN Org:[/bold cyan] {org}\n"
                f"[bold cyan]CDN Edge PoP:[/bold cyan] {colo} ({city})\n\n"
                f"[bold]FORENSIC TECHNICAL VERDICT:[/bold]\n"
                f"{verdict_badge}\n"
                f"{verdict_desc}"
            )
            self.console.print(Panel(dossier_text, title=title, border_style=border))

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