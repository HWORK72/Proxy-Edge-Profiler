import asyncio
from core.logger import app_logger
from models.proxy import ProxyRecord
from profiler.subnet_analyzer import SubnetAnalyzer


def test_subnet_analyzer() -> None:
    raw_cluster_list: list[str] = [
        "142.250.190.46:8080:u1:p1",
        "142.250.190.47:8080:u2:p2",
        "142.250.190.48:8080:u3:p3",
        "142.250.190.49:8080:u4:p4",
        "104.16.123.96:8080:u5:p5",
        "104.16.123.97:8080:u6:p6",
        "8.8.8.8:8080:u7:p7"
    ]
    records = [ProxyRecord.parse_raw_line(line) for line in raw_cluster_list]
    profiles = SubnetAnalyzer.analyze_pool_subnets(records)

    for host, profile in profiles.items():
        app_logger.info(
            f"Host: [bold yellow]{host}[/bold yellow] | "
            f"CIDR /24: [cyan]{profile.cidr_24}[/cyan] | "
            f"Pool Density: [bold magenta]{profile.pool_concentration_percentage}%[/bold magenta] | "
            f"Cascade Warning: [bold red]{profile.cascade_ban_risk_warning}[/bold red]"
        )


if __name__ == "__main__":
    test_subnet_analyzer()