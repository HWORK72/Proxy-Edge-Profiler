import ipaddress
from collections import Counter
from models.proxy import ProxyRecord
from models.telemetry import SubnetRiskProfile
from core.logger import app_logger


class SubnetAnalyzer:
    CASCADE_BAN_DENSITY_THRESHOLD_PERCENT: float = 5.0

    @classmethod
    def analyze_pool_subnets(cls, proxy_list: list[ProxyRecord]) -> dict[str, SubnetRiskProfile]:
        total_proxies: int = len(proxy_list)
        if total_proxies == 0:
            return {}

        slash_24_counter: Counter[str] = Counter()
        slash_16_counter: Counter[str] = Counter()
        ip_mapping: dict[str, tuple[str, str]] = {}

        for proxy in proxy_list:
            try:
                ip_obj = ipaddress.ip_address(proxy.host)
                if ip_obj.version == 4:
                    network_24: str = str(ipaddress.ip_network(f"{proxy.host}/24", strict=False))
                    network_16: str = str(ipaddress.ip_network(f"{proxy.host}/16", strict=False))
                else:
                    network_24 = str(ipaddress.ip_network(f"{proxy.host}/64", strict=False))
                    network_16 = str(ipaddress.ip_network(f"{proxy.host}/48", strict=False))

                slash_24_counter[network_24] += 1
                slash_16_counter[network_16] += 1
                ip_mapping[proxy.host] = (network_24, network_16)

            except ValueError:
                fallback_net: str = f"{proxy.host}/unknown"
                ip_mapping[proxy.host] = (fallback_net, fallback_net)
                slash_24_counter[fallback_net] += 1
                slash_16_counter[fallback_net] += 1

        profiles_by_ip: dict[str, SubnetRiskProfile] = {}

        for host, (net_24, net_16) in ip_mapping.items():
            count_24: int = slash_24_counter[net_24]
            concentration: float = round((count_24 / total_proxies) * 100.0, 2)
            warning: bool = concentration >= cls.CASCADE_BAN_DENSITY_THRESHOLD_PERCENT

            profiles_by_ip[host] = SubnetRiskProfile(
                cidr_24=net_24,
                cidr_16=net_16,
                pool_concentration_percentage=concentration,
                cascade_ban_risk_warning=warning
            )

        return profiles_by_ip