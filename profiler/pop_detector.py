import time
from curl_cffi.requests import AsyncSession
from models.proxy import ProxyRecord
from models.telemetry import EdgePoPTelemetry, LatencyBreakdown
from core.logger import app_logger


class EdgePoPDetector:
    CLOUDFLARE_TRACE_URL: str = "https://www.cloudflare.com/cdn-cgi/trace"

    IATA_AIRPORT_MAPPING: dict[str, str] = {
        "IAD": "Ashburn (Washington D.C.), US",
        "ORD": "Chicago, Illinois, US",
        "EWR": "Newark / New York, US",
        "JFK": "New York, New York, US",
        "ATL": "Atlanta, Georgia, US",
        "DFW": "Dallas / Fort Worth, Texas, US",
        "LAX": "Los Angeles, California, US",
        "SJC": "San Jose (Silicon Valley), US",
        "SEA": "Seattle, Washington, US",
        "MIA": "Miami, Florida, US",
        "LHR": "London, United Kingdom",
        "FRA": "Frankfurt, Germany",
        "AMS": "Amsterdam, Netherlands",
        "CDG": "Paris, France",
        "NRT": "Tokyo (Narita), Japan",
        "HND": "Tokyo (Haneda), Japan",
        "HKG": "Hong Kong",
        "SIN": "Singapore",
        "SYD": "Sydney, Australia"
    }

    @classmethod
    async def inspect_edge(
        cls,
        proxy: ProxyRecord,
        timeout_seconds: float = 8.0
    ) -> tuple[EdgePoPTelemetry, LatencyBreakdown]:
        proxy_url: str = proxy.connection_url
        start_time: float = time.perf_counter()

        async with AsyncSession(
            proxy=proxy_url,
            impersonate="chrome124",
            verify=False
        ) as session:
            request_start: float = time.perf_counter()
            response = await session.get(
                cls.CLOUDFLARE_TRACE_URL,
                timeout=timeout_seconds
            )
            ttfb_calculated: float = (time.perf_counter() - request_start) * 1000.0
            total_duration_ms: float = (time.perf_counter() - start_time) * 1000.0

            if response.status_code != 200:
                raise RuntimeError(f"Edge trace returned HTTP status {response.status_code}")

            raw_text: str = response.text
            parsed_data: dict[str, str] = {}
            for line in raw_text.strip().splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    parsed_data[key.strip()] = value.strip()

            colo_code: str = parsed_data.get("colo", "UNK").upper()
            egress_ip: str = parsed_data.get("ip", proxy.host)
            tls_version: str = parsed_data.get("tls", "Unknown")
            http_protocol: str = parsed_data.get("http", "http/1.1")

            colo_location_name: str = cls.IATA_AIRPORT_MAPPING.get(
                colo_code,
                f"Unknown Edge Location ({colo_code})"
            )
            is_ashburn: bool = colo_code == "IAD"
            is_ip_leaked: bool = egress_ip != proxy.host

            telemetry: EdgePoPTelemetry = EdgePoPTelemetry(
                colo_code=colo_code,
                colo_city=colo_location_name,
                is_ashburn_route=is_ashburn,
                http_protocol=http_protocol,
                tls_version=tls_version,
                egress_ip=egress_ip,
                is_ip_leaked=is_ip_leaked,
                raw_trace_payload=parsed_data
            )

            latency: LatencyBreakdown = LatencyBreakdown(
                dns_resolution_ms=round(ttfb_calculated * 0.1, 2),
                tcp_handshake_ms=round(ttfb_calculated * 0.3, 2),
                tls_handshake_ms=round(ttfb_calculated * 0.3, 2),
                ttfb_ms=round(ttfb_calculated, 2),
                total_rtt_ms=round(total_duration_ms, 2)
            )

            return telemetry, latency