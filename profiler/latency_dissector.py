import asyncio
import socket
import ssl
import time
from models.proxy import ProxyRecord
from models.telemetry import LatencyBreakdown
from core.logger import app_logger


class LatencyDissector:
    TARGET_HOST: str = "cloudflare.com"
    TARGET_PORT: int = 443

    @classmethod
    async def measure_proxy_path(
        cls,
        proxy: ProxyRecord,
        timeout_seconds: float = 6.0
    ) -> LatencyBreakdown:
        start_global: float = time.perf_counter()
        dns_resolution_ms: float = 0.0
        tcp_handshake_ms: float = 0.0
        tls_handshake_ms: float = 0.0

        loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()

        try:
            dns_start: float = time.perf_counter()
            resolved_host_info = await asyncio.wait_for(
                loop.getaddrinfo(
                    proxy.host,
                    proxy.port,
                    family=socket.AF_INET,
                    type=socket.SOCK_STREAM
                ),
                timeout=timeout_seconds
            )
            dns_resolution_ms = (time.perf_counter() - dns_start) * 1000.0
            target_sockaddr = resolved_host_info[0][4]

            tcp_start: float = time.perf_counter()
            connection_task = asyncio.open_connection(
                host=target_sockaddr[0],
                port=target_sockaddr[1]
            )
            reader, writer = await asyncio.wait_for(connection_task, timeout=timeout_seconds)
            tcp_handshake_ms = (time.perf_counter() - tcp_start) * 1000.0

            writer.close()
            await writer.wait_closed()

        except Exception as error:
            app_logger.debug(f"Direct socket breakdown skipped for {proxy.host}:{proxy.port} -> {error}")

        total_rtt_ms: float = (time.perf_counter() - start_global) * 1000.0

        return LatencyBreakdown(
            dns_resolution_ms=round(dns_resolution_ms, 2),
            tcp_handshake_ms=round(tcp_handshake_ms, 2),
            tls_handshake_ms=round(tls_handshake_ms, 2),
            ttfb_ms=round(tcp_handshake_ms, 2),
            total_rtt_ms=round(total_rtt_ms, 2)
        )