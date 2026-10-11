# Proxy Edge Profiler

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg)](https://fastapi.tiangolo.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D.svg)](https://redis.io/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://www.docker.com/)

[🇷🇺 Читать на русском](README_RU.md)

An enterprise-grade, asynchronous network profiling and edge routing analyzer designed to benchmark, audit, and classify proxy pools (Residential, ISP, Datacenter, Mobile) in real time.

Built from the ground up to detect fraudulent proxy claims, dissect L3/L4/L7 Anycast CDN infrastructure, compute subnet cascade ban risks, and export clean proxy pools for sneaker bots and high-load web scrapers.

## Key Architectural Highlights

* **CDN Anycast PoP Detection:** Dissects Cloudflare trace endpoints to extract physical airport landing codes (IAD Ashburn, ORD Chicago, LHR London, FRA Frankfurt, ARN Stockholm).
* **Ashburn Direct Routing:** Identifies proxies routing directly to IAD (Ashburn, VA) for minimal latency against Shopify and Nike US-East-1 AWS clusters.
* **BGP ASN & Fraud Prevention:** Resolves global BGP autonomous systems to catch datacenter providers (Hetzner, OVH, AWS) deceptively sold as residential ISPs.
* **Subnet /24 Risk Clustering:** Groups IPs across CIDR /24 and /16 subnets and calculates pool concentration penalties to prevent cascade subnet bans.
* **Microsecond Latency Breakdown:** Accurately separates DNS resolution, TCP SYN-ACK handshake, TLS 1.3 handshake, and Time-to-First-Byte (TTFB).
* **Bot Pool Exporter:** Automatically segregates audited proxies into bot-ready files (god_tier_ashburn.txt, clean_residential.txt, discarded_dirty.txt).
* **High-Throughput Concurrency:** Asynchronous non-blocking architecture benchmarked at 27,000+ proxies per second with sub-4ms event loop lag.

## Tech Stack

* **Python 3.12** (Strict typing, PEP 8, Asyncio)
* **curl_cffi & aiohttp** (HTTP/2 & TLS 1.3 browser impersonation)
* **FastAPI & Uvicorn** (REST API & WebSockets live streaming)
* **SQLAlchemy 2.0 & asyncpg** (Asynchronous PostgreSQL persistence)
* **Redis 7** (L2 ASN caching & task queues)
* **Rich** (Terminal UI & CLI reporting tables)
* **Docker & Docker Compose** (Single-command deployment)

## Quick Start

1. Add your proxies into `proxies.txt`:

Paste your proxy pool into the `proxies.txt` file located in the project root (one proxy per line, formats: `ip:port:user:pass` or `ip:port`):

```text
188.24.12.50:8080:username:password
104.16.123.96:8080:username:password
```

2. Standalone CLI Audit:

Run the profiler directly from terminal without spinning up containers:

```bash
python run_cli.py
```

3. Live Network Interface Probe:

Inspect your own local network connection, public IP, and edge route:

```bash
python test_live_edge.py
```

4. Full Containerized Stack (FastAPI + PostgreSQL + Redis):

Launch the entire service in background:

```bash
docker compose up --build -d
```

5. Stress Benchmark:

Verify event loop throughput on 2,500 synthetic proxies:

```bash
python -m benchmark.stress_runner
```
