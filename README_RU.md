# Proxy Edge Profiler

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg)](https://fastapi.tiangolo.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D.svg)](https://redis.io/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://www.docker.com/)

[🇬🇧 Read in English](README.md)

Высокоскоростной асинхронный сетевой профайлер и анализатор Anycast CDN маршрутизации для глубокого аудита, бенчмаркинга и классификации пулов прокси (Residential, ISP, Datacenter, Mobile) в реальном времени.

Система создана для выявления обмана со стороны селлеров прокси, анализа L3/L4/L7 инфраструктуры CDN (Cloudflare, Akamai), расчета рисков каскадного бана подсетей и генерации чистых пулов наивысшего качества для сникер-ботов и парсеров.

## Ключевые архитектурные особенности

* **Определение Anycast PoP:** анализ трейс-эндпоинтов Cloudflare с извлечением IATA-кодов аэропортов приземления (IAD Эшберн, ORD Чикаго, LHR Лондон, FRA Франкфурт, ARN Стокгольм).
* **Приоритет маршрута Ashburn Direct:** выделение прокси с приземлением в IAD (Эшберн, Вирджиния) для минимального пинга до серверов Shopify и Nike в AWS us-east-1.
* **Проверка BGP ASN и защита от фейков:** сверка автономных систем в реестрах BGP для выявления хостинг-сетей (Hetzner, OVH, AWS), выдаваемых за домашний интернет.
* **Кластеризация подсетей CIDR /24:** группировка адресов по маскам /24 и /16 с начислением штрафов за чрезмерную концентрацию пула на одной подсети.
* **Микросекундная декомпозиция задержек:** раздельный замер DNS-резолвинга, чистого TCP SYN-ACK сокета, согласования шифров TLS 1.3 и TTFB.
* **Экспорт для ботов:** автогенерация файлов готовых форматов для ботов (god_tier_ashburn.txt, clean_residential.txt, discarded_dirty.txt).
* **Экстремальная скорость:** подтвержденная пропускная способность свыше 27 000+ прокси/сек с лагом Event Loop менее 4 мс.

## Технологический стек

* **Python 3.12** (Строгая типизация, PEP 8, Asyncio)
* **curl_cffi & aiohttp** (HTTP/2 и маскировка TLS 1.3 отпечатков Chrome 124)
* **FastAPI & Uvicorn** (REST API и живой стриминг через WebSockets)
* **SQLAlchemy 2.0 & asyncpg** (Асинхронная работа с PostgreSQL)
* **Redis 7** (L2 кэширование ASN и очереди задач)
* **Rich** (Консольный CLI-интерфейс и аналитические таблицы)
* **Docker & Docker Compose** (Развертывание в одну команду)

## Быстрый старт

1. Установка зависимостей:

Установите все необходимые библиотеки в ваше виртуальное окружение:

```bash
pip install -r requirements.txt
```

2. Добавление прокси в `proxies.txt`:

Поместите список ваших прокси в файл `proxies.txt` в корне проекта (по одному на строку, формат: `ip:port:user:pass` или `ip:port`):

```text
188.24.12.50:8080:username:password
104.16.123.96:8080:username:password
```

3. Консольный Solo CLI-режим:

Запустите аудит пула напрямую из терминала без развертывания контейнеров:

```bash
python run_cli.py
```

4. Живой тест сетевого подключения:

Проверьте собственное интернет-соединение, внешний IP и Anycast маршрут:

```bash
python test_live_edge.py
```

5. Запуск всего комплекса в Docker (FastAPI + PostgreSQL + Redis):

Поднимите полный стек одной командой (Docker автоматически установит все зависимости внутри контейнера):

```bash
docker compose up --build -d
```

6. Стресс-тестирование:

Проверьте стабильность Event Loop на 2 500 прокси:

```bash
python -m benchmark.stress_runner
```
