import asyncio
from core.logger import app_logger
from storage.db import db_manager
from storage.redis_queue import redis_manager


async def test_storage_layer() -> None:
    app_logger.info("Validating database and cache infrastructure status...")

    postgres_alive: bool = await db_manager.check_connection()
    if postgres_alive:
        app_logger.info("PostgreSQL (asyncpg): [bold green]ONLINE[/bold green]")
        await db_manager.create_tables()
    else:
        app_logger.warning("PostgreSQL (asyncpg): [bold yellow]OFFLINE[/bold yellow] (Will be mounted in Docker Compose)")

    redis_alive: bool = await redis_manager.check_connection()
    if redis_alive:
        app_logger.info("Redis Queue & Cache: [bold green]ONLINE[/bold green]")
    else:
        app_logger.warning("Redis Queue & Cache: [bold yellow]OFFLINE[/bold yellow] (Will be mounted in Docker Compose)")

    await redis_manager.close()
    app_logger.info("Storage diagnostics finished.")


if __name__ == "__main__":
    asyncio.run(test_storage_layer())