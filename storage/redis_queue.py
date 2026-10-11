import json
from redis.asyncio import Redis, from_url
from core.config import get_settings
from core.logger import app_logger


class RedisQueueManager:
    def __init__(self) -> None:
        settings = get_settings()
        self._redis_url: str = settings.redis_url
        self._client: Redis = from_url(
            self._redis_url,
            decode_responses=True,
            socket_timeout=3.0,
            socket_connect_timeout=3.0
        )

    async def check_connection(self) -> bool:
        try:
            return await self._client.ping()
        except Exception as error:
            app_logger.warning(f"Redis connection offline or unreachable: {error}")
            return False

    async def push_proxies(self, queue_name: str, proxies: list[str]) -> int:
        if not proxies:
            return 0
        return await self._client.lpush(queue_name, *proxies)

    async def pop_proxy(self, queue_name: str) -> str | None:
        return await self._client.rpop(queue_name)

    async def get_queue_len(self, queue_name: str) -> int:
        return await self._client.llen(queue_name)

    async def cache_asn_result(self, ip_address: str, payload: dict, ttl_seconds: int = 86400) -> None:
        key: str = f"asn_cache:{ip_address}"
        try:
            serialized: str = json.dumps(payload)
            await self._client.set(key, serialized, ex=ttl_seconds)
        except Exception as error:
            app_logger.debug(f"Redis ASN cache write failure: {error}")

    async def get_cached_asn_result(self, ip_address: str) -> dict | None:
        key: str = f"asn_cache:{ip_address}"
        try:
            cached = await self._client.get(key)
            if cached:
                return json.loads(cached)
        except Exception as error:
            app_logger.debug(f"Redis ASN cache read failure: {error}")
        return None

    async def close(self) -> None:
        await self._client.aclose()


redis_manager: RedisQueueManager = RedisQueueManager()