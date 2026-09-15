import json
import logging
from datetime import UTC, datetime
from typing import Any

import redis.asyncio as redis

from app.config import settings

logger = logging.getLogger(__name__)

# Global async Redis client reference (can be overridden in tests via set_redis_client)
_redis_client: redis.Redis | None = None


def get_redis_client() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis_client


def set_redis_client(client: redis.Redis | None) -> None:
    global _redis_client
    _redis_client = client


class RedisTokenStore:
    """Redis-backed token and session lifecycle manager.
    
    Handles session storage, automatic TTL expiration, single token invalidation (logout),
    user-wide session revocation, access token blocklisting, and rotation reuse detection.
    """

    def __init__(self, client: redis.Redis | None = None) -> None:
        self.client = client

    @property
    def redis(self) -> redis.Redis:
        return self.client if self.client is not None else get_redis_client()

    async def store_refresh_token(
        self,
        token_hash: str,
        session_data: dict[str, Any],
        ttl_seconds: int,
    ) -> None:
        """Store refresh token session metadata in Redis with automatic TTL eviction."""
        user_id = str(session_data["user_id"])
        key = f"refresh_token:{token_hash}"
        user_sessions_key = f"user_sessions:{user_id}"

        session_json = json.dumps(session_data)
        
        # Pipelines execute commands atomically in a single Redis roundtrip
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.set(key, session_json, ex=ttl_seconds)
            pipe.sadd(user_sessions_key, token_hash)
            pipe.expire(user_sessions_key, ttl_seconds)
            await pipe.execute()

    async def get_refresh_token(self, token_hash: str) -> dict[str, Any] | None:
        """Retrieve active refresh token session data from Redis."""
        key = f"refresh_token:{token_hash}"
        raw_data = await self.redis.get(key)
        if not raw_data:
            return None
        try:
            return json.loads(raw_data)
        except Exception:
            return None

    async def revoke_refresh_token(self, token_hash: str) -> None:
        """Revoke/delete a single refresh token session (e.g. on logout)."""
        session_data = await self.get_refresh_token(token_hash)
        key = f"refresh_token:{token_hash}"
        
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.delete(key)
            if session_data and "user_id" in session_data:
                user_sessions_key = f"user_sessions:{session_data['user_id']}"
                pipe.srem(user_sessions_key, token_hash)
            await pipe.execute()

    async def mark_token_used(self, token_hash: str, ttl_seconds: int) -> None:
        """Mark a rotated token as used in Redis to enable token reuse detection."""
        key = f"used_token:{token_hash}"
        await self.redis.set(key, "1", ex=ttl_seconds)

    async def is_token_used(self, token_hash: str) -> bool:
        """Check if a rotated refresh token was previously used."""
        key = f"used_token:{token_hash}"
        val = await self.redis.get(key)
        return val is not None

    async def revoke_user_sessions(
        self,
        user_id: str,
        access_token_ttl: int = 1800,
    ) -> None:
        """Revoke all active refresh sessions for a user and mark user access tokens invalidated."""
        user_sessions_key = f"user_sessions:{user_id}"
        active_token_hashes = await self.redis.smembers(user_sessions_key)
        
        now_ts = int(datetime.now(UTC).timestamp())
        user_revoked_key = f"user_revoked_at:{user_id}"

        async with self.redis.pipeline(transaction=True) as pipe:
            for token_hash in active_token_hashes:
                pipe.delete(f"refresh_token:{token_hash}")
            pipe.delete(user_sessions_key)
            # Record user revocation timestamp (valid for max access token lifetime)
            pipe.set(user_revoked_key, str(now_ts), ex=access_token_ttl)
            await pipe.execute()

    async def is_access_token_revoked(
        self,
        user_id: str,
        iat: int,
        jti: str | None = None,
    ) -> bool:
        """Check if an access token has been revoked explicitly via JTI or user-wide revocation."""
        if jti:
            jti_key = f"revoked_jti:{jti}"
            if await self.redis.get(jti_key):
                return True

        user_revoked_key = f"user_revoked_at:{user_id}"
        revoked_at_str = await self.redis.get(user_revoked_key)
        if revoked_at_str is not None:
            revoked_at = int(revoked_at_str)
            if iat <= revoked_at:
                return True

        return False

    async def revoke_access_token(self, jti: str, ttl_seconds: int) -> None:
        """Add a specific access token JTI to the Redis blocklist."""
        key = f"revoked_jti:{jti}"
        await self.redis.set(key, "1", ex=ttl_seconds)


# Default store singleton instance
token_store = RedisTokenStore()
