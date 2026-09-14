import uuid
from datetime import UTC, datetime
import pytest
from app.redis_store import RedisTokenStore


@pytest.mark.asyncio
async def test_redis_token_store_lifecycle(redis_client):
    store = RedisTokenStore(redis_client)
    user_id = str(uuid.uuid4())
    token_hash = "hash_123"

    session_data = {
        "user_id": user_id,
        "token_family": str(uuid.uuid4()),
        "ip_address": "127.0.0.1",
    }

    # Store token
    await store.store_refresh_token(token_hash, session_data, ttl_seconds=3600)

    # Get token
    retrieved = await store.get_refresh_token(token_hash)
    assert retrieved == session_data

    # Revoke token
    await store.revoke_refresh_token(token_hash)
    assert await store.get_refresh_token(token_hash) is None


@pytest.mark.asyncio
async def test_redis_token_store_used_tokens(redis_client):
    store = RedisTokenStore(redis_client)
    token_hash = "used_hash_456"

    assert not await store.is_token_used(token_hash)
    await store.mark_token_used(token_hash, ttl_seconds=600)
    assert await store.is_token_used(token_hash)


@pytest.mark.asyncio
async def test_redis_token_store_user_session_revocation(redis_client):
    store = RedisTokenStore(redis_client)
    user_id = str(uuid.uuid4())

    await store.store_refresh_token("token_a", {"user_id": user_id}, 3600)
    await store.store_refresh_token("token_b", {"user_id": user_id}, 3600)

    assert await store.get_refresh_token("token_a") is not None
    assert await store.get_refresh_token("token_b") is not None

    now_ts = int(datetime.now(UTC).timestamp())

    # Revoke all user sessions
    await store.revoke_user_sessions(user_id, access_token_ttl=1800)

    assert await store.get_refresh_token("token_a") is None
    assert await store.get_refresh_token("token_b") is None

    # Check access token invalidation for tokens issued at or before revocation
    assert await store.is_access_token_revoked(user_id, iat=now_ts - 5)
    assert not await store.is_access_token_revoked(user_id, iat=now_ts + 10)


@pytest.mark.asyncio
async def test_redis_token_store_access_token_jti_revocation(redis_client):
    store = RedisTokenStore(redis_client)
    jti = str(uuid.uuid4())
    user_id = str(uuid.uuid4())

    assert not await store.is_access_token_revoked(user_id, iat=1000, jti=jti)
    await store.revoke_access_token(jti, ttl_seconds=300)
    assert await store.is_access_token_revoked(user_id, iat=1000, jti=jti)
