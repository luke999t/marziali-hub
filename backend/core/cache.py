"""
AI_MODULE: Cache Service
AI_DESCRIPTION: Redis-based caching for API responses
AI_BUSINESS: Performance optimization, reduce DB load
"""

from functools import wraps
from typing import Optional, Any, Callable
import json
import hashlib
from datetime import timedelta

# Mock Redis for now - replace with actual Redis in production
class MockRedis:
    def __init__(self):
        self._cache = {}

    def get(self, key: str) -> Optional[bytes]:
        return self._cache.get(key)

    def set(self, key: str, value: bytes, ex: int = None):
        self._cache[key] = value

    def delete(self, key: str):
        self._cache.pop(key, None)

    def flushdb(self):
        self._cache.clear()

# Global cache instance
cache = MockRedis()

def generate_cache_key(prefix: str, *args, **kwargs) -> str:
    """Generate cache key from function arguments"""
    key_data = f"{prefix}:{str(args)}:{str(sorted(kwargs.items()))}"
    return hashlib.md5(key_data.encode()).hexdigest()

def cached(prefix: str, ttl: int = 300):
    """
    Cache decorator for functions

    Args:
        prefix: Cache key prefix
        ttl: Time to live in seconds (default 5 minutes)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = generate_cache_key(prefix, *args, **kwargs)

            # Try to get from cache
            cached_value = cache.get(cache_key)
            if cached_value:
                return json.loads(cached_value)

            # Call function
            result = await func(*args, **kwargs)

            # Store in cache
            cache.set(cache_key, json.dumps(result).encode(), ex=ttl)

            return result
        return wrapper
    return decorator

def invalidate_cache(prefix: str, *args, **kwargs):
    """Invalidate specific cache entry"""
    cache_key = generate_cache_key(prefix, *args, **kwargs)
    cache.delete(cache_key)

def clear_cache():
    """Clear all cache"""
    cache.flushdb()

# Common TTL values
TTL_1_MINUTE = 60
TTL_5_MINUTES = 300
TTL_15_MINUTES = 900
TTL_1_HOUR = 3600
TTL_24_HOURS = 86400
