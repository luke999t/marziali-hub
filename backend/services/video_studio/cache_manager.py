"""
Cache Manager - Performance Optimization
Implements caching for frequently accessed data
"""

from typing import Any, Optional, Callable
from functools import wraps
import json
import hashlib
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class CacheManager:
    """Simple in-memory cache with TTL support"""

    def __init__(self, default_ttl: int = 300):  # 5 minutes default
        self.cache = {}
        self.default_ttl = default_ttl

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if key in self.cache:
            entry = self.cache[key]
            if datetime.utcnow() < entry['expires_at']:
                logger.debug(f"Cache hit: {key}")
                return entry['value']
            else:
                # Expired
                del self.cache[key]
                logger.debug(f"Cache expired: {key}")

        logger.debug(f"Cache miss: {key}")
        return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value in cache"""
        if ttl is None:
            ttl = self.default_ttl

        self.cache[key] = {
            'value': value,
            'created_at': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(seconds=ttl)
        }
        logger.debug(f"Cache set: {key} (TTL: {ttl}s)")

    def delete(self, key: str):
        """Delete value from cache"""
        if key in self.cache:
            del self.cache[key]
            logger.debug(f"Cache deleted: {key}")

    def clear(self):
        """Clear all cache"""
        self.cache.clear()
        logger.info("Cache cleared")

    def get_stats(self) -> dict:
        """Get cache statistics"""
        return {
            "total_entries": len(self.cache),
            "memory_size_approx": sum(len(str(v)) for v in self.cache.values())
        }


def cache_key(*args, **kwargs) -> str:
    """Generate cache key from arguments"""
    key_data = json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True)
    return hashlib.md5(key_data.encode()).hexdigest()


def cached(ttl: int = 300, key_prefix: str = ""):
    """
    Decorator to cache function results

    Usage:
        @cached(ttl=600, key_prefix="skeleton")
        def get_skeleton_data(video_id):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            cache_k = f"{key_prefix}:{func.__name__}:{cache_key(*args, **kwargs)}"

            # Try to get from cache
            cached_result = cache.get(cache_k)
            if cached_result is not None:
                return cached_result

            # Call function and cache result
            result = func(*args, **kwargs)
            cache.set(cache_k, result, ttl)

            return result

        return wrapper
    return decorator


# Global cache instance
cache = CacheManager(default_ttl=300)
