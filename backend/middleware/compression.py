"""
AI_MODULE: Compression Middleware
AI_DESCRIPTION: Gzip compression for API responses
"""

from starlette.middleware.gzip import GZipMiddleware
from starlette.types import ASGIApp

def add_compression_middleware(app: ASGIApp):
    """
    Add gzip compression middleware

    Compresses responses > 1000 bytes
    Reduces bandwidth usage by 70-90%
    """
    return GZipMiddleware(app, minimum_size=1000)
