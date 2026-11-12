"""
OS Package Resolver for Linux distribution packages.

Normalizes distribution package names (deb, rpm, apk) to canonical upstream products
before NVD discovery to reduce false positives and improve CVE discovery accuracy.
"""

from .resolver import OSPackageResolver
from .aliases import OSPackageAliases

__all__ = [
    'OSPackageResolver',
    'OSPackageAliases',
]
