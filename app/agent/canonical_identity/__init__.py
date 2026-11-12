"""
Canonical Component Identity Layer.

Extracts canonical identities from PURLs, lock files, and package manifests.
Ensures consistent identity resolution across SBOM and codebase uploads.
"""

from .resolver import CanonicalIdentityResolver

__all__ = [
    'CanonicalIdentityResolver',
]
