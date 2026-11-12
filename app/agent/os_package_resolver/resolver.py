"""
OS Package Resolver.

Normalizes Linux distribution package names to canonical upstream products.
"""

from typing import Optional, Dict, Tuple
from .aliases import OSPackageAliases


class OSPackageResolver:
    """Resolves OS package names to canonical vendor/product."""
    
    def __init__(self):
        self.aliases = OSPackageAliases()
    
    def detect_ecosystem(self, purl: str, component_name: str) -> Optional[str]:
        """
        Detect if a component is an OS package and its ecosystem.
        
        Args:
            purl: Package URL
            component_name: Component name
        
        Returns:
            Ecosystem (deb, rpm, apk) or None if not an OS package
        """
        if not purl:
            return None
        
        if purl.startswith("pkg:deb/"):
            return "deb"
        elif purl.startswith("pkg:rpm/"):
            return "rpm"
        elif purl.startswith("pkg:apk/"):
            return "apk"
        
        # Heuristic detection based on package name patterns
        if component_name.startswith("lib") and component_name.count("-") >= 1:
            # Likely a library package (libssl1.1, libbz2-1.0)
            return "deb"  # Default to deb for lib* patterns
        
        return None
    
    def resolve(self, package_name: str, ecosystem: str) -> Dict:
        """
        Resolve a package name to canonical vendor/product.
        
        Args:
            package_name: Distribution package name (e.g., "libc6", "libssl1.1")
            ecosystem: Package ecosystem (deb, rpm, apk)
        
        Returns:
            Dict with canonical_vendor, canonical_product, and resolution info
        """
        result = {
            "package_name": package_name,
            "ecosystem": ecosystem,
            "canonical_vendor": None,
            "canonical_product": None,
            "resolution_method": None,
            "confidence": 0
        }
        
        # Try alias resolution
        alias_result = self.aliases.resolve(package_name, ecosystem)
        if alias_result:
            canonical_vendor, canonical_product = alias_result
            result["canonical_vendor"] = canonical_vendor
            result["canonical_product"] = canonical_product
            result["resolution_method"] = "alias"
            result["confidence"] = 90
            return result
        
        # Fallback: use package name as-is
        result["canonical_vendor"] = package_name
        result["canonical_product"] = package_name
        result["resolution_method"] = "fallback"
        result["confidence"] = 50
        
        return result
    
    def generate_search_name(self, canonical_vendor: str, canonical_product: str) -> str:
        """
        Generate search name from canonical vendor/product.
        
        Args:
            canonical_vendor: Canonical vendor (e.g., "gnu")
            canonical_product: Canonical product (e.g., "glibc")
        
        Returns:
            Search name for NVD (e.g., "gnu glibc")
        """
        if canonical_vendor and canonical_product:
            if canonical_vendor.lower() in canonical_product.lower():
                # Vendor is redundant, return product only
                return canonical_product
            else:
                # Both needed
                return f"{canonical_vendor.lower()} {canonical_product}"
        return canonical_product or ""
