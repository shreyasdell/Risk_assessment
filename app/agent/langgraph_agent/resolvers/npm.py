"""
NPM deterministic resolver.

Extracts vendor/product from NPM PURLs without LLM.
"""

from typing import Optional, Dict


class NPMResolver:
    """Deterministic resolver for NPM packages."""
    
    def resolve(self, purl: str, component_name: str) -> Optional[Dict]:
        """
        Resolve NPM component from PURL.
        
        Input: pkg:npm/@angular/core@16.0.0
        Output:
            vendor = angular
            product = core
            search_name = angular core
            confidence = 95
            resolution_method = deterministic
        """
        if not purl or not purl.startswith("pkg:npm/"):
            return None
        
        try:
            # Extract path (remove pkg:npm/ and version)
            path = purl[8:].split("@")[0]
            path = path.replace("%40", "@")  # Decode @
            
            if "/" in path:
                # Scoped package: @angular/core
                vendor, product = path.split("/", 1)
                vendor = vendor.lstrip("@")  # Remove @ prefix
                search_name = f"{vendor} {product}"
            else:
                # Unscoped package: react
                vendor = product = path
                search_name = path
            
            return {
                "vendor": vendor,
                "product": product,
                "ecosystem": "npm",
                "search_name": search_name,
                "confidence": 95,
                "resolution_method": "deterministic"
            }
            
        except Exception as e:
            print(f"[NPMResolver] Error: {e}")
            return None
