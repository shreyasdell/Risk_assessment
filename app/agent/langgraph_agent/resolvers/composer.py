"""
Composer deterministic resolver.

Extracts vendor/product from Composer PURLs without LLM.
"""

from typing import Optional, Dict


class ComposerResolver:
    """Deterministic resolver for Composer packages."""
    
    def resolve(self, purl: str, component_name: str) -> Optional[Dict]:
        """
        Resolve Composer component from PURL.
        
        Input: pkg:composer/guzzlehttp/guzzle@7.8.0
        Output:
            vendor = guzzlehttp
            product = guzzle
            search_name = guzzlehttp guzzle
            confidence = 95
            resolution_method = deterministic
        """
        if not purl or not purl.startswith("pkg:composer/"):
            return None
        
        try:
            # Extract path (remove pkg:composer/ and version)
            path = purl[14:].split("@")[0]
            
            if "/" in path:
                vendor, product = path.split("/", 1)
                search_name = f"{vendor} {product}"
            else:
                vendor = product = path
                search_name = path
            
            return {
                "vendor": vendor,
                "product": product,
                "ecosystem": "composer",
                "search_name": search_name,
                "confidence": 95,
                "resolution_method": "deterministic"
            }
            
        except Exception as e:
            print(f"[ComposerResolver] Error: {e}")
            return None
