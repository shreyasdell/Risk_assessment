"""
PyPI deterministic resolver.

Extracts vendor/product from PyPI PURLs without LLM.
"""

from typing import Optional, Dict


class PyPIResolver:
    """Deterministic resolver for PyPI packages."""
    
    def resolve(self, purl: str, component_name: str) -> Optional[Dict]:
        """
        Resolve PyPI component from PURL.
        
        Input: pkg:pypi/Flask@2.0.0
        Output:
            vendor = flask
            product = flask
            search_name = flask
            confidence = 90
            resolution_method = deterministic
        """
        if not purl or not purl.startswith("pkg:pypi/"):
            return None
        
        try:
            # Extract path (remove pkg:pypi/ and version)
            path = purl[9:].split("@")[0]
            name = path.split("/")[-1]
            
            # For PyPI, vendor and product are the same
            vendor = product = name
            search_name = name
            
            return {
                "vendor": vendor,
                "product": product,
                "ecosystem": "pypi",
                "search_name": search_name,
                "confidence": 90,
                "resolution_method": "deterministic"
            }
            
        except Exception as e:
            print(f"[PyPIResolver] Error: {e}")
            return None
