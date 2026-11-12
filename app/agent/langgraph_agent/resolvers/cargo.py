"""
Cargo deterministic resolver.

Extracts vendor/product from Cargo PURLs without LLM.
"""

from typing import Optional, Dict


class CargoResolver:
    """Deterministic resolver for Cargo packages."""
    
    def resolve(self, purl: str, component_name: str) -> Optional[Dict]:
        """
        Resolve Cargo component from PURL.
        
        Input: pkg:cargo/serde@1.0.0
        Output:
            vendor = serde
            product = serde
            search_name = serde
            confidence = 90
            resolution_method = deterministic
        """
        if not purl or not purl.startswith("pkg:cargo/"):
            return None
        
        try:
            # Extract path (remove pkg:cargo/ and version)
            path = purl[11:].split("@")[0]
            name = path.split("/")[-1]
            
            # For Cargo, vendor and product are the same
            vendor = product = name
            search_name = name
            
            return {
                "vendor": vendor,
                "product": product,
                "ecosystem": "cargo",
                "search_name": search_name,
                "confidence": 90,
                "resolution_method": "deterministic"
            }
            
        except Exception as e:
            print(f"[CargoResolver] Error: {e}")
            return None
