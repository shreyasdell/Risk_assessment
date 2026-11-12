"""
Golang deterministic resolver.

Extracts vendor/product from Go PURLs without LLM.
"""

from typing import Optional, Dict


class GolangResolver:
    """Deterministic resolver for Go packages."""
    
    def resolve(self, purl: str, component_name: str) -> Optional[Dict]:
        """
        Resolve Go component from PURL.
        
        Input: pkg:golang/github.com/Microsoft/hcsshim@v0.11.7
        Output:
            vendor = Microsoft
            product = hcsshim
            search_name = microsoft hcsshim
            confidence = 95
            resolution_method = deterministic
        """
        if not purl or not purl.startswith("pkg:golang/"):
            return None
        
        try:
            # Extract path (remove pkg:golang/ and version)
            path = purl[11:].split("@")[0]
            path_parts = path.split("/")
            
            if len(path_parts) >= 3:
                vendor = path_parts[1]  # github.com/Microsoft/hcsshim -> Microsoft
                product = path_parts[-1]     # hcsshim
                search_name = f"{vendor.lower()} {product}"
            else:
                return None
            
            return {
                "vendor": vendor,
                "product": product,
                "ecosystem": "golang",
                "search_name": search_name,
                "confidence": 95,
                "resolution_method": "deterministic"
            }
            
        except Exception as e:
            print(f"[GolangResolver] Error: {e}")
            return None
