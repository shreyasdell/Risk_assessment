"""
NuGet deterministic resolver.

Extracts vendor/product from NuGet PURLs without LLM.
"""

from typing import Optional, Dict


class NuGetResolver:
    """Deterministic resolver for NuGet packages."""
    
    def resolve(self, purl: str, component_name: str) -> Optional[Dict]:
        """
        Resolve NuGet component from PURL.
        
        Input: pkg:nuget/Newtonsoft.Json@13.0.0
        Output:
            vendor = Newtonsoft
            product = Json
            search_name = newtonsoft json
            confidence = 90
            resolution_method = deterministic
        """
        if not purl or not purl.startswith("pkg:nuget/"):
            return None
        
        try:
            # Extract path (remove pkg:nuget/ and version)
            path = purl[10:].split("@")[0]
            name = path.split("/")[-1]
            
            # Split by dot to extract vendor/product
            if "." in name:
                parts = name.split(".")
                vendor = parts[0]
                product = ".".join(parts[1:])  # Preserve rest as product
            else:
                vendor = product = name
            
            search_name = f"{vendor.lower()} {product.lower()}"
            
            return {
                "vendor": vendor,
                "product": product,
                "ecosystem": "nuget",
                "search_name": search_name,
                "confidence": 90,
                "resolution_method": "deterministic"
            }
            
        except Exception as e:
            print(f"[NuGetResolver] Error: {e}")
            return None
