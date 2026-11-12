"""
Maven deterministic resolver.

Extracts vendor/product from Maven PURLs without LLM.
"""

from typing import Optional, Dict


class MavenResolver:
    """Deterministic resolver for Maven packages."""
    
    def resolve(self, purl: str, component_name: str) -> Optional[Dict]:
        """
        Resolve Maven component from PURL.
        
        Input: pkg:maven/org.apache.activemq/activemq-pool@5.7.0
        Output:
            vendor = apache
            product = activemq-pool
            search_name = apache activemq-pool
            confidence = 95
            resolution_method = deterministic
        """
        if not purl or not purl.startswith("pkg:maven/"):
            return None
        
        try:
            # Extract path (remove pkg:maven/ and version)
            path = purl[11:].split("@")[0]
            parts = path.split("/")
            
            if len(parts) < 2:
                return None
            
            group_id = parts[0]
            artifact_id = parts[-1]
            
            # Extract vendor from group_id
            vendor = self._extract_vendor_from_group(group_id)
            
            # Preserve full artifact_id as product (don't collapse)
            product = artifact_id
            
            # Search name: vendor product (preserve artifact name)
            search_name = f"{vendor.lower()} {product}"
            
            return {
                "vendor": vendor,
                "product": product,
                "ecosystem": "maven",
                "search_name": search_name,
                "confidence": 95,
                "resolution_method": "deterministic"
            }
            
        except Exception as e:
            print(f"[MavenResolver] Error: {e}")
            return None
    
    def _extract_vendor_from_group(self, group_id: str) -> str:
        """
        Extract vendor from Maven group ID.
        
        Examples:
        - org.apache.logging.log4j -> Apache
        - org.springframework.boot -> Spring
        - com.google.guava -> Google
        - io.github -> GitHub
        """
        vendor_map = {
            "org.apache": "Apache",
            "com.google": "Google",
            "org.springframework": "Spring",
            "com.fasterxml": "FasterXML",
            "io.github": "GitHub",
            "com.microsoft": "Microsoft",
            "org.eclipse": "Eclipse",
            "com.amazonaws": "Amazon",
            "software.amazon": "Amazon",
            "io.netty": "Netty",
            "org.jboss": "Red Hat",
            "org.hibernate": "Red Hat",
            "org.reactivestreams": "Reactive Streams",
            "io.reactivex": "ReactiveX",
            "org.junit": "JUnit",
            "org.mockito": "Mockito",
            "org.testng": "TestNG",
            "org.slf4j": "SLF4J",
            "ch.qos.logback": "QOS.ch",
            "org.aspectj": "AspectJ",
            "org.ow2": "OW2",
            "org.glassfish": "Eclipse",
            "javax": "Oracle",
            "jakarta": "Eclipse",
        }
        
        # Check exact matches
        for prefix, vendor in vendor_map.items():
            if group_id.startswith(prefix):
                return vendor
        
        # Extract second-to-last part as vendor
        parts = group_id.split(".")
        if len(parts) >= 2:
            return parts[-2].capitalize()
        
        return group_id
