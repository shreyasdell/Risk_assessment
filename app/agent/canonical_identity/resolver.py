"""
Canonical Component Identity Resolver.

Extracts canonical identities from PURLs, lock files, and package manifests.
Ensures consistent identity resolution across SBOM and codebase uploads.
"""

from typing import Optional, Dict, Tuple
import re


class CanonicalIdentityResolver:
    """Resolves canonical component identities from various sources."""
    
    def __init__(self):
        pass
    
    def resolve_from_purl(self, purl: str) -> Optional[Dict]:
        """
        Extract canonical identity from PURL.
        
        Args:
            purl: Package URL (e.g., pkg:composer/guzzlehttp/guzzle@6.5.8)
        
        Returns:
            Dict with canonical_ecosystem, canonical_vendor_identity, canonical_product_identity, canonical_key
        """
        if not purl:
            return None
        
        # Parse PURL format: pkg:type/namespace/name@version
        match = re.match(r'^pkg:([^/]+)/([^/]+)/([^@]+)', purl)
        if not match:
            return None
        
        purl_type = match.group(1)
        namespace = match.group(2)
        name = match.group(3)
        
        # Determine canonical ecosystem
        canonical_ecosystem = self._normalize_ecosystem(purl_type)
        
        # Extract canonical vendor and product
        canonical_vendor, canonical_product = self._extract_vendor_product(
            canonical_ecosystem, namespace, name
        )
        
        # Generate canonical key
        canonical_key = f"{canonical_ecosystem}:{canonical_vendor}:{canonical_product}"
        
        return {
            "canonical_ecosystem": canonical_ecosystem,
            "canonical_vendor_identity": canonical_vendor,
            "canonical_product_identity": canonical_product,
            "canonical_key": canonical_key,
            "resolution_method": "purl"
        }
    
    def resolve_from_lock_file(self, lock_file: str, package_name: str) -> Optional[Dict]:
        """
        Extract canonical identity from lock file (composer.lock, package-lock.json, etc.).
        
        Args:
            lock_file: Lock file type (composer, npm, maven, etc.)
            package_name: Package name from lock file (e.g., guzzlehttp/guzzle)
        
        Returns:
            Dict with canonical identity
        """
        if not lock_file or not package_name:
            return None
        
        # Determine ecosystem from lock file type
        canonical_ecosystem = self._normalize_ecosystem(lock_file)
        
        # Parse package name
        if "/" in package_name:
            # composer/npm format: vendor/package
            parts = package_name.split("/", 1)
            namespace = parts[0]
            name = parts[1]
        else:
            # Simple name (e.g., npm without scope)
            namespace = None
            name = package_name
        
        # Extract canonical vendor and product
        canonical_vendor, canonical_product = self._extract_vendor_product(
            canonical_ecosystem, namespace, name
        )
        
        # Generate canonical key
        canonical_key = f"{canonical_ecosystem}:{canonical_vendor}:{canonical_product}"
        
        return {
            "canonical_ecosystem": canonical_ecosystem,
            "canonical_vendor_identity": canonical_vendor,
            "canonical_product_identity": canonical_product,
            "canonical_key": canonical_key,
            "resolution_method": "lock_file"
        }
    
    def resolve_from_code_path(self, code_path: str) -> Optional[Dict]:
        """
        Extract canonical identity from code path (e.g., vendor/guzzlehttp/guzzle).
        
        Args:
            code_path: Code path (e.g., vendor/guzzlehttp/guzzle)
        
        Returns:
            Dict with canonical identity
        """
        if not code_path:
            return None
        
        # Detect ecosystem from path structure
        if code_path.startswith("vendor/"):
            # PHP Composer
            parts = code_path.split("/")
            if len(parts) >= 3:
                namespace = parts[1]
                name = parts[2]
                canonical_ecosystem = "composer"
                
                canonical_vendor, canonical_product = self._extract_vendor_product(
                    canonical_ecosystem, namespace, name
                )
                
                canonical_key = f"{canonical_ecosystem}:{canonical_vendor}:{canonical_product}"
                
                return {
                    "canonical_ecosystem": canonical_ecosystem,
                    "canonical_vendor_identity": canonical_vendor,
                    "canonical_product_identity": canonical_product,
                    "canonical_key": canonical_key,
                    "resolution_method": "code_path"
                }
        
        elif code_path.startswith("node_modules/"):
            # NPM
            parts = code_path.split("/")
            if len(parts) >= 2:
                # Handle scoped packages: @angular/core
                if parts[1].startswith("@"):
                    if len(parts) >= 3:
                        namespace = parts[1]
                        name = parts[2]
                    else:
                        namespace = None
                        name = parts[1]
                else:
                    namespace = None
                    name = parts[1]
                
                canonical_ecosystem = "npm"
                canonical_vendor, canonical_product = self._extract_vendor_product(
                    canonical_ecosystem, namespace, name
                )
                
                canonical_key = f"{canonical_ecosystem}:{canonical_vendor}:{canonical_product}"
                
                return {
                    "canonical_ecosystem": canonical_ecosystem,
                    "canonical_vendor_identity": canonical_vendor,
                    "canonical_product_identity": canonical_product,
                    "canonical_key": canonical_key,
                    "resolution_method": "code_path"
                }
        
        elif code_path.startswith("go.mod") or "go/pkg/mod/" in code_path:
            # Go
            if "go/pkg/mod/" in code_path:
                # Extract from go module path
                match = re.search(r'go/pkg/mod/([^@]+)', code_path)
                if match:
                    module_path = match.group(1)
                    return self._resolve_from_go_module(module_path)
            return None
        
        return None
    
    def resolve_from_go_module(self, module_path: str) -> Optional[Dict]:
        """
        Extract canonical identity from Go module path.
        
        Args:
            module_path: Go module path (e.g., github.com/Masterminds/semver/v3)
        
        Returns:
            Dict with canonical identity
        """
        if not module_path:
            return None
        
        # Parse GitHub paths: github.com/owner/repo
        if module_path.startswith("github.com/"):
            parts = module_path.split("/")
            if len(parts) >= 3:
                vendor = parts[1]
                product = parts[2]
                # Remove version suffix (e.g., /v3)
                product = re.sub(r'/v\d+$', '', product)
                
                canonical_key = f"golang:{vendor}:{product}"
                
                return {
                    "canonical_ecosystem": "golang",
                    "canonical_vendor_identity": vendor,
                    "canonical_product_identity": product,
                    "canonical_key": canonical_key,
                    "resolution_method": "go_module"
                }
        
        # Other Go modules - use full path as vendor, last part as product
        parts = module_path.split("/")
        if len(parts) >= 2:
            vendor = "/".join(parts[:-1])
            product = parts[-1]
            product = re.sub(r'/v\d+$', '', product)
            
            canonical_key = f"golang:{vendor}:{product}"
            
            return {
                "canonical_ecosystem": "golang",
                "canonical_vendor_identity": vendor,
                "canonical_product_identity": product,
                "canonical_key": canonical_key,
                "resolution_method": "go_module"
            }
        
        return None
    
    def _normalize_ecosystem(self, ecosystem: str) -> str:
        """Normalize ecosystem name."""
        ecosystem_map = {
            "composer": "composer",
            "php": "composer",
            "npm": "npm",
            "node": "npm",
            "maven": "maven",
            "java": "maven",
            "pypi": "pypi",
            "python": "pypi",
            "golang": "golang",
            "go": "golang",
            "cargo": "cargo",
            "rust": "cargo",
            "nuget": "nuget",
            "dotnet": "nuget",
            "apk": "apk",
            "deb": "deb",
            "rpm": "rpm",
        }
        
        return ecosystem_map.get(ecosystem.lower(), ecosystem.lower())
    
    def _extract_vendor_product(self, ecosystem: str, namespace: str, name: str) -> Tuple[str, str]:
        """
        Extract canonical vendor and product based on ecosystem rules.
        
        Args:
            ecosystem: Canonical ecosystem
            namespace: Package namespace (e.g., guzzlehttp, org.apache)
            name: Package name (e.g., guzzle, activemq-pool)
        
        Returns:
            Tuple of (canonical_vendor, canonical_product)
        """
        if ecosystem == "composer":
            # Composer: vendor/package → vendor/package
            if namespace:
                return namespace, name
            return name, name
        
        elif ecosystem == "npm":
            # NPM: @angular/core → angular/core
            if namespace and namespace.startswith("@"):
                vendor = namespace[1:]  # Remove @
                return vendor, name
            elif namespace:
                return namespace, name
            return name, name
        
        elif ecosystem == "maven":
            # Maven: org.apache.activemq/activemq-pool → apache/activemq-pool
            if namespace:
                # Extract from groupId (e.g., org.apache.activemq → apache)
                parts = namespace.split(".")
                # Use last non-org part, or second-to-last if starts with org/com
                if parts[0] in ["org", "com", "io", "net"] and len(parts) >= 2:
                    vendor = parts[-1]
                else:
                    vendor = parts[-1] if len(parts) > 0 else name
                return vendor, name
            return name, name
        
        elif ecosystem == "pypi":
            # PyPI: package name is both vendor and product
            return name, name
        
        elif ecosystem == "golang":
            # Go: already handled in resolve_from_go_module
            return namespace or name, name
        
        elif ecosystem == "cargo":
            # Cargo: package name is both vendor and product
            return name, name
        
        elif ecosystem == "nuget":
            # NuGet: Newtonsoft.Json → Newtonsoft/Json
            if "." in name:
                parts = name.split(".")
                vendor = parts[0]
                product = ".".join(parts[1:])
                return vendor, product
            return name, name
        
        elif ecosystem in ["apk", "deb", "rpm"]:
            # OS packages: use OS package resolver
            return namespace or name, name
        
        # Default: use namespace as vendor, name as product
        return namespace or name, name
    
    def generate_canonical_key(self, ecosystem: str, vendor: str, product: str) -> str:
        """
        Generate canonical key from ecosystem, vendor, and product.
        
        Args:
            ecosystem: Canonical ecosystem
            vendor: Canonical vendor
            product: Canonical product
        
        Returns:
            Canonical key in format: ecosystem:vendor:product
        """
        return f"{ecosystem}:{vendor}:{product}"
