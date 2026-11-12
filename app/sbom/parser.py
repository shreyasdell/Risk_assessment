import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional
from app.schemas.component import ComponentCreate


class SBOMParser:
    """Base parser for SBOM files"""

    @staticmethod
    def _parse_purl(purl: str) -> tuple:
        """
        Parse PURL into (purl_type, purl_namespace, purl_name).
        
        Args:
            purl: Package URL string (e.g., "pkg:composer/laravel/framework@7.30.6")
        
        Returns:
            tuple: (purl_type, purl_namespace, purl_name) or (None, None, None) if invalid
        """
        if not purl or not purl.startswith("pkg:"):
            return None, None, None
        
        # Remove "pkg:" prefix
        purl = purl[4:]
        
        # Split by "/" to get type, namespace, name
        parts = purl.split("/")
        if len(parts) < 2:
            return None, None, None
        
        purl_type = parts[0]  # composer, npm, maven, pypi, golang, apk, deb
        
        # Extract namespace and name
        if len(parts) >= 3:
            # Format: type/namespace/name@version
            purl_namespace = parts[1]
            purl_name_with_version = parts[2]
        else:
            # Format: type/name@version (no namespace)
            purl_namespace = None
            purl_name_with_version = parts[1]
        
        # Remove version and qualifiers
        purl_name = purl_name_with_version.split("@")[0].split("?")[0]
        
        return purl_type, purl_namespace, purl_name

    @staticmethod
    def _extract_name_from_purl(purl: str, original_name: str) -> str:
        """
        Extract full package name from PURL for ecosystems where the name field is incomplete.

        This fixes the issue where CycloneDX stores bare names (e.g., "framework") for
        Composer packages, but the PURL contains the full vendor/package (e.g., "laravel/framework").

        Args:
            purl: Package URL string (e.g., "pkg:composer/laravel/framework@7.30.6")
            original_name: Original name from SBOM (e.g., "framework")

        Returns:
            Full package name if PURL provides it, otherwise original name
        """
        if not purl:
            return original_name

        # Composer/PHP: pkg:composer/vendor/package@version
        if purl.startswith("pkg:composer/"):
            # Extract vendor/package from PURL
            # Format: pkg:composer/vendor/package@version
            # We need to extract everything between "pkg:composer/" and "@"
            parts = purl.split("/")
            if len(parts) >= 3:
                # parts[0] = "pkg:composer", parts[1] = "vendor", parts[2] = "package@version"
                vendor = parts[1]
                package_with_version = parts[2]
                # Remove version and qualifiers
                package = package_with_version.split("@")[0].split("?")[0]
                return f"{vendor}/{package}"

        # Maven: pkg:maven/groupId/artifactId@version
        # Maven already stores artifactId in name field, but we can use groupId/artifactId for clarity
        if purl.startswith("pkg:maven/"):
            parts = purl.split("/")
            if len(parts) >= 3:
                # parts[0] = "pkg:maven", parts[1] = "groupId", parts[2] = "artifactId@version"
                group_id = parts[1]
                artifact_id = parts[2].split("@")[0].split("?")[0]
                # Use artifactId only (already correct in most cases)
                # Or use groupId:artifactId format if needed
                return artifact_id

        # npm: pkg:npm/@scope/package@version or pkg:npm/package@version
        # npm already stores full name correctly, no change needed
        if purl.startswith("pkg:npm/"):
            return original_name

        # Python: pkg:pypi/package@version
        # Python already stores name correctly, no change needed
        if purl.startswith("pkg:pypi/"):
            return original_name

        # Go: pkg:golang/module@version
        # Go already stores full module path correctly, no change needed
        if purl.startswith("pkg:golang/"):
            return original_name

        # Alpine: pkg:apk/alpine/package@version
        # Alpine already stores package name correctly, no change needed
        if purl.startswith("pkg:apk/"):
            return original_name

        # Debian: pkg:deb/debian/package@version
        # Debian already stores package name correctly, no change needed
        if purl.startswith("pkg:deb/"):
            return original_name

        # For other ecosystems, return original name
        return original_name

    @staticmethod
    def parse_cyclonedx_json(data: Dict, application_id: Optional[int] = None, sbom_id: Optional[str] = None) -> List[ComponentCreate]:
        """Parse CycloneDX JSON format"""
        components = []
        
        if "components" not in data:
            return components
        
        for comp in data["components"]:
            component = SBOMParser._extract_cyclonedx_component(comp, application_id, sbom_id)
            if component:
                components.append(component)
        
        return components
    
    @staticmethod
    def _extract_cyclonedx_component(comp: Dict, application_id: Optional[int], sbom_id: Optional[str]) -> Optional[ComponentCreate]:
        """Extract component data from CycloneDX component object"""
        name = comp.get("name")
        version = comp.get("version")

        if not name or not version:
            return None

        component_type = comp.get("type", "library")
        component_type_enum = SBOMParser._map_component_type(component_type)

        purl = comp.get("purl")
        supplier = comp.get("supplier")
        description = comp.get("description")
        license_info = comp.get("licenses", [{}])[0].get("license", {}).get("id") if comp.get("licenses") else None
        cpe = comp.get("cpe")

        # Parse PURL to extract purl_type, purl_namespace, purl_name
        purl_type, purl_namespace, purl_name = SBOMParser._parse_purl(purl)

        # Enrich name from PURL for ecosystems where name field is incomplete
        # This fixes Composer packages where name is just "framework" but PURL has "laravel/framework"
        enriched_name = SBOMParser._extract_name_from_purl(purl, name)

        return ComponentCreate(
            name=enriched_name,
            version=version,
            component_type=component_type_enum,
            purl=purl,
            purl_type=purl_type,
            purl_namespace=purl_namespace,
            purl_name=purl_name,
            supplier=supplier,
            description=description,
            license=license_info,
            cpe=cpe,
            application_id=application_id,
            sbom_id=sbom_id
        )
    
    @staticmethod
    def parse_cyclonedx_xml(xml_content: str, application_id: Optional[int] = None, sbom_id: Optional[str] = None) -> List[ComponentCreate]:
        """Parse CycloneDX XML format"""
        components = []
        
        try:
            root = ET.fromstring(xml_content)
            namespace = {'bom': 'http://cyclonedx.org/schema/bom/1.4'}
            
            for comp in root.findall('.//bom:component', namespace):
                name = comp.find('bom:name', namespace)
                version = comp.find('bom:version', namespace)
                
                if name is not None and version is not None:
                    component_type = comp.find('bom:type', namespace)
                    purl = comp.find('bom:purl', namespace)
                    supplier = comp.find('bom:supplier', namespace)
                    description = comp.find('bom:description', namespace)
                    cpe = comp.find('bom:cpe', namespace)
                    
                    license_elem = comp.find('.//bom:license/bom:id', namespace)
                    license_info = license_elem.text if license_elem is not None else None
                    
                    component_type_enum = SBOMParser._map_component_type(
                        component_type.text if component_type is not None else "library"
                    )

                    # Enrich name from PURL for ecosystems where name field is incomplete
                    purl_text = purl.text if purl is not None else None
                    enriched_name = SBOMParser._extract_name_from_purl(purl_text, name.text)
                    
                    # Parse PURL to extract purl_type, purl_namespace, purl_name
                    purl_type, purl_namespace, purl_name = SBOMParser._parse_purl(purl_text)

                    component = ComponentCreate(
                        name=enriched_name,
                        version=version.text,
                        component_type=component_type_enum,
                        purl=purl_text,
                        purl_type=purl_type,
                        purl_namespace=purl_namespace,
                        purl_name=purl_name,
                        supplier=supplier.text if supplier is not None else None,
                        description=description.text if description is not None else None,
                        license=license_info,
                        cpe=cpe.text if cpe is not None else None,
                        application_id=application_id,
                        sbom_id=sbom_id
                    )
                    components.append(component)
        
        except ET.ParseError as e:
            raise ValueError(f"Invalid XML format: {str(e)}")
        
        return components
    
    @staticmethod
    def parse_spdx_json(data: Dict, application_id: Optional[int] = None, sbom_id: Optional[str] = None) -> List[ComponentCreate]:
        """Parse SPDX JSON format"""
        components = []
        
        if "packages" not in data:
            return components
        
        for pkg in data["packages"]:
            component = SBOMParser._extract_spdx_package(pkg, application_id, sbom_id)
            if component:
                components.append(component)
        
        return components
    
    @staticmethod
    def _extract_spdx_package(pkg: Dict, application_id: Optional[int], sbom_id: Optional[str]) -> Optional[ComponentCreate]:
        """Extract component data from SPDX package object"""
        name = pkg.get("name")
        version = pkg.get("versionInfo")

        if not name:
            return None

        # SPDX doesn't always have version, use "NOASSERTION" if missing
        if not version:
            version = "unknown"

        purl = pkg.get("externalRefs", [])
        purl_value = None
        for ref in purl:
            if ref.get("referenceType") == "purl":
                purl_value = ref.get("referenceLocator")
                break

        supplier = pkg.get("supplier")
        description = pkg.get("description")
        license_info = pkg.get("licenseConcluded")
        download_location = pkg.get("downloadLocation")

        # Enrich name from PURL for ecosystems where name field is incomplete
        enriched_name = SBOMParser._extract_name_from_purl(purl_value, name)

        return ComponentCreate(
            name=enriched_name,
            version=version,
            component_type="library",  # Changed from Enum to String
            purl=purl_value,
            supplier=supplier,
            description=description,
            license=license_info,
            cpe=None,
            application_id=application_id,
            sbom_id=sbom_id
        )
    
    @staticmethod
    def parse_spdx_rdf(xml_content: str, application_id: Optional[int] = None, sbom_id: Optional[str] = None) -> List[ComponentCreate]:
        """Parse SPDX RDF/XML format (simplified implementation)"""
        # RDF/XML parsing is complex, for now we'll return empty list
        # In production, use rdflib library for proper RDF parsing
        raise NotImplementedError("SPDX RDF/XML parsing requires rdflib library")
    
    @staticmethod
    def _map_component_type(cyclonedx_type: str) -> str:
        """Map CycloneDX component type to our string values"""
        type_mapping = {
            "library": "library",
            "framework": "framework",
            "application": "platform",
            "operating-system": "operating_system",
            "device": "platform",
            "firmware": "platform",
            "file": "other",
            "container": "platform",
            "platform": "platform"
        }
        return type_mapping.get(cyclonedx_type.lower(), "library")
    
    @staticmethod
    def detect_format(content: str, filename: str) -> str:
        """Detect SBOM format from content or filename"""
        # Try content-based detection first
        try:
            data = json.loads(content)
            # CycloneDX indicators
            if "bomFormat" in data and data["bomFormat"] == "CycloneDX":
                return "cyclonedx_json"
            elif "components" in data or "dependencies" in data or "metadata" in data:
                # Common CycloneDX fields (but not SPDX)
                if "spdxVersion" not in data:
                    return "cyclonedx_json"
            # SPDX indicators
            elif "spdxVersion" in data:
                return "spdx_json"
        except json.JSONDecodeError:
            pass
        
        # Try XML parsing
        try:
            root = ET.fromstring(content)
            if "CycloneDX" in root.tag or "bom" in root.tag.lower():
                return "cyclonedx_xml"
            elif "SPDX" in root.tag or "Document" in root.tag:
                return "spdx_rdf"
        except ET.ParseError:
            pass
        
        raise ValueError("Unable to detect SBOM format")
    
    @staticmethod
    def parse(content: str, filename: str, application_id: Optional[int] = None, sbom_id: Optional[str] = None) -> List[ComponentCreate]:
        """Parse SBOM content based on detected format"""
        format_type = SBOMParser.detect_format(content, filename)
        
        if format_type == "cyclonedx_json":
            data = json.loads(content)
            return SBOMParser.parse_cyclonedx_json(data, application_id, sbom_id)
        elif format_type == "cyclonedx_xml":
            return SBOMParser.parse_cyclonedx_xml(content, application_id, sbom_id)
        elif format_type == "spdx_json":
            data = json.loads(content)
            return SBOMParser.parse_spdx_json(data, application_id, sbom_id)
        elif format_type == "spdx_rdf":
            return SBOMParser.parse_spdx_rdf(content, application_id, sbom_id)
        else:
            raise ValueError(f"Unsupported SBOM format: {format_type}")
