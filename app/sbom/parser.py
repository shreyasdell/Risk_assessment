import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional
from app.schemas.component import ComponentCreate, ComponentTypeEnum


class SBOMParser:
    """Base parser for SBOM files"""
    
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
        
        return ComponentCreate(
            name=name,
            version=version,
            component_type=component_type_enum,
            purl=purl,
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
                    
                    component = ComponentCreate(
                        name=name.text,
                        version=version.text,
                        component_type=component_type_enum,
                        purl=purl.text if purl is not None else None,
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
        
        return ComponentCreate(
            name=name,
            version=version,
            component_type=ComponentTypeEnum.LIBRARY,
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
    def _map_component_type(cyclonedx_type: str) -> ComponentTypeEnum:
        """Map CycloneDX component type to our enum"""
        type_mapping = {
            "library": ComponentTypeEnum.LIBRARY,
            "framework": ComponentTypeEnum.FRAMEWORK,
            "application": ComponentTypeEnum.PLATFORM,
            "operating-system": ComponentTypeEnum.OPERATING_SYSTEM,
            "device": ComponentTypeEnum.PLATFORM,
            "firmware": ComponentTypeEnum.PLATFORM,
            "file": ComponentTypeEnum.OTHER,
            "container": ComponentTypeEnum.PLATFORM,
            "platform": ComponentTypeEnum.PLATFORM
        }
        return type_mapping.get(cyclonedx_type.lower(), ComponentTypeEnum.LIBRARY)
    
    @staticmethod
    def detect_format(content: str, filename: str) -> str:
        """Detect SBOM format from content or filename"""
        if filename.endswith(".json"):
            try:
                data = json.loads(content)
                if "bomFormat" in data and data["bomFormat"] == "CycloneDX":
                    return "cyclonedx_json"
                elif "spdxVersion" in data:
                    return "spdx_json"
            except json.JSONDecodeError:
                pass
        elif filename.endswith(".xml"):
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
