"""
LangGraph Agent for SBOM Component Enrichment

Architecture:
- Node 1: parse_purl - Extracts ecosystem, namespace, name from PURL (70% of cases, no LLM)
- Node 2: check_cache - Looks up vendor/product in cache (hybrid: DB + in-memory)
- Node 3: llm_resolve - Uses Qwen to resolve vendor/product (30% of cases)
- Node 4: construct_cpe - Builds CPE string from resolved vendor/product
- Node 5: clean_version - Strips version suffixes
- Node 6: update_component - Stores enriched metadata in database

Cascading Fallback (1,2,3):
1. PURL parsing → if successful, skip to CPE construction
2. Cache lookup → if hit, skip to CPE construction
3. LLM resolution → if fails, fallback to existing CPE
4. Normalizer fallback → if fails, use ComponentNormalizer
5. Never skip component
"""

from typing import TypedDict, Optional
import logging

logger = logging.getLogger(__name__)


class ComponentEnrichmentState(TypedDict):
    """State for component enrichment workflow."""
    component_id: int
    name: str
    version: str
    purl: Optional[str]
    supplier: Optional[str]
    ecosystem: Optional[str]
    nvd_vendor: Optional[str]
    nvd_product: Optional[str]
    search_name: Optional[str]
    clean_version: Optional[str]
    constructed_cpe: Optional[str]
    enrichment_method: Optional[str]
    confidence: int
    error: Optional[str]
    fallback_stage: Optional[str]


class ComponentEnrichmentAgent:
    """
    LangGraph-based agent for enriching SBOM components with NVD metadata.
    """
    
    def __init__(self, db_session, ollama_url="http://localhost:11434", model="qwen2.5:7b"):
        self.db = db_session
        self.ollama_url = ollama_url
        self.model = model
        logger.info("ComponentEnrichmentAgent initialized")
    
    async def enrich_component(self, component_id: int) -> dict:
        """Enrich a single component with NVD metadata."""
        from app.models.component import Component
        
        component = self.db.query(Component).filter(Component.id == component_id).first()
        if not component:
            return {"error": "Component not found", "component_id": component_id}
        
        # Run the enrichment pipeline
        try:
            result = await self._enrich_pipeline(component)
            return result
        except Exception as e:
            logger.error(f"Error enriching component {component_id}: {e}")
            return {"error": str(e), "component_id": component_id}
    
    async def _enrich_pipeline(self, component) -> dict:
        """Run the enrichment pipeline for a component."""
        state = {
            "component_id": component.id,
            "name": component.name,
            "version": component.version,
            "purl": component.purl,
            "supplier": component.supplier,
            "ecosystem": None,
            "nvd_vendor": None,
            "nvd_product": None,
            "search_name": None,
            "clean_version": None,
            "constructed_cpe": None,
            "enrichment_method": None,
            "confidence": 0,
            "error": None,
            "fallback_stage": None
        }
        
        # Step 1: Parse PURL
        state = await self.parse_purl(state)
        
        # Step 2: Check cache
        if not state.get("error"):
            state = await self.check_cache(state)
        
        # Step 3: LLM resolve if cache miss
        if not state.get("error") and state.get("cache_miss"):
            state = await self.llm_resolve(state)
        
        # Step 4: Construct CPE
        if not state.get("error") and state.get("nvd_vendor"):
            state = await self.construct_cpe(state)
        
        # Step 5: Fallback chain if errors
        if state.get("error"):
            state = await self.fallback_1(state)
            if state.get("error"):
                state = await self.fallback_2(state)
                if state.get("error"):
                    state = await self.fallback_3(state)
        
        # Step 6: Update component
        state = await self.update_component(state)
        
        return state
    
    # ──────────────────────────────────────────────────────────────
    #  Node implementations
    # ──────────────────────────────────────────────────────────────
    
    async def parse_purl(self, state: dict) -> dict:
        """Node 1: Parse PURL to extract ecosystem and basic metadata."""
        logger.info(f"[parse_purl] Processing component {state['name']}")
        
        if not state.get("purl"):
            state["error"] = "No PURL available"
            return state
        
        try:
            purl = state["purl"]
            if not purl.startswith("pkg:"):
                state["error"] = "Invalid PURL format"
                return state
            
            # Parse PURL
            remainder = purl[4:]  # Remove "pkg:"
            slash_idx = remainder.index("/")
            purl_type = remainder[:slash_idx].lower()
            
            state["ecosystem"] = purl_type
            state["enrichment_method"] = "purl_only"
            state["confidence"] = 80
            
            logger.info(f"[parse_purl] Parsed ecosystem: {purl_type}")
            return state
            
        except Exception as e:
            logger.error(f"[parse_purl] Error: {e}")
            state["error"] = str(e)
            return state
    
    async def check_cache(self, state: dict) -> dict:
        """Node 2: Check vendor/product cache."""
        logger.info(f"[check_cache] Checking cache for {state['name']}")
        
        from app.models.vendor_cache import VendorProductCache
        from sqlalchemy.sql import func
        
        # Check database cache
        cache_entry = self.db.query(VendorProductCache).filter(
            VendorProductCache.component_name == state["name"]
        ).first()
        
        if cache_entry:
            state["nvd_vendor"] = cache_entry.nvd_vendor
            state["nvd_product"] = cache_entry.nvd_product
            state["enrichment_method"] = "purl_cache"
            state["confidence"] = cache_entry.confidence
            
            # Update hit count
            cache_entry.hit_count += 1
            cache_entry.last_used_at = func.now()
            self.db.commit()
            
            logger.info(f"[check_cache] Cache hit: {cache_entry.nvd_vendor}/{cache_entry.nvd_product}")
            return state
        else:
            logger.info(f"[check_cache] Cache miss")
            state["cache_miss"] = True
            return state
    
    async def llm_resolve(self, state: dict) -> dict:
        """Node 3: Use LLM to resolve vendor/product."""
        logger.info(f"[llm_resolve] Using LLM for {state['name']}")
        
        import httpx
        import json
        import re
        
        prompt = f"""
Analyze this software component and determine the correct NVD (National Vulnerability Database) vendor and product names.

Component Name: {state['name']}
Component Version: {state['version']}
PURL: {state.get('purl', 'N/A')}
Ecosystem: {state.get('ecosystem', 'N/A')}
Supplier: {state.get('supplier', 'N/A')}

Return JSON:
{{
    "nvd_vendor": "vendor name",
    "nvd_product": "product name",
    "confidence": 0-100,
    "reasoning": "explanation"
}}

Important:
- Use the actual NVD vendor/product names as they appear in NVD CPE strings
- For npm packages, vendor is often "nodejs" or the organization name
- For Python packages, vendor is often "python" or the organization name
- For Java packages, vendor is often "apache", "oracle", "eclipse", etc.
- Be specific and accurate
"""
        
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(
                    f"{self.ollama_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json"
                    }
                )
                response.raise_for_status()
                result = response.json()
                
                llm_output = result.get("response", "")
                
                # Parse JSON from LLM output
                parsed = json.loads(llm_output)
                
                state["nvd_vendor"] = parsed.get("nvd_vendor")
                state["nvd_product"] = parsed.get("nvd_product")
                state["confidence"] = parsed.get("confidence", 70)
                state["enrichment_method"] = "llm"
                
                # Cache the result
                self._cache_result(state)
                
                logger.info(f"[llm_resolve] LLM resolved: {state['nvd_vendor']}/{state['nvd_product']}")
                return state
                
        except Exception as e:
            logger.error(f"[llm_resolve] Error: {e}")
            state["error"] = str(e)
            return state
    
    async def construct_cpe(self, state: dict) -> dict:
        """Node 4: Construct CPE string from resolved vendor/product."""
        logger.info(f"[construct_cpe] Building CPE for {state['name']}")
        
        if not state.get("nvd_vendor") or not state.get("nvd_product"):
            state["error"] = "Missing vendor or product for CPE construction"
            return state
        
        try:
            # Clean version
            clean_ver = self._clean_version_string(state["version"])
            state["clean_version"] = clean_ver
            
            # Construct CPE
            cpe = f"cpe:2.3:a:{state['nvd_vendor']}:{state['nvd_product']}:{clean_ver}:*:*:*:*:*:*:*"
            state["constructed_cpe"] = cpe
            
            # Generate search name (for keyword fallback)
            state["search_name"] = state["nvd_product"]
            
            logger.info(f"[construct_cpe] Built CPE: {cpe}")
            return state
            
        except Exception as e:
            logger.error(f"[construct_cpe] Error: {e}")
            state["error"] = str(e)
            return state
    
    async def update_component(self, state: dict) -> dict:
        """Node 6: Update component in database with enriched metadata."""
        logger.info(f"[update_component] Updating component {state['component_id']}")
        
        from app.models.component import Component
        
        try:
            component = self.db.query(Component).filter(Component.id == state["component_id"]).first()
            if not component:
                state["error"] = "Component not found"
                return state
            
            # Update fields
            component.nvd_vendor = state.get("nvd_vendor")
            component.nvd_product = state.get("nvd_product")
            component.search_name = state.get("search_name")
            component.clean_version = state.get("clean_version")
            component.constructed_cpe = state.get("constructed_cpe")
            component.ecosystem = state.get("ecosystem")
            component.enrichment_status = "completed"
            component.enrichment_confidence = state.get("confidence")
            component.enrichment_method = state.get("enrichment_method")
            
            self.db.commit()
            
            logger.info(f"[update_component] Component {state['component_id']} enriched successfully")
            return state
            
        except Exception as e:
            logger.error(f"[update_component] Error: {e}")
            state["error"] = str(e)
            return state
    
    async def fallback_1(self, state: dict) -> dict:
        """Fallback 1: Use existing CPE from component."""
        logger.info(f"[fallback_1] Using existing CPE for {state['name']}")
        
        from app.models.component import Component
        
        component = self.db.query(Component).filter(Component.id == state["component_id"]).first()
        if component and component.cpe:
            try:
                parts = component.cpe.split(":")
                if len(parts) >= 5:
                    state["nvd_vendor"] = parts[3]
                    state["nvd_product"] = parts[4]
                    state["constructed_cpe"] = component.cpe
                    state["enrichment_method"] = "fallback_1"
                    state["confidence"] = 60
                    return state
            except:
                pass
        
        state["error"] = "Fallback 1 failed"
        return state
    
    async def fallback_2(self, state: dict) -> dict:
        """Fallback 2: Use ComponentNormalizer."""
        logger.info(f"[fallback_2] Using ComponentNormalizer for {state['name']}")
        
        from app.agent.normalizer.normalizer import component_normalizer
        from app.models.component import Component
        
        try:
            component = self.db.query(Component).filter(Component.id == state["component_id"]).first()
            if component:
                normalized_name, _, _ = component_normalizer.normalize_component(component, self.db)
                state["search_name"] = normalized_name
                state["enrichment_method"] = "fallback_2"
                state["confidence"] = 40
                return state
        except Exception as e:
            logger.error(f"[fallback_2] Error: {e}")
        
        state["error"] = "Fallback 2 failed"
        return state
    
    async def fallback_3(self, state: dict) -> dict:
        """Fallback 3: Use basic name as search_name (never skip component)."""
        logger.info(f"[fallback_3] Using basic name for {state['name']}")
        
        state["search_name"] = state["name"]
        state["enrichment_method"] = "fallback_3"
        state["confidence"] = 20
        state["enrichment_status"] = "completed"
        
        # Try to construct a basic CPE using the static CPE vendor map
        from app.services.cpe_vendor_map import CPE_VENDOR_MAP
        
        component_name = state["name"]
        if component_name in CPE_VENDOR_MAP:
            vendor, product = CPE_VENDOR_MAP[component_name]
            clean_ver = self._clean_version_string(state["version"])
            cpe = f"cpe:2.3:a:{vendor}:{product}:{clean_ver}:*:*:*:*:*:*:*"
            state["nvd_vendor"] = vendor
            state["nvd_product"] = product
            state["constructed_cpe"] = cpe
            state["confidence"] = 30  # Higher confidence since we used the map
            logger.info(f"[fallback_3] Found in CPE_VENDOR_MAP: {vendor}/{product}")
        
        return state
    
    def _clean_version_string(self, version: str) -> str:
        """Clean version string for CPE format."""
        if not version:
            return "*"
        
        cleaned = version
        
        # Remove 'v' prefix
        if cleaned.startswith("v"):
            cleaned = cleaned[1:]
        
        # Remove Alpine suffix (-rX)
        import re
        cleaned = re.sub(r'-r\d+$', '', cleaned)
        
        # Remove git suffixes
        cleaned = re.sub(r'_git[a-f0-9]+$', '', cleaned)
        
        # Remove Debian epoch
        cleaned = re.sub(r'^\d+:', '', cleaned)
        
        # Remove Debian revision
        cleaned = re.sub(r'-\d+$', '', cleaned)
        
        # Remove RC/beta/alpha
        cleaned = re.sub(r'[-.]?(rc|alpha|beta|dev|pre|snapshot)[\d.]*$', '', cleaned, flags=re.IGNORECASE)
        
        if not cleaned:
            return "*"
        
        return cleaned
    
    def _cache_result(self, state: dict):
        """Cache the enrichment result in database."""
        from app.models.vendor_cache import VendorProductCache
        from sqlalchemy.sql import func
        
        cache_entry = VendorProductCache(
            component_name=state["name"],
            nvd_vendor=state["nvd_vendor"],
            nvd_product=state["nvd_product"],
            ecosystem=state.get("ecosystem"),
            confidence=state["confidence"],
            resolution_method="llm",
            source_purl=state.get("purl"),
            hit_count=1
        )
        
        self.db.add(cache_entry)
        self.db.commit()
