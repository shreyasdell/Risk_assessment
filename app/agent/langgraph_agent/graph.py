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

from app.core.config import settings

logger = logging.getLogger(__name__)


class ComponentEnrichmentState(TypedDict):
    """State for component enrichment workflow."""
    component_id: int
    name: str
    version: str
    purl: Optional[str]
    supplier: Optional[str]
    ecosystem: Optional[str]
    purl_type: Optional[str]
    purl_namespace: Optional[str]
    purl_name: Optional[str]
    nvd_vendor: Optional[str]
    nvd_product: Optional[str]
    search_name: Optional[str]
    clean_version: Optional[str]
    constructed_cpe: Optional[str]
    enrichment_method: Optional[str]
    confidence: int
    error: Optional[str]
    fallback_stage: Optional[str]
    cache_miss: Optional[bool]
    validated: Optional[bool]
    validation_status: Optional[str]
    validation_error: Optional[str]


class ComponentEnrichmentAgent:
    """
    LangGraph-based agent for enriching SBOM components with NVD metadata.
    """
    
    # In-memory cache (simple dict for now, could use LRU cache)
    _memory_cache = {}
    
    def __init__(self, db_session, ollama_url=None, model=None, ollama_timeout=None):
        self.db = db_session
        self.ollama_url = ollama_url or settings.OLLAMA_URL
        self.model = model or settings.OLLAMA_MODEL
        self.ollama_timeout = ollama_timeout or settings.OLLAMA_TIMEOUT
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
            "purl_type": None,
            "purl_namespace": None,
            "purl_name": None,
            "nvd_vendor": None,
            "nvd_product": None,
            "search_name": None,
            "clean_version": None,
            "constructed_cpe": None,
            "enrichment_method": None,
            "confidence": 0,
            "error": None,
            "fallback_stage": None,
            "cache_miss": None,
            "validated": None,
            "validation_status": None,
            "validation_error": None
        }
        
        # Step 1: Parse PURL
        state = await self.parse_purl(state)
        
        # Step 2: Check cache
        if not state.get("error"):
            state = await self.check_cache(state)
        
        # Step 3: LLM resolve if cache miss
        if not state.get("error") and state.get("cache_miss"):
            state = await self.llm_resolve(state)
            if not state.get("error"):
                # Validate LLM result
                state = await self.validate_vendor_product(state)
                # Only cache if validated
                if state.get("validated"):
                    self._cache_result(state)
                else:
                    logger.warning(f"[enrich_pipeline] LLM result not validated, skipping cache")
            
            # Run fallbacks if confidence is too low (configurable, default 60)
            if not state.get("error") and state.get("confidence", 0) < 60:
                logger.warning(f"[enrich_pipeline] Confidence {state.get('confidence')} below threshold 60, running fallbacks")
                state = await self.fallback_1(state)
                if state.get("error"):
                    state = await self.fallback_2(state)
                    if state.get("error"):
                        state = await self.fallback_3(state)
        
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
        """Node 1: Parse PURL to extract ecosystem, namespace, and name per PURL spec."""
        logger.info(f"[parse_purl] Processing PURL: {state.get('purl')}")
        
        if not state.get("purl"):
            state["error"] = "No PURL available"
            return state
        
        try:
            purl = state["purl"]
            if not purl.startswith("pkg:"):
                state["error"] = "Invalid PURL format: must start with pkg:"
                return state
            
            # Remove "pkg:" prefix
            remainder = purl[4:]
            
            # Split at @ to separate package part from version
            if "@" in remainder:
                package_part, version_part = remainder.split("@", 1)
            else:
                package_part = remainder
                version_part = ""
            
            # Remove qualifiers and subpath
            if "?" in package_part:
                package_part = package_part.split("?")[0]
            if "#" in package_part:
                package_part = package_part.split("#")[0]
            
            # Split package part into type, namespace, name
            parts = package_part.split("/")
            
            if len(parts) < 2:
                state["error"] = f"Invalid PURL: expected at least type/name, got {package_part}"
                return state
            
            # Extract type
            purl_type = parts[0].lower()
            state["purl_type"] = purl_type
            state["ecosystem"] = purl_type
            
            # Extract namespace (if present)
            if len(parts) >= 3:
                # URL-decode namespace
                from urllib.parse import unquote
                # Namespace is everything between type and the last part
                purl_namespace = unquote("/".join(parts[1:-1]))
                state["purl_namespace"] = purl_namespace
                # Name is the last part
                purl_name = parts[-1]
                state["purl_name"] = purl_name
            else:
                # No namespace, name is the second part
                state["purl_namespace"] = None
                state["purl_name"] = parts[1]
            
            state["enrichment_method"] = "purl_only"
            state["confidence"] = 80
            
            logger.info(f"[parse_purl] Parsed: type={purl_type}, namespace={state.get('purl_namespace')}, name={state.get('purl_name')}")
            return state
            
        except Exception as e:
            logger.error(f"[parse_purl] Error: {e}")
            state["error"] = str(e)
            return state
    
    async def check_cache(self, state: dict) -> dict:
        """Node 2: Check vendor/product cache (in-memory + database)."""
        logger.info(f"[check_cache] Checking cache for {state['name']}")
        
        from app.models.vendor_cache import VendorProductCache
        from sqlalchemy.sql import func
        
        # Build cache key from PURL fields
        cache_key = None
        if state.get("purl_type") and state.get("purl_name"):
            cache_key = f"{state['purl_type']}:{state.get('purl_namespace', '')}:{state['purl_name']}"
        else:
            # Fallback to component name if PURL fields not available
            cache_key = state["name"]
        
        logger.info(f"[check_cache] Cache key: {cache_key}")
        
        # Check in-memory cache first
        if cache_key in self._memory_cache:
            cached = self._memory_cache[cache_key]
            state["nvd_vendor"] = cached["nvd_vendor"]
            state["nvd_product"] = cached["nvd_product"]
            state["enrichment_method"] = "memory_cache"
            state["confidence"] = cached["confidence"]
            logger.info(f"[check_cache] Memory cache hit: {cached['nvd_vendor']}/{cached['nvd_product']}")
            return state
        
        # Check database cache
        cache_entry = self.db.query(VendorProductCache).filter(
            VendorProductCache.component_name == cache_key
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
            
            # Store in memory cache
            self._memory_cache[cache_key] = {
                "nvd_vendor": cache_entry.nvd_vendor,
                "nvd_product": cache_entry.nvd_product,
                "confidence": cache_entry.confidence
            }
            
            logger.info(f"[check_cache] Database cache hit: {cache_entry.nvd_vendor}/{cache_entry.nvd_product}")
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
            async with httpx.AsyncClient(timeout=self.ollama_timeout) as client:
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
                # Cap LLM confidence at 75
                llm_confidence = parsed.get("confidence", 70)
                state["confidence"] = min(llm_confidence, 75)
                state["enrichment_method"] = "llm"
                
                # Cache the result (will be re-cached after validation)
                # self._cache_result(state)  # Moved to after validation
                
                logger.info(f"[llm_resolve] LLM resolved: {state['nvd_vendor']}/{state['nvd_product']}")
                return state
                
        except Exception as e:
            logger.error(f"[llm_resolve] Error: {e}")
            state["error"] = str(e)
            return state
    
    async def validate_vendor_product(self, state: dict) -> dict:
        """Node 3.5: Validate LLM vendor/product against NVD CPE dictionary."""
        logger.info(f"[validate] Checking NVD CPE dictionary for {state.get('nvd_vendor')}/{state.get('nvd_product')}")
        
        import httpx
        
        nvd_vendor = state.get("nvd_vendor")
        nvd_product = state.get("nvd_product")
        
        if not nvd_vendor or not nvd_product:
            state["validation_status"] = "missing_data"
            state["validated"] = False
            return state
        
        try:
            # Query NVD CPE dictionary API
            cpe_string = f"cpe:2.3:a:{nvd_vendor}:{nvd_product}:*:*:*:*:*:*:*:*"
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cpes/2.0",
                    params={"cpeMatchString": cpe_string, "resultsPerPage": 1}
                )
                response.raise_for_status()
                data = response.json()
                
                # Check if any CPEs match
                total_results = data.get("totalResults", 0)
                if total_results > 0:
                    state["validation_status"] = "validated"
                    state["validated"] = True
                    state["confidence"] = 90  # Raise confidence for validated pairs
                    logger.info(f"[validate] VALIDATED: {nvd_vendor}/{nvd_product} exists in NVD CPE dictionary")
                else:
                    state["validation_status"] = "not_found"
                    state["validated"] = False
                    state["enrichment_status"] = "unvalidated"
                    logger.warning(f"[validate] NOT VALIDATED: {nvd_vendor}/{nvd_product} not found in NVD CPE dictionary")
                
                return state
                
        except Exception as e:
            logger.error(f"[validate] Error checking NVD CPE dictionary: {e}")
            state["validation_status"] = "error"
            state["validated"] = False
            state["validation_error"] = str(e)
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
            component.purl_type = state.get("purl_type")
            component.purl_namespace = state.get("purl_namespace")
            component.purl_name = state.get("purl_name")
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
