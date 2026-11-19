"""
NVD API v2.0 Client - TWO-PHASE APPROACH

Phase 1: Discovery (NVD keyword search) - get CVE IDs only
Phase 2: Verification (CVE.org API) - precise check of each CVE

This solves the problem where NVD lacks CPE data for many CVEs.
Instead of relying on NVD's incomplete data, we use NVD only for
discovery (fast keyword search), then verify each CVE with CVE.org
which has complete CPE and version range data.
"""

import httpx
import asyncio
import re
import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Tuple
from sqlalchemy.orm import Session

from app.models.cve import CVE
from app.models.component import Component
from app.agent.cve_filter_agent import CVEFilterAgent
from app.core.config import settings
from app.services.cve_org_service import cve_org_client
from app.services.cve_cache_service import CVECacheService
from app.agent.normalizer.normalizer import component_normalizer
from app.services.cpe_vendor_map import CPE_VENDOR_MAP


class NVDService:

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        self.api_key = settings.NVD_API_KEY
        self.headers = {}
        if self.api_key:
            self.headers["apiKey"] = self.api_key

        self.request_times: List[datetime] = []
        self.max_requests = 50 if self.api_key else 5
        self.rate_window = 30

        # Initialize CVE Filter Agent
        self.cve_agent = CVEFilterAgent(
            ollama_url=settings.OLLAMA_URL,
            model=settings.OLLAMA_MODEL,
            ollama_timeout=settings.OLLAMA_TIMEOUT,
            display_threshold=settings.CVE_DISPLAY_THRESHOLD,
        )

        # Initialize CVE Cache Service
        self.cache_service = CVECacheService(cve_org_client)

    async def _rate_limit(self):
        """Wait if we are about to exceed NVD rate limits."""
        now = datetime.utcnow()
        self.request_times = [
            t for t in self.request_times
            if (now - t).total_seconds() < self.rate_window
        ]

        if len(self.request_times) >= self.max_requests:
            oldest = self.request_times[0]
            wait_time = (
                self.rate_window
                - (now - oldest).total_seconds()
                + 1
            )
            if wait_time > 0:
                print(
                    f"[NVD] Rate limit. "
                    f"Waiting {wait_time:.0f}s..."
                )
                await asyncio.sleep(wait_time)

        self.request_times.append(datetime.utcnow())

    def _clean_component_name(self, name: str) -> str:
        """
        Clean component name for better NVD matching.

        Examples:
          'log4j-core'      -> 'log4j'
          'jackson-databind' -> 'jackson-databind'
          'spring-boot'     -> 'spring boot'
          'commons-text'    -> 'commons-text'
        """
        # Remove common suffixes that NVD might not use
        cleaned = name.lower().strip()
        return cleaned

    def _build_cpe(self, component_name: str, component_version: str, purl: str = None) -> Optional[str]:
        """
        Build a correct NVD CPE string using known vendor mappings.
        
        Args:
            component_name: Display name (e.g., "guzzlehttp/psr7")
            component_version: Cleaned version (e.g., "1.9.0")
            purl: Package URL for additional context
        
        Returns:
            CPE string like "cpe:2.3:a:guzzlephp:psr7:1.9.0:*:*:*:*:*:*:*"
            or None if no mapping exists
        
        Logic:
        1. Extract package name from display_name (after "/" if present)
        2. Look up in CPE_VENDOR_MAP
        3. If found, construct CPE with correct vendor
        4. If not found, try extracting from PURL namespace
        5. Clean version (remove -r0, v prefix, etc.)
        6. Return formatted CPE string
        """
        # Extract package name (after "/" if present)
        package_name = component_name
        if "/" in component_name:
            _, package_name = component_name.split("/", 1)
        
        # Look up in CPE vendor map
        if component_name in CPE_VENDOR_MAP:
            vendor, product = CPE_VENDOR_MAP[component_name]
        elif package_name in CPE_VENDOR_MAP:
            vendor, product = CPE_VENDOR_MAP[package_name]
        else:
            # Try to extract from PURL
            if purl:
                extracted = self._extract_vendor_from_purl(purl)
                if extracted:
                    vendor, product = extracted
                else:
                    return None
            else:
                return None
        
        # Clean version for CPE format
        cleaned_version = self._clean_version_for_cpe(component_version)
        
        # Construct CPE string
        # Format: cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        cpe = f"cpe:2.3:a:{vendor}:{product}:{cleaned_version}:*:*:*:*:*:*:*"
        
        return cpe

    def _extract_vendor_from_purl(self, purl: str) -> Optional[Tuple[str, str]]:
        """
        Try to extract NVD vendor/product from PURL.
        
        pkg:composer/guzzlehttp/guzzle@6.5.8 → check "guzzlehttp/guzzle" in map
        pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 → check "log4j-core" in map
        pkg:npm/%40angular/core@16.0.0 → check "angular" in map
        """
        if not purl:
            return None
        
        # Parse PURL
        parts = purl.split(":")
        if len(parts) < 3:
            return None
        
        purl_type = parts[0]
        namespace = parts[1] if len(parts) > 1 else ""
        name = parts[2] if len(parts) > 2 else ""
        
        # For npm scoped packages, remove @ from namespace
        if namespace.startswith("@"):
            namespace = namespace[1:]
        
        # Try different combinations
        combinations = [
            f"{namespace}/{name}",  # vendor/package
            name,  # just package name
            namespace,  # just namespace
        ]
        
        for combo in combinations:
            if combo in CPE_VENDOR_MAP:
                return CPE_VENDOR_MAP[combo]
        
        return None

    def _clean_version_for_cpe(self, version: str) -> str:
        """
        Clean version string for CPE format.
        
        Removes:
        - Alpine suffixes: 4.4.1-r2 → 4.4.1
        - Go prefixes: v1.2.3 → 1.2.3
        - Git suffixes: 13.2.1_git20231014 → 13.2.1
        - Debian epochs: 1:3.0.9-1 → 3.0.9
        """
        if not version:
            return "*"
        
        cleaned = version
        
        # Remove 'v' prefix (common in Go)
        if cleaned.startswith("v"):
            cleaned = cleaned[1:]
        
        # Remove Alpine suffix (-rX)
        cleaned = re.sub(r'-r\d+$', '', cleaned)
        
        # Remove git suffixes
        cleaned = re.sub(r'_git[a-f0-9]+$', '', cleaned)
        
        # Remove Debian epoch (X: prefix)
        cleaned = re.sub(r'^\d+:', '', cleaned)
        
        # Remove Debian revision (-X suffix)
        cleaned = re.sub(r'-\d+$', '', cleaned)
        
        # Remove RC/beta/alpha suffixes
        cleaned = re.sub(r'[-.]?(rc|alpha|beta|dev|pre|snapshot)[\d.]*$', '', cleaned, flags=re.IGNORECASE)
        
        # If empty after cleaning, use wildcard
        if not cleaned:
            return "*"
        
        return cleaned

    def _generate_search_queries(
        self,
        name: str,
        version: str = None
    ) -> List[Dict]:
        """
        Generate multiple search query strategies.
        We try them in order until one returns results.

        Why multiple strategies?
        NVD indexes things inconsistently:
        - "log4j" vs "log4j-core" vs "apache log4j"
        - "jackson-databind" vs "jackson databind"
        """
        queries = []
        clean_name = self._clean_component_name(name)

        # Fix 2: Add fallback search without vendor prefix for all components
        package_name = None
        if "/" in clean_name:
            _, package_name = clean_name.split("/", 1)

        # Strategy 1: Name + version, no exact match
        if version:
            queries.append({
                "keywordSearch": f"{clean_name} {version}",
                "resultsPerPage": 1000,
            })

        # Strategy 2: Just the name, no version
        queries.append({
            "keywordSearch": clean_name,
            "resultsPerPage": 1000,
        })

        # Fix 2: Strategy 3: Package name alone (without vendor prefix)
        if package_name and len(package_name) >= 4:
            # Avoid very generic names
            if package_name not in ["framework", "process", "common", "utils", "core", "base", "lib", "tool"]:
                queries.append({
                    "keywordSearch": package_name,
                    "resultsPerPage": 1000,
                })

        # Strategy 3: Try with common vendor prefixes
        vendor_prefixes = {
            "log4j": "apache log4j",
            "commons": "apache commons",
            "spring": "spring framework",
            "jackson": "fasterxml jackson",
            "openssl": "openssl",
            "tomcat": "apache tomcat",
            "struts": "apache struts",
            "nginx": "nginx",
            "jquery": "jquery",
        }

        for prefix, expanded in vendor_prefixes.items():
            if prefix in clean_name:
                if version:
                    queries.append({
                        "keywordSearch": f"{expanded} {version}",
                        "resultsPerPage": 1000,
                    })
                queries.append({
                    "keywordSearch": expanded,
                    "resultsPerPage": 1000,
                })
                break

        return queries

    def _fetch_cve_from_nvd_sync(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch a single CVE from NVD API to get CVSS data (synchronous).
        Returns parsed JSON or None on failure.
        """
        import requests
        import time

        # Simple rate limiting for sync calls
        time.sleep(0.6)  # NVD rate limit: ~6 requests per 10 seconds

        try:
            # Correct NVD API endpoint uses query parameter
            url = f"{self.BASE_URL}?cveId={cve_id}"
            print(f"[NVD] Fetching CVSS from NVD for {cve_id}")

            response = requests.get(
                url,
                headers=self.headers,
                timeout=30.0
            )

            if response.status_code == 200:
                data = response.json()
                # NVD returns data in a "vulnerabilities" array
                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    # Extract the CVE data from the response
                    # The format is: vulnerabilities[0].cve
                    cve_data = vulnerabilities[0].get("cve", {})
                    return cve_data
                return None

            elif response.status_code == 403:
                print(f"[NVD] 403 Forbidden for {cve_id}")
                return None

            elif response.status_code == 404:
                print(f"[NVD] 404 Not Found for {cve_id}")
                return None

            else:
                print(f"[NVD] Error fetching {cve_id}: {response.status_code}")
                return None

        except Exception as e:
            print(f"[NVD] Exception fetching {cve_id}: {e}")
            return None

    async def _make_request(
        self,
        params: Dict
    ) -> Optional[Dict]:
        """
        Make a single request to NVD API with error handling.
        Returns parsed JSON or None on failure.
        """
        await self._rate_limit()

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                print(
                    f"[NVD] Searching: "
                    f"{params.get('keywordSearch', '')} "
                    f"| CPE: {params.get('cpeName', 'none')}"
                )

                response = await client.get(
                    self.BASE_URL,
                    params=params,
                    headers=self.headers
                )

                if response.status_code == 200:
                    data = response.json()
                    total = data.get("totalResults", 0)
                    print(f"[NVD] Found {total} results")
                    return data

                elif response.status_code == 403:
                    print(
                        "[NVD] 403 Forbidden — "
                        "check your API key"
                    )
                    return None

                elif response.status_code == 429:
                    print("[NVD] 429 Rate Limited — waiting 35s")
                    await asyncio.sleep(35)

                    response = await client.get(
                        self.BASE_URL,
                        params=params,
                        headers=self.headers
                    )
                    if response.status_code == 200:
                        return response.json()
                    return None

                elif response.status_code == 404:
                    print("[NVD] 404 Not Found")
                    return None

                else:
                    print(
                        f"[NVD] HTTP {response.status_code}: "
                        f"{response.text[:200]}"
                    )
                    return None

        except httpx.TimeoutException:
            print("[NVD] Request timed out (30s)")
            return None
        except httpx.ConnectError:
            print("[NVD] Cannot connect to NVD API")
            return None
        except Exception as e:
            print(f"[NVD] Unexpected error: {e}")
            return None

    async def fetch_cves_for_component(
        self,
        component_name: str,
        component_version: str = None,
        cpe: str = None
    ) -> List[Dict]:
        """
        Search NVD for CVEs affecting a component.

        Search strategy (in order):
        1. CPE string (most accurate, if available)
        2. Name + version keyword search
        3. Name-only keyword search
        4. Expanded name keyword search

        Stops at the first strategy that returns results.
        """

        # Strategy 0: Use CPE if available
        if cpe:
            print(f"[NVD] Trying CPE: {cpe}")
            data = await self._make_request({
                "cpeName": cpe,
                "resultsPerPage": 100,
            })
            if data:
                results = self._parse_nvd_response(data)
                if results:
                    return self._filter_by_version(
                        results, component_version
                    )

        # Generate and try multiple keyword strategies
        queries = self._generate_search_queries(
            component_name, component_version
        )

        for query_params in queries:
            data = await self._make_request(query_params)

            if data and data.get("totalResults", 0) > 0:
                results = self._parse_nvd_response(data)

                if results:
                    # Filter results to improve relevance
                    filtered = self._filter_relevant_cves(
                        results,
                        component_name,
                        component_version
                    )

                    if filtered:
                        print(
                            f"[NVD] Returning {len(filtered)} "
                            f"relevant CVEs"
                        )
                        return filtered

        print(
            f"[NVD] No CVEs found for "
            f"{component_name} {component_version or ''}"
        )
        return []

    async def discover_cve_ids(
        self,
        component_name: str,
        component_version: str = None,
        purl: str = None,
        constructed_cpe: str = None,
        search_name: str = None
    ) -> List[str]:
        """
        Phase 1: Discovery - Get CVE IDs from NVD keyword search.

        This is fast and returns only CVE IDs (candidate CVEs).
        Verification happens in Phase 2 via CVE.org.

        Args:
            component_name: Component name
            component_version: Optional version
            purl: Optional Package URL for CPE construction
            constructed_cpe: Pre-constructed CPE from LangGraph agent (NEW)
            search_name: Pre-computed search name from LangGraph agent (NEW)

        Returns:
            List of CVE IDs (e.g., ["CVE-2024-12345", "CVE-2023-67890"])
        """
        cve_ids = set()
        
        # Strategy 0: Use pre-constructed CPE from LangGraph agent (MOST ACCURATE)
        if constructed_cpe:
            print(f"[NVD] Using agent-constructed CPE: {constructed_cpe}")
            data = await self._make_request({
                "cpeName": constructed_cpe,
                "resultsPerPage": 100,
            })
            if data and data.get("totalResults", 0) > 0:
                for vuln in data.get("vulnerabilities", []):
                    cve_id = vuln.get("cve", {}).get("id", "")
                    if cve_id:
                        cve_ids.add(cve_id)
                print(f"[NVD] CPE search found {len(cve_ids)} CVEs")
        
        # Strategy 1: Use pre-computed search name from LangGraph agent
        if search_name and not cve_ids:
            print(f"[NVD] Using agent search name: {search_name}")
            data = await self._make_request({
                "keywordSearch": search_name,
                "resultsPerPage": 100,
            })
            if data and data.get("totalResults", 0) > 0:
                vulnerabilities = data.get("vulnerabilities", [])
                total = data.get("totalResults", 0)
                
                # If total > 500, skip and mark as needs CPE
                if total > 500:
                    print(f"[NVD] Too many results ({total}), skipping keyword search")
                    print(f"[NVD] Component needs CPE instead of keyword search")
                    # Don't add any CVEs from this search
                else:
                    # Sort by published date descending (most recent first)
                    vulnerabilities.sort(
                        key=lambda v: v.get("cve", {}).get("published", ""),
                        reverse=True
                    )
                    if len(vulnerabilities) > 100:
                        print(f"[NVD] Too many results ({len(vulnerabilities)}), capping at 100")
                        vulnerabilities = vulnerabilities[:100]
                    for vuln in vulnerabilities:
                        cve = vuln.get("cve", {})
                        cve_id = cve.get("id", "")
                        if cve_id:
                            cve_ids.add(cve_id)
                    print(f"[NVD] Keyword search found {len(cve_ids)} CVEs")
        
        # Fallback: Original search strategies (only if agent data not available)
        if not constructed_cpe and not search_name:
            print(f"[NVD] No agent data, using fallback search")
            cpe = self._build_cpe(component_name, component_version, purl)
            if cpe:
                print(f"[NVD] Trying fallback CPE: {cpe}")
                data = await self._make_request({
                    "cpeName": cpe,
                    "resultsPerPage": 100,
                })
                if data and data.get("totalResults", 0) > 0:
                    for vuln in data.get("vulnerabilities", []):
                        cve_id = vuln.get("cve", {}).get("id", "")
                        if cve_id:
                            cve_ids.add(cve_id)
            
            queries = self._generate_search_queries(component_name, component_version)
            for query_params in queries:
                data = await self._make_request(query_params)
                if data and data.get("totalResults", 0) > 0:
                    vulnerabilities = data.get("vulnerabilities", [])
                    if len(vulnerabilities) > 100:
                        vulnerabilities = vulnerabilities[:100]
                    for vuln in vulnerabilities:
                        cve = vuln.get("cve", {})
                        cve_id = cve.get("id", "")
                        if cve_id:
                            cve_ids.add(cve_id)

        print(f"[NVD Discovery] Found {len(cve_ids)} CVE IDs for {component_name}")
        return list(cve_ids)

    def _filter_relevant_cves(
        self,
        cves: List[Dict],
        component_name: str,
        component_version: str = None
    ) -> List[Dict]:
        """
        Filter NVD results to only include CVEs that
        actually mention our component.

        Why?
        Keyword search can return unrelated results.
        e.g., searching "react" might return CVEs for
        "nuclear reactor" software.
        """
        clean_name = self._clean_component_name(component_name)
        name_parts = clean_name.replace("-", " ").split()

        relevant = []
        for cve in cves:
            desc = cve.get("description", "").lower()
            cve_id = cve.get("cve_id", "")

            # Check if description mentions the component
            # At least one significant part of the name
            # must appear
            name_found = False
            for part in name_parts:
                if len(part) >= 3 and part in desc:
                    name_found = True
                    break

            # Also check the CVE references (list of URLs)
            refs = cve.get("references", [])
            if not name_found and refs:
                if any(clean_name in ref.get("url", "").lower() for ref in refs):
                    name_found = True

            if name_found:
                relevant.append(cve)

        return relevant

    def _filter_by_version(
        self,
        cves: List[Dict],
        version: str = None
    ) -> List[Dict]:
        """
        When using CPE search, NVD already filters by
        version. This is a secondary check.
        """
        if not version:
            return cves
        return cves

    def _parse_nvd_response(
        self,
        data: Dict
    ) -> List[Dict]:
        """
        Parse NVD API v2.0 JSON into our database format.
        """
        cves = []
        vulnerabilities = data.get("vulnerabilities", [])

        for item in vulnerabilities:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "")

            if not cve_id:
                continue

            # Description (prefer English)
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            if not description:
                descs = cve_data.get("descriptions", [])
                if descs:
                    description = descs[0].get("value", "")

            # CVSS
            cvss_score, cvss_vector, severity = (
                self._extract_cvss(cve_data)
            )

            # CWE
            cwe_id = self._extract_cwe(cve_data)

            # Dates
            published_date = self._parse_date(
                cve_data.get("published")
            )
            modified_date = self._parse_date(
                cve_data.get("lastModified")
            )

            # References, exploits, patches
            references = cve_data.get("references", [])
            exploit_available = False
            patch_available = False
            reference_urls = []

            for ref in references:
                url = ref.get("url", "")
                tags = ref.get("tags", [])
                reference_urls.append(url)

                if "Exploit" in tags:
                    exploit_available = True
                if "Patch" in tags:
                    patch_available = True

            cves.append({
                "cve_id": cve_id,
                "description": description[:2000],
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "severity": severity.lower(),
                "cwe_id": cwe_id,
                "published_date": published_date,
                "modified_date": modified_date,
                "exploit_available": exploit_available,
                "patch_available": patch_available,
                "references": ", ".join(reference_urls[:10]),
                "nvd_url": (
                    f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                ),
            })

        return cves

    def _extract_cvss(
        self,
        cve_data: Dict
    ) -> Tuple[float, str, str]:
        """Extract CVSS score trying v4.0, v3.1, v3.0, v2 in order."""
        metrics = cve_data.get("metrics", {})

        # CVSS v4.0
        v40 = metrics.get("cvssMetricV40", [])
        if v40:
            cvss = v40[0].get("cvssData", {})
            score = cvss.get("baseScore", 0.0)
            severity = cvss.get("baseSeverity", "UNKNOWN")
            # Calculate severity from score if not provided
            if severity == "UNKNOWN":
                if score >= 9.0:
                    severity = "CRITICAL"
                elif score >= 7.0:
                    severity = "HIGH"
                elif score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            return (score, cvss.get("vectorString", ""), severity)

        # CVSS v3.1
        v31 = metrics.get("cvssMetricV31", [])
        if v31:
            cvss = v31[0].get("cvssData", {})
            score = cvss.get("baseScore", 0.0)
            severity = cvss.get("baseSeverity", "UNKNOWN")
            # Calculate severity from score if not provided
            if severity == "UNKNOWN":
                if score >= 9.0:
                    severity = "CRITICAL"
                elif score >= 7.0:
                    severity = "HIGH"
                elif score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            return (score, cvss.get("vectorString", ""), severity)

        # CVSS v3.0
        v30 = metrics.get("cvssMetricV30", [])
        if v30:
            cvss = v30[0].get("cvssData", {})
            score = cvss.get("baseScore", 0.0)
            severity = cvss.get("baseSeverity", "UNKNOWN")
            # Calculate severity from score if not provided
            if severity == "UNKNOWN":
                if score >= 9.0:
                    severity = "CRITICAL"
                elif score >= 7.0:
                    severity = "HIGH"
                elif score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            return (score, cvss.get("vectorString", ""), severity)

        # CVSS v2
        v2 = metrics.get("cvssMetricV2", [])
        if v2:
            cvss = v2[0].get("cvssData", {})
            score = cvss.get("baseScore", 0.0)
            if score >= 7.0:
                sev = "HIGH"
            elif score >= 4.0:
                sev = "MEDIUM"
            else:
                sev = "LOW"
            return (score, cvss.get("vectorString", ""), sev)

        return (0.0, "", "unknown")

    def _extract_references(
        self,
        cve_data: Dict
    ) -> List[Dict]:
        """Extract references from NVD data in the format expected by the frontend."""
        references = []
        for ref in cve_data.get("references", []):
            url = ref.get("url", "")
            tags = ref.get("tags", [])
            source = ref.get("source", "NVD")
            references.append({
                "url": url,
                "source": source,
                "tags": ", ".join(tags) if tags else ""
            })
        return references

    async def _fetch_cvss_from_mitre(self, cve_id: str) -> Tuple[float, str, str]:
        """Fetch CVSS score from MITRE CVE API as fallback when NVD shows N/A."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"https://cveawg.mitre.org/api/cve/{cve_id}",
                    headers={"Accept": "application/json"}
                )
                if response.status_code == 200:
                    data = response.json()
                    containers = data.get("containers", {})
                    cna = containers.get("cna", {})
                    metrics = cna.get("metrics", [])
                    
                    for metric in metrics:
                        # Try CVSS v4.0 first
                        cvss_v4 = metric.get("cvssV4_0", {})
                        if cvss_v4:
                            score = cvss_v4.get("baseScore", 0.0)
                            vector = cvss_v4.get("vectorString", "")
                            # CVSS v4.0 doesn't have baseSeverity, calculate from score
                            if score >= 9.0:
                                severity = "critical"
                            elif score >= 7.0:
                                severity = "high"
                            elif score >= 4.0:
                                severity = "medium"
                            else:
                                severity = "low"
                            return (score, vector, severity)
                        # Try CVSS v3.1
                        elif "cvssV3_1" in metric:
                            cvss = metric["cvssV3_1"]
                            score = cvss.get("baseScore", 0.0)
                            severity = cvss.get("baseSeverity", "UNKNOWN")
                            if severity == "UNKNOWN":
                                if score >= 9.0:
                                    severity = "CRITICAL"
                                elif score >= 7.0:
                                    severity = "HIGH"
                                elif score >= 4.0:
                                    severity = "MEDIUM"
                                else:
                                    severity = "LOW"
                            return (score, cvss.get("vectorString", ""), severity.lower())
                        # Try CVSS v3.0
                        elif "cvssV3_0" in metric:
                            cvss = metric["cvssV3_0"]
                            score = cvss.get("baseScore", 0.0)
                            severity = cvss.get("baseSeverity", "UNKNOWN")
                            if severity == "UNKNOWN":
                                if score >= 9.0:
                                    severity = "CRITICAL"
                                elif score >= 7.0:
                                    severity = "HIGH"
                                elif score >= 4.0:
                                    severity = "MEDIUM"
                                else:
                                    severity = "LOW"
                            return (score, cvss.get("vectorString", ""), severity.lower())
                        # Try CVSS v2.0
                        elif "cvssV2_0" in metric:
                            cvss = metric["cvssV2_0"]
                            score = cvss.get("baseScore", 0.0)
                            if score >= 7.0:
                                sev = "HIGH"
                            elif score >= 4.0:
                                sev = "MEDIUM"
                            else:
                                sev = "LOW"
                            return (score, cvss.get("vectorString", ""), sev.lower())
        except Exception as e:
            print(f"[MITRE] Error fetching CVSS for {cve_id}: {e}")
        
        return (0.0, "", "unknown")

    def _extract_cwe(self, cve_data: Dict) -> Optional[str]:
        """Extract primary CWE ID."""
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                value = desc.get("value", "")
                if value.startswith("CWE-"):
                    return value
        return None

    def _parse_date(
        self,
        date_str: Optional[str]
    ) -> Optional[datetime]:
        """Parse ISO date string from NVD."""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(
                date_str.replace("Z", "+00:00")
            )
        except (ValueError, TypeError):
            return None

    def sync_component_cves(
        self,
        db: Session,
        component: Component
    ) -> List[CVE]:
        """
        Main method called by the API endpoint.

        TWO-PHASE APPROACH:
        1. Phase 1: Discovery - Get CVE IDs from NVD keyword search (fast)
        2. Phase 2: Verification - Verify each CVE with CVE.org (precise) WITH CACHING
        3. Create or update CVE records with verification metadata
        4. Link CVEs to the component
        5. Return results
        """
        async def sync_cves_async():
            # Use enriched fields from LangGraph agent if available
            if component.constructed_cpe and component.search_name:
                # Component was enriched by LangGraph agent
                constructed_cpe = component.constructed_cpe
                search_name = component.search_name
                clean_version = component.clean_version or component_normalizer.clean_version(
                    component.version,
                    component.purl.split(":")[1].split("/")[0] if component.purl and ":" in component.purl else None
                )
                print(f"[NVD] Using LangGraph agent enriched data")
                print(f"[NVD] Constructed CPE: {constructed_cpe}")
                print(f"[NVD] Search name: {search_name}")
                print(f"[NVD] Clean version: {clean_version}")
            else:
                # Fallback to old ComponentNormalizer logic
                display_name = component.name
                if not component.normalized_name:
                    display_name, _, _ = component_normalizer.normalize_component(component, db)
                    if not display_name:
                        display_name = component.name
                else:
                    display_name = component.normalized_name

                search_name = component_normalizer.get_search_name(display_name)
                clean_version = component_normalizer.clean_version(
                    component.version,
                    component.purl.split(":")[1].split("/")[0] if component.purl and ":" in component.purl else None
                )
                constructed_cpe = None
                print(f"[NVD] No agent data, using fallback search")
                print(f"[NVD] Display name: {display_name}")
                print(f"[NVD] Search name: {search_name} (for NVD API)")
                print(f"[NVD] Cleaned version: {clean_version} (original: {component.version})")

            # Phase 1: Discover CVE IDs from NVD (now with LangGraph agent data)
            cve_ids = await self.discover_cve_ids(
                component_name=search_name,
                component_version=clean_version,
                purl=component.purl,
                constructed_cpe=constructed_cpe,
                search_name=search_name
            )
            
            # NEVER overwrite constructed_cpe set by LangGraph agent
            # Only set it if component doesn't have one AND agent didn't set one
            if not component.cpe and not component.constructed_cpe:
                constructed_cpe = self._build_cpe(search_name, clean_version, component.purl)
                if constructed_cpe:
                    component.cpe = constructed_cpe
                    db.commit()
                    print(f"[NVD] Stored constructed CPE: {constructed_cpe}")
            elif component.constructed_cpe:
                print(f"[NVD] Using agent-constructed CPE: {component.constructed_cpe}")

            if not cve_ids:
                print(f"[NVD Discovery] No CVE IDs found for {component.name} {component.version}")
                return []

            print(f"[CVE.org Verification] Verifying {len(cve_ids)} CVEs for {component.name} {component.version}")

            # Phase 2: Verify each CVE with CVE.org (PARALLEL + CACHING)
            cache_hits = 0
            cache_misses = 0

            async def verify_cve(cve_id):
                """Verify a single CVE with CVE.org using cache"""
                nonlocal cache_hits, cache_misses
                try:
                    # Use cache service - checks cache first, only calls API on miss
                    cve_data = await self.cache_service.get_affected_products(db, cve_id)

                    if not cve_data:
                        return None

                    if cve_data.get("from_cache"):
                        cache_hits += 1
                    else:
                        cache_misses += 1

                    affected_products = cve_data.get("affected_products", [])

                    # Run product + version matching (now async for LLM support)
                    is_affected, confidence, reason = await cve_org_client.is_component_affected(
                        {
                            "affected_products": affected_products,
                            "cve_id": cve_id,
                            "description": cve_data.get("parsed_data", {}).get("description", "")
                        },
                        component.name,
                        component.version,
                        component.purl
                    )

                    if is_affected and confidence >= 50:
                        print(
                            f"[CVE.org] {cve_id}: VERIFIED - {reason} "
                            f"(confidence: {confidence})"
                        )
                        # Get full CVE data for storage
                        parsed = cve_data.get("parsed_data", {})
                        return {
                            "cve_id": cve_id,
                            "confidence": confidence,
                            "reason": reason,
                            "parsed_data": parsed
                        }
                    else:
                        print(
                            f"[CVE.org] {cve_id}: REJECTED - {reason} "
                            f"(confidence: {confidence})"
                        )
                        return None
                except Exception as e:
                    print(f"[CVE.org] Error verifying {cve_id}: {e}")
                    return None

            async def verify_all_cves(cve_ids):
                """Verify all CVEs in parallel with concurrency limit"""
                semaphore = asyncio.Semaphore(10)  # Max 10 concurrent requests

                async def verify_with_semaphore(cve_id):
                    async with semaphore:
                        return await verify_cve(cve_id)

                tasks = [verify_with_semaphore(cve_id) for cve_id in cve_ids]
                results = await asyncio.gather(*tasks)
                return [r for r in results if r is not None]

            verified_cves = await verify_all_cves(cve_ids)

            print(
                f"[Cache] Stats: {cache_hits} hits, "
                f"{cache_misses} misses, "
                f"{len(verified_cves)} verified"
            )

            return verified_cves

        # Run the async sync operation
        verified_cves = asyncio.run(sync_cves_async())

        if not verified_cves:
            print(f"[CVE.org] No verified CVEs for {component.name} {component.version}")
            # Clear old CVE links even if no new CVEs are verified
            old_cve_count = len(component.cves)
            if old_cve_count > 0:
                component.cves.clear()
                db.commit()
                print(f"[NVD] Cleared {old_cve_count} old CVE links (no new CVEs verified)")
            return []

        print(f"[CVE.org] Verified {len(verified_cves)} CVEs for {component.name} {component.version}")

        # Clear old CVE-component links before adding new verified ones
        # This ensures stale/unverified CVEs from previous syncs are removed
        old_cve_count = len(component.cves)
        component.cves.clear()
        db.flush()  # Flush the clear operation
        print(f"[NVD] Cleared {old_cve_count} old CVE links for {component.name} {component.version}")

        # Save verified CVEs to database
        saved_cves = []
        for verified in verified_cves:
            parsed_data = verified["parsed_data"]
            cve_id = verified["cve_id"]
            confidence = verified["confidence"]
            reason = verified["reason"]

            # Check if CVE already exists
            existing = db.query(CVE).filter(CVE.cve_id == cve_id).first()

            if existing:
                # Update with latest data, but preserve description if CVE.org doesn't have one
                new_description = parsed_data.get("description", "")
                if not new_description:
                    # Keep existing description if CVE.org doesn't have one
                    new_description = existing.description

                existing.description = new_description

                # Use CVE.org CVSS if available (v4.0, v3.1, v3.0)
                cvss_score = parsed_data.get("cvss_score", 0.0)
                cvss_vector = parsed_data.get("cvss_vector", "")
                severity = parsed_data.get("severity", "unknown")
                
                # Only fallback to NVD if CVE.org has no CVSS at all (v4.0, v3.1, v3.0 all missing)
                if cvss_score == 0.0:
                    # CVE.org doesn't have CVSS, fetch from NVD
                    nvd_data = self._fetch_cve_from_nvd_sync(cve_id)
                    if nvd_data:
                        nvd_cvss_score, nvd_cvss_vector, nvd_severity = self._extract_cvss(nvd_data)
                        if nvd_cvss_score > 0.0:
                            cvss_score = nvd_cvss_score
                            cvss_vector = nvd_cvss_vector
                            severity = nvd_severity
                            print(f"[NVD] Fetched CVSS from NVD for {cve_id}: {cvss_score}")

                existing.cvss_score = cvss_score
                existing.cvss_vector = cvss_vector
                existing.severity = severity
                
                # CWE ID: use CVE.org if available, otherwise fetch from NVD
                cwe_id = parsed_data.get("cwe_id")
                if not cwe_id:
                    nvd_data = self._fetch_cve_from_nvd_sync(cve_id)
                    if nvd_data:
                        cwe_id = self._extract_cwe(nvd_data)
                        if cwe_id:
                            print(f"[NVD] Fetched CWE from NVD for {cve_id}: {cwe_id}")
                existing.cwe_id = cwe_id
                
                existing.published_date = self._parse_date(parsed_data.get("published_date"))
                existing.exploit_available = parsed_data.get("exploit_available", False)
                existing.patch_available = parsed_data.get("patch_available", False)
                existing.references = parsed_data.get("references", "")
                existing.nvd_url = parsed_data.get("nvd_url", "")

                # Fallback: if CVE.org has no references, fetch from NVD
                if not existing.references or existing.references == "[]":
                    nvd_data = self._fetch_cve_from_nvd_sync(cve_id)
                    if nvd_data:
                        nvd_references = self._extract_references(nvd_data)
                        if nvd_references:
                            existing.references = json.dumps(nvd_references)
                            print(f"[NVD] Fetched references from NVD for {cve_id}")

                # Update agent fields
                existing.agent_confidence = confidence
                existing.agent_verdict = "RELEVANT"
                existing.agent_reasoning = reason
                existing.match_method = "cve_org_verification"
                existing.stage_details = {"cve_org": {"verified": True, "confidence": confidence}}
                existing.agent_processing_time = 0.0
                existing.agent_processed_at = datetime.utcnow()

                cve_record = existing
            else:
                # Create new CVE record
                # Try to get description from NVD data if CVE.org doesn't have one
                nvd_description = ""
                if not parsed_data.get("description"):
                    # Look for NVD data in the verified record
                    nvd_data = verified.get("nvd_data", {})
                    if nvd_data:
                        nvd_description = nvd_data.get("description", "")

                description = parsed_data.get("description", "") or nvd_description

                # Use CVE.org CVSS if available (v4.0, v3.1, v3.0)
                cvss_score = parsed_data.get("cvss_score", 0.0)
                cvss_vector = parsed_data.get("cvss_vector", "")
                severity = parsed_data.get("severity", "unknown")
                
                # Only fallback to NVD if CVE.org has no CVSS at all (v4.0, v3.1, v3.0 all missing)
                if cvss_score == 0.0:
                    # CVE.org doesn't have CVSS, fetch from NVD
                    nvd_data = self._fetch_cve_from_nvd_sync(cve_id)
                    if nvd_data:
                        nvd_cvss_score, nvd_cvss_vector, nvd_severity = self._extract_cvss(nvd_data)
                        if nvd_cvss_score > 0.0:
                            cvss_score = nvd_cvss_score
                            cvss_vector = nvd_cvss_vector
                            severity = nvd_severity
                            print(f"[NVD] Fetched CVSS from NVD for {cve_id}: {cvss_score}")

                # Fallback: if CVE.org has no references, fetch from NVD
                references = parsed_data.get("references", "")
                if not references or references == "[]":
                    nvd_data = self._fetch_cve_from_nvd_sync(cve_id)
                    if nvd_data:
                        nvd_references = self._extract_references(nvd_data)
                        if nvd_references:
                            references = json.dumps(nvd_references)
                            print(f"[NVD] Fetched references from NVD for {cve_id}")

                # CWE ID: use CVE.org if available, otherwise fetch from NVD
                cwe_id = parsed_data.get("cwe_id")
                if not cwe_id:
                    nvd_data = self._fetch_cve_from_nvd_sync(cve_id)
                    if nvd_data:
                        cwe_id = self._extract_cwe(nvd_data)
                        if cwe_id:
                            print(f"[NVD] Fetched CWE from NVD for {cve_id}: {cwe_id}")

                cve_record = CVE(
                    cve_id=cve_id,
                    description=description,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    severity=severity,
                    cwe_id=cwe_id,
                    published_date=self._parse_date(parsed_data.get("published_date")),
                    exploit_available=parsed_data.get("exploit_available", False),
                    patch_available=parsed_data.get("patch_available", False),
                    references=references,
                    nvd_url=parsed_data.get("nvd_url", ""),
                    # Agent fields
                    agent_confidence=confidence,
                    agent_verdict="RELEVANT",
                    agent_reasoning=reason,
                    match_method="cve_org_verification",
                    stage_details={"cve_org": {"verified": True, "confidence": confidence}},
                    agent_processing_time=0.0,
                    agent_processed_at=datetime.utcnow(),
                )
                db.add(cve_record)

            # Link CVE to component if not already linked
            if cve_record not in component.cves:
                component.cves.append(cve_record)
                print(f"[NVD] Linked CVE {cve_id} to component {component.name} {component.version}")
            else:
                print(f"[NVD] CVE {cve_id} already linked to component {component.name} {component.version}")

            saved_cves.append(cve_record)

        db.flush()  # Ensure all pending changes are written
        db.commit()
        print(f"[NVD] Saved {len(saved_cves)} verified CVEs for {component.name} {component.version}")
        print(f"[NVD] Component now has {len(component.cves)} CVEs linked")
        return saved_cves


# Singleton
nvd_service = NVDService()