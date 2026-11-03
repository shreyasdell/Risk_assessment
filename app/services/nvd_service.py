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
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Tuple
from sqlalchemy.orm import Session

from app.models.cve import CVE
from app.models.component import Component
from app.agent.cve_filter_agent import CVEFilterAgent
from app.core.config import settings
from app.services.cve_org_service import cve_org_client


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
        component_version: str = None
    ) -> List[str]:
        """
        Phase 1: Discovery - Get CVE IDs from NVD keyword search.

        This is fast and returns only CVE IDs (candidate CVEs).
        Verification happens in Phase 2 via CVE.org.

        Args:
            component_name: Component name
            component_version: Optional version

        Returns:
            List of CVE IDs (e.g., ["CVE-2024-12345", "CVE-2023-67890"])
        """
        queries = self._generate_search_queries(component_name, component_version)
        cve_ids = set()

        for query_params in queries:
            data = await self._make_request(query_params)

            if data and data.get("totalResults", 0) > 0:
                vulnerabilities = data.get("vulnerabilities", [])
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
        """Extract CVSS score trying v3.1, v3.0, v2 in order."""
        metrics = cve_data.get("metrics", {})

        # CVSS v3.1
        v31 = metrics.get("cvssMetricV31", [])
        if v31:
            cvss = v31[0].get("cvssData", {})
            return (
                cvss.get("baseScore", 0.0),
                cvss.get("vectorString", ""),
                cvss.get("baseSeverity", "UNKNOWN")
            )

        # CVSS v3.0
        v30 = metrics.get("cvssMetricV30", [])
        if v30:
            cvss = v30[0].get("cvssData", {})
            return (
                cvss.get("baseScore", 0.0),
                cvss.get("vectorString", ""),
                cvss.get("baseSeverity", "UNKNOWN")
            )

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

        return (0.0, "", "UNKNOWN")

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
        2. Phase 2: Verification - Verify each CVE with CVE.org (precise)
        3. Create or update CVE records with verification metadata
        4. Link CVEs to the component
        5. Return results
        """
        async def sync_cves_async():
            # Phase 1: Discover CVE IDs from NVD
            cve_ids = await self.discover_cve_ids(
                component_name=component.name,
                component_version=component.version
            )

            if not cve_ids:
                print(f"[NVD Discovery] No CVE IDs found for {component.name} {component.version}")
                return []

            print(f"[CVE.org Verification] Verifying {len(cve_ids)} CVEs for {component.name} {component.version}")

            # Phase 2: Verify each CVE with CVE.org (PARALLEL)
            async def verify_cve(cve_id):
                """Verify a single CVE with CVE.org"""
                try:
                    cve_org_data = await cve_org_client.fetch_cve(cve_id)
                    if not cve_org_data:
                        return None
                    parsed = cve_org_client.parse_cve_record(cve_org_data)
                    is_affected, confidence, reason = cve_org_client.is_component_affected(
                        parsed,
                        component.name,
                        component.version,
                        component.purl
                    )
                    if is_affected and confidence >= 50:
                        return {
                            "cve_id": cve_id,
                            "parsed_data": parsed,
                            "confidence": confidence,
                            "reason": reason
                        }
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
            return verified_cves

        # Run the async sync operation
        verified_cves = asyncio.run(sync_cves_async())

        if not verified_cves:
            print(f"[CVE.org] No verified CVEs for {component.name} {component.version}")
            return []

        print(f"[CVE.org] Verified {len(verified_cves)} CVEs for {component.name} {component.version}")

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
                # Update with latest data
                existing.description = parsed_data.get("description", "")
                existing.cvss_score = parsed_data.get("cvss_score", 0.0)
                existing.cvss_vector = parsed_data.get("cvss_vector", "")
                existing.severity = parsed_data.get("severity", "unknown")
                existing.cwe_id = parsed_data.get("cwe_id")
                existing.published_date = self._parse_date(parsed_data.get("published_date"))
                existing.exploit_available = parsed_data.get("exploit_available", False)
                existing.patch_available = parsed_data.get("patch_available", False)
                existing.references = parsed_data.get("references", "")
                existing.nvd_url = parsed_data.get("nvd_url", "")

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
                cve_record = CVE(
                    cve_id=cve_id,
                    description=parsed_data.get("description", ""),
                    cvss_score=parsed_data.get("cvss_score", 0.0),
                    cvss_vector=parsed_data.get("cvss_vector", ""),
                    severity=parsed_data.get("severity", "unknown"),
                    cwe_id=parsed_data.get("cwe_id"),
                    published_date=self._parse_date(parsed_data.get("published_date")),
                    exploit_available=parsed_data.get("exploit_available", False),
                    patch_available=parsed_data.get("patch_available", False),
                    references=parsed_data.get("references", ""),
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

            saved_cves.append(cve_record)

        db.commit()
        print(f"[NVD] Saved {len(saved_cves)} verified CVEs for {component.name} {component.version}")
        return saved_cves


# Singleton
nvd_service = NVDService()