"""
CVE.org API Client

Fetches CVE data from MITRE's CVE Services API.

API Base: https://cveawg.mitre.org/api/cve/
Docs: https://www.cve.org/AllResources/CveServices

Why use this alongside NVD:
- CVE.org has CPE entries that NVD often lacks
- CVE.org has structured version ranges
- CVE.org has vendor + product names in affected[]
- CVE.org has workarounds and solutions
- No API key required
"""

import httpx
import asyncio
import re
from typing import Optional, List, Dict, Tuple
from datetime import datetime


class CVEOrgClient:
    """
    Client for the CVE.org (MITRE) API.

    Endpoint: https://cveawg.mitre.org/api/cve/{CVE-ID}

    This API returns the CVE Record in the CVE JSON 5.0/5.1
    format which includes:
    - Affected products with vendor, product, version ranges
    - CPE entries
    - CVSS metrics
    - CWE weakness types
    - Workarounds and solutions
    """

    BASE_URL = "https://cveawg.mitre.org/api/cve"

    def __init__(self):
        self.timeout = 30

    async def fetch_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch a single CVE record from CVE.org.

        Args:
            cve_id: e.g., "CVE-2026-94402"

        Returns:
            Parsed CVE data dict or None
        """
        url = f"{self.BASE_URL}/{cve_id}"

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout
            ) as client:
                response = await client.get(url)

                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 404:
                    print(f"[CVE.org] {cve_id} not found")
                    return None
                else:
                    print(f"[CVE.org] HTTP {response.status_code} for {cve_id}")
                    return None

        except httpx.TimeoutException:
            print(f"[CVE.org] Timeout fetching {cve_id}")
            return None
        except Exception as e:
            print(f"[CVE.org] Error: {e}")
            return None

    def parse_cve_record(self, data: Dict) -> Dict:
        """
        Parse a CVE.org record into a structured format
        that your agent pipeline can use.

        The key difference from NVD:
        - affected[] contains vendor, product, versions,
          AND CPE entries
        - Version ranges use semver with lessThan/
          lessThanOrEqual
        """
        if not data:
            return {}

        metadata = data.get("cveMetadata", {})
        cna = data.get("containers", {}).get("cna", {})

        # Basic fields
        cve_id = metadata.get("cveId", "")
        assigner = metadata.get("assignerShortName", "")
        published = metadata.get("datePublished", "")

        # Description
        description = ""
        for desc in cna.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # CVSS
        cvss_score = 0.0
        cvss_vector = ""
        severity = "unknown"
        for metric in cna.get("metrics", []):
            cvss = metric.get("cvssV3_1", {})
            if cvss:
                cvss_score = cvss.get("baseScore", 0.0)
                cvss_vector = cvss.get("vectorString", "")
                severity = cvss.get("baseSeverity", "unknown").lower()
                break

        # CWE
        cwe_id = None
        for problem in cna.get("problemTypes", []):
            for desc in problem.get("descriptions", []):
                cwe = desc.get("cweId")
                if cwe:
                    cwe_id = cwe
                    break

        # References
        references = []
        exploit_available = False
        patch_available = False
        for ref in cna.get("references", []):
            url = ref.get("url", "")
            tags = ref.get("tags", [])
            references.append(url)
            if "exploit" in tags:
                exploit_available = True
            if "patch" in tags:
                patch_available = True

        # ── THE KEY DATA: Affected Products ──────────
        # This is what NVD often lacks
        affected_products = []
        for affected in cna.get("affected", []):
            vendor = affected.get("vendor", "")
            product = affected.get("product", "")
            cpes = affected.get("cpes", [])

            versions_info = []
            for ver in affected.get("versions", []):
                # Clean version strings - remove trailing dashes, spaces, etc.
                version_start = ver.get("version", "").strip().rstrip("-")
                version_end = ver.get("lessThanOrEqual", ver.get("lessThan", "")).strip().rstrip("-")
                
                versions_info.append({
                    "status": ver.get("status", ""),
                    "version_start": version_start,
                    "version_end": version_end,
                    "version_end_type": "including" if "lessThanOrEqual" in ver else "excluding",
                    "version_type": ver.get("versionType", "custom"),
                })

            affected_products.append({
                "vendor": vendor,
                "product": product,
                "cpes": cpes,
                "versions": versions_info,
            })

        # Workarounds and solutions
        workarounds = []
        for w in cna.get("workarounds", []):
            workarounds.append(w.get("value", ""))

        solutions = []
        for s in cna.get("solutions", []):
            solutions.append(s.get("value", ""))

        return {
            "cve_id": cve_id,
            "assigner": assigner,
            "description": description[:2000],
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "severity": severity,
            "cwe_id": cwe_id,
            "published_date": published,
            "exploit_available": exploit_available,
            "patch_available": patch_available,
            "references": ", ".join(references[:10]),
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            # New fields from CVE.org
            "affected_products": affected_products,
            "workarounds": workarounds,
            "solutions": solutions,
        }

    def is_component_affected(
        self,
        cve_data: Dict,
        component_name: str,
        component_version: str,
        component_purl: str = None
    ) -> Tuple[bool, int, str]:
        """
        Check if a specific component is affected by this CVE
        using the structured affected[] data from CVE.org.

        Returns:
            Tuple of (is_affected, confidence, reason)
        """
        affected_products = cve_data.get("affected_products", [])

        if not affected_products:
            return (False, 20, "No affected product data")

        clean_name = component_name.lower().strip()
        clean_version = component_version.strip()

        # Remove leading 'v' from version
        if clean_version.startswith("v"):
            clean_version = clean_version[1:]

        for product_info in affected_products:
            vendor = product_info.get("vendor", "").lower()
            product = product_info.get("product", "").lower()
            cpes = product_info.get("cpes", [])
            versions = product_info.get("versions", [])

            # ── Check 1: Product name match ──────────
            product_match = False

            # Direct name match (exact match only - no fuzzy matching)
            if clean_name == product:
                product_match = True

            # Check PURL match (only if PURL contains exact product name as a word)
            if component_purl and product in component_purl.lower():
                # Ensure it's a word boundary match, not substring
                purl_parts = component_purl.lower().replace("/", " ").replace("@", " ").replace("-", " ").split()
                if product in purl_parts:
                    product_match = True

            # Check CPE match (exact match on CPE product field)
            for cpe in cpes:
                cpe_lower = cpe.lower()
                cpe_parts = cpe_lower.split(":")
                if len(cpe_parts) >= 5:
                    cpe_product = cpe_parts[4]
                    # Normalize: replace underscores and hyphens with spaces for comparison
                    cpe_product_normalized = cpe_product.replace("_", " ").replace("-", " ")
                    name_normalized = clean_name.replace("@", "").replace("/", " ").replace("-", " ").replace("_", " ")

                    # Only match if normalized names are identical
                    if cpe_product_normalized == name_normalized:
                        product_match = True
                        break

            if not product_match:
                continue

            # ── Check 2: Version range match ─────────
            for ver_info in versions:
                if ver_info["status"] != "affected":
                    continue

                version_start = ver_info.get("version_start", "")
                version_end = ver_info.get("version_end", "")
                end_type = ver_info.get("version_end_type", "including")
                version_type = ver_info.get("version_type", "custom")

                in_range = self._check_version_in_range(
                    clean_version,
                    version_start,
                    version_end,
                    end_type,
                    version_type
                )

                if in_range:
                    return (
                        True,
                        95,
                        f"Product '{product}' matched. "
                        f"Version {clean_version} is within "
                        f"affected range {version_start}–{version_end} "
                        f"({end_type})."
                    )
                else:
                    return (
                        False,
                        90,
                        f"Product '{product}' matched but "
                        f"version {clean_version} is OUTSIDE "
                        f"affected range {version_start}–{version_end}."
                    )

            # Product matched but no version info
            return (
                True,
                60,
                f"Product '{product}' matched but "
                f"no version range data to verify."
            )

        # No product matched
        return (
            False,
            85,
            f"Component '{component_name}' does not match "
            f"any affected product: "
            f"{[p['product'] for p in affected_products]}"
        )

    def _check_version_in_range(
        self,
        version: str,
        start: str,
        end: str,
        end_type: str,
        version_type: str
    ) -> bool:
        """
        Check if a version falls within an affected range.

        Critical fix: Handle excluding boundaries correctly.
        - If end_type is "excluding" (lessThan), versions >= end are NOT affected
        - If end_type is "including" (lessThanOrEqual), versions > end are NOT affected
        """
        print(f"[VERSION CHECK] version={version}, start={start}, end={end}, end_type={end_type}")
        
        try:
            from packaging.version import Version, InvalidVersion

            try:
                v = Version(version)
                v_start = Version(start) if start else None
                v_end = Version(end) if end else None
                print(f"[VERSION CHECK] Parsed: v={v}, v_start={v_start}, v_end={v_end}")
            except InvalidVersion as e:
                print(f"[VERSION CHECK] InvalidVersion, falling back to string compare: {e}")
                return self._string_version_compare(version, start, end, end_type)

            # Check lower bound (if specified)
            if v_start and v < v_start:
                print(f"[VERSION CHECK] v < v_start ({v} < {v_start}), NOT affected")
                return False

            # Check upper bound (if specified)
            if v_end:
                if end_type == "including":
                    # lessThanOrEqual: versions <= v_end are affected
                    result = v <= v_end
                    print(f"[VERSION CHECK] v <= v_end ({v} <= {v_end}) = {result}")
                    return result
                else:
                    # lessThan: versions < v_end are affected
                    # v == v_end means it's the fix version, NOT affected
                    result = v < v_end
                    print(f"[VERSION CHECK] v < v_end ({v} < {v_end}) = {result}")
                    return result

            # No end version specified - assume all versions >= start are affected
            print(f"[VERSION CHECK] No end version, assuming affected")
            return True

        except ImportError:
            print(f"[VERSION CHECK] packaging not installed, using string compare")
            return self._string_version_compare(version, start, end, end_type)

    def _string_version_compare(
        self,
        version: str,
        start: str,
        end: str,
        end_type: str
    ) -> bool:
        """
        Simple version comparison using tuple of integers.
        """
        def parse_ver(v):
            parts = re.findall(r'\d+', v)
            return tuple(int(p) for p in parts) if parts else (0,)

        v = parse_ver(version)
        v_start = parse_ver(start) if start else None
        v_end = parse_ver(end) if end else None

        # Check lower bound
        if v_start and v < v_start:
            return False

        # Check upper bound
        if v_end:
            if end_type == "including":
                return v <= v_end
            else:
                # excluding: v == v_end means it's the fix version, NOT affected
                return v < v_end

        return True


# Singleton
cve_org_client = CVEOrgClient()
