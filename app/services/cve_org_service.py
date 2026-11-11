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

# Fix 6: Generic name blocklist - common English words that should require CPE-based lookup
GENERIC_NAME_BLOCKLIST = {
    "make", "patch", "file", "time", "test", "date", "core", "base", "lib", "tool",
    "utils", "common", "framework", "process", "service", "client", "server",
    "config", "data", "main", "app", "system", "user", "admin", "auth"
}

# Fix 7: Known CPE vendor mappings for accurate NVD searching
CPE_VENDOR_MAPPINGS = {
    "make": "gnu",
    "patch": "gnu",
    "openssl": "openssl",
    "python3": "python",
    "python": "python",
    "node": "nodejs",
    "java": "oracle",
    "mysql": "oracle",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "nginx": "f5",
    "apache": "apache",
    "tomcat": "apache",
    "libxml2": "xmlsoft",
    "libpng": "libpng",
    "libjpeg": "ijg",
    "zlib": "gnu"
}
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

                # Fix Issue 2: Parse composite version strings like ">= 0.6.0, < 2.9.0"
                # If version_start contains a comma, it's a composite constraint
                if "," in version_start:
                    version_start = self._parse_composite_version(version_start)
                if "," in version_end:
                    version_end = self._parse_composite_version(version_end)

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

    async def is_component_affected(
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

        # Fix: Handle "n/a" products (old CVEs without structured data)
        # These CVEs predate ~2020 and need LLM analysis
        if not affected_products:
            return (False, 20, "No affected product data")

        # Check if all products are "n/a" (old CVE format)
        all_na = all(p.get("product", "").lower() == "n/a" for p in affected_products)
        if all_na:
            # Use LLM to analyze old CVEs without structured data
            return await self._llm_analyze_old_cve(cve_data, component_name, component_version, component_purl)

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

            # Skip "n/a" products
            if product == "n/a":
                continue

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

                # Fix: Strip product name from version string before parsing
                # e.g., "binutils 2.34" -> "2.34", "GNU binutils version 2.36" -> "2.36"
                version_start = self._strip_product_from_version(version_start, product)
                version_end = self._strip_product_from_version(version_end, product)

                in_range = self._check_version_in_range(
                    clean_version,
                    version_start,
                    version_end,
                    end_type,
                    version_type
                )

                # Fix Issue 1: Handle None return (no end version)
                if in_range is None:
                    return (
                        True,
                        50,  # Lowered confidence from 95 to 50
                        f"Product '{product}' matched. "
                        f"Version {clean_version} >= {version_start} "
                        f"but no upper bound specified - NEEDS_REVIEW"
                    )
                elif in_range:
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
        # Fix Issue 3: Truncate product list in log output
        product_list = [p['product'] for p in affected_products if p.get('product', '').lower() != 'n/a']
        if len(product_list) > 5:
            product_list = product_list[:5] + [f"... ({len(product_list) - 5} more)"]
        return (
            False,
            85,
            f"Component '{component_name}' does not match "
            f"any affected product: {product_list}"
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
                    # lessThan (excluding): versions < v_end are affected
                    # v == v_end means it's the fix version, NOT affected
                    # Use strict less-than comparison
                    result = v < v_end
                    print(f"[VERSION CHECK] v < v_end (excluding) ({v} < {v_end}) = {result}")
                    return result

            # Fix Issue 1: No end version specified - cannot confirm affected range
            # Reduce confidence significantly and mark as NEEDS_REVIEW
            print(f"[VERSION CHECK] No end version, cannot confirm affected range - lowering confidence")
            # We'll handle this in the caller by checking if end is None
            return None  # Signal to caller that this needs special handling

        except ImportError:
            print(f"[VERSION CHECK] packaging not installed, using string compare")
            return self._string_version_compare(version, start, end, end_type)

    def _strip_product_from_version(self, version_str: str, product_name: str) -> str:
        """
        Fix 3: Strip product name prefix from version string.
        e.g., "binutils 2.34" -> "2.34", "GNU binutils version 2.36" -> "2.36"
        """
        if not version_str:
            return version_str
        
        # Try to extract version-like pattern
        match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version_str)
        if match:
            return match.group(1)
        
        # Fallback: remove common prefixes
        prefixes_to_remove = [product_name.lower(), "version", "before", "including", "up to"]
        cleaned = version_str.lower()
        for prefix in prefixes_to_remove:
            cleaned = cleaned.replace(prefix, "")
        
        # Extract first version-like pattern from cleaned string
        match = re.search(r'(\d+\.\d+(?:\.\d+)?)', cleaned)
        if match:
            return match.group(1)
        
        return version_str

    def _parse_composite_version_string(self, version_str: str) -> Tuple[str, str, str]:
        """
        Fix 4: Parse composite version strings like ">= 0.6.0, < 2.9.0"
        Returns: (start_version, end_version, end_type)
        """
        if not version_str:
            return ("", "", "including")
        
        # Pattern: ">= X, < Y" or ">= X - Y"
        # Extract start version
        start_match = re.search(r'>=\s*(\d+\.\d+(?:\.\d+)?)', version_str)
        if start_match:
            start = start_match.group(1)
        else:
            start = ""
        
        # Extract end version
        end_match = re.search(r'<\s*(\d+\.\d+(?:\.\d+)?)', version_str)
        if end_match:
            end = end_match.group(1)
            end_type = "excluding"  # < means excluding
        else:
            end = ""
            end_type = "including"
        
        return (start, end, end_type)

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

        # Fix Issue 1: No end version specified - cannot confirm affected range
        return None

    def _parse_composite_version(self, version_str: str) -> str:
        """
        Fix Issue 2: Parse composite version strings like ">= 0.6.0, < 2.9.0"
        Extract the most relevant version for comparison.
        """
        import re

        # Remove operators and extract version numbers
        # Pattern: >= 0.6.0, < 2.9.0 -> extract versions
        versions = re.findall(r'[\d.]+', version_str)

        if not versions:
            return version_str

        # Return the first version found (usually the lower bound)
        # This is a simplification - ideally we'd parse the full constraint
        return versions[0]

    def _strip_product_from_version(self, version_str: str, product_name: str) -> str:
        """
        Strip product name prefix from version string.
        
        Examples:
        - "binutils 2.34" -> "2.34"
        - "GNU binutils version 2.36" -> "2.36"
        - "Binutils 2.35.1" -> "2.35.1"
        - "binutils 2.39-7" -> "2.39-7"
        - "GNU Binutils version before and including 2.36" -> "2.36"
        """
        if not version_str:
            return version_str
        
        # Try to extract version using regex (digits, dots, hyphens, tilde)
        import re
        version_match = re.search(r'[\d.]+(?:-[a-z0-9]+)?', version_str)
        if version_match:
            return version_match.group(0)
        
        # Fallback: return original
        return version_str

    async def _llm_analyze_old_cve(
        self,
        cve_data: Dict,
        component_name: str,
        component_version: str,
        component_purl: str = None
    ) -> Tuple[bool, int, str]:
        """
        Use LLM to analyze old CVEs (pre-2020) that have "n/a" product data.

        These CVEs lack structured affected[] data, so we use the LLM to
        read the description and determine if the component is affected.
        """
        cve_id = cve_data.get("cve_id", "")
        description = cve_data.get("description", "")

        prompt = f"""You are a cybersecurity expert analyzing CVE vulnerabilities.

Given a component and a CVE description, determine if the component is affected by this vulnerability.

Component: {component_name}
Version: {component_version}
PURL: {component_purl or 'N/A'}

CVE ID: {cve_id}
Description: {description}

Analyze whether this CVE affects the component. Consider:
1. Does the description mention the component name or related products?
2. Does the version range mentioned in the CVE include the component's version?
3. Is the component in the ecosystem this CVE targets?

Respond in JSON format:
{{"is_affected": true/false, "confidence": 0-100, "reasoning": "explanation", "affected_product": "product name", "affected_range": "version range (e.g., '< 2.0.0', '>= 1.0.0, < 2.0.0')"}}

Examples:
- Component: "binutils", Version: "2.34", CVE about "binutils 2.34 allows remote attackers..." -> {{"is_affected": true, "confidence": 85, "reasoning": "Description explicitly mentions binutils 2.34", "affected_product": "binutils", "affected_range": "2.34"}}
- Component: "openssl", Version: "1.1.1", CVE about "log4j" -> {{"is_affected": false, "confidence": 90, "reasoning": "CVE affects log4j, not openssl", "affected_product": "log4j", "affected_range": "N/A"}}"""

        try:
            import httpx
            import json
            import re
            from packaging import version as pkg_version

            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    "http://localhost:11434/api/generate",
                    json={
                        "model": "qwen2.5:7b",
                        "prompt": prompt,
                        "stream": False,
                        "format": "json"
                    }
                )
                if response.status_code == 200:
                    result = response.json()
                    content = result.get("response", "{}")
                    # Extract JSON from response
                    try:
                        parsed = json.loads(content)
                    except json.JSONDecodeError:
                        # Try to extract JSON from text
                        match = re.search(r'\{[^}]+\}', content)
                        if match:
                            parsed = json.loads(match.group())
                        else:
                            parsed = {}

                    is_affected = parsed.get("is_affected", False)
                    llm_confidence = parsed.get("confidence", 50)
                    # CAP CONFIDENCE AT 75
                    confidence = min(llm_confidence, 75)
                    reasoning = parsed.get("reasoning", "LLM analysis")
                    affected_product = parsed.get("affected_product", "")
                    affected_range = parsed.get("affected_range", "")

                    # Check if product is different (hard REJECT)
                    if affected_product and affected_product.lower() not in component_name.lower():
                        return (False, 95, f"LLM analysis: CVE affects {affected_product}, not {component_name}")

                    # If no range, return NEEDS_REVIEW (50)
                    if not affected_range or affected_range == "N/A":
                        return (False, 50, f"LLM analysis: No version range specified, needs manual review - {reasoning}")

                    # Try to compare versions using packaging
                    try:
                        # Simple version comparison for common patterns
                        if "<" in affected_range:
                            parts = affected_range.split("<")
                            if len(parts) == 2:
                                max_version = parts[1].strip()
                                try:
                                    if pkg_version.parse(component_version) < pkg_version.parse(max_version):
                                        return (True, confidence, f"LLM analysis: {reasoning} (version {component_version} < {max_version})")
                                except:
                                    pass
                        elif ">" in affected_range:
                            parts = affected_range.split(">")
                            if len(parts) == 2:
                                min_version = parts[1].strip()
                                try:
                                    if pkg_version.parse(component_version) > pkg_version.parse(min_version):
                                        return (True, confidence, f"LLM analysis: {reasoning} (version {component_version} > {min_version})")
                                except:
                                    pass
                    except Exception as e:
                        print(f"[CVE.org] Version comparison failed: {e}")

                    return (
                        is_affected,
                        confidence,
                        f"LLM analysis of old CVE: {reasoning}"
                    )

        except Exception as e:
            print(f"[CVE.org] LLM analysis failed for {cve_id}: {e}")

        # Fallback: mark as uncertain
        return (False, 50, "LLM analysis failed - CVE predates structured data, manual review required")


# Singleton
cve_org_client = CVEOrgClient()
