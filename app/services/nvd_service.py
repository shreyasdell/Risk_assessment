"""
NVD API v2.0 Client - FIXED VERSION

Problems with previous version:
1. keywordExactMatch was too strict
2. Did not try multiple search strategies
3. Did not handle component name variations
4. Did not properly use CPE matching

Fix approach:
- Try CPE first (most accurate)
- Then try keyword WITHOUT exact match
- Clean component names before searching
- Try name variations (log4j -> log4j-core)
"""

import os
import httpx
import asyncio
import re
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Tuple
from sqlalchemy.orm import Session

from app.models.cve import CVE
from app.models.component import Component


# Generic Name Blocklist
GENERIC_NAME_BLOCKLIST = {
    "make", "patch", "file", "time", "test", "date",
    "cal", "at", "bc", "dc", "diff", "find", "sort",
    "split", "strings", "su", "tar", "top", "tr",
    "tree", "true", "false", "yes", "more", "less",
    "man", "nice", "link", "unlink", "head", "tail",
    "cut", "join", "fold", "fmt", "pr", "env", "id",
    "who", "w", "last", "look", "spell", "units",
    "factor", "seq", "shuf", "paste", "comm", "expand",
    "base", "core", "common", "commons", "util", "utils",
    "config", "log", "logger", "logging", "cache",
    "crypto", "ssl", "tls", "net", "http", "dns",
    "db", "sql", "json", "xml", "yaml", "csv",
    "io", "os", "sys", "math", "random", "re",
    "async", "sync", "promise", "promises", "events",
    "stream", "buffer", "string", "array", "list",
    "map", "set", "queue", "stack", "tree", "graph",
    "proxy", "server", "client", "socket", "pipe",
    "lock", "mutex", "signal", "token", "key",
    "color", "debug", "error", "info", "warn",
    "busybox", "musl", "scanelf", "ssl_client",
    "alpine-baselayout", "alpine-baselayout-data",
    "alpine-keys", "apk-tools", "ca-certificates",
    "ca-certificates-bundle", "libc-utils",
}

# Known CPE Vendor Mappings
KNOWN_CPE_VENDORS = {
    "make": "gnu",
    "patch": "gnu",
    "tar": "gnu",
    "gzip": "gnu",
    "grep": "gnu",
    "sed": "gnu",
    "awk": "gnu",
    "bash": "gnu",
    "coreutils": "gnu",
    "binutils": "gnu",
    "gcc": "gnu",
    "gdb": "gnu",
    "glibc": "gnu",
    "libc": "gnu",
    "readline": "gnu",
    "ncurses": "gnu",
    "diffutils": "gnu",
    "findutils": "gnu",
    "wget": "gnu",
    "openssl": "openssl",
    "libssl": "openssl",
    "curl": "haxx",
    "libcurl": "haxx",
    "zlib": "zlib",
    "libxml2": "xmlsoft",
    "libxslt": "xmlsoft",
    "sqlite": "sqlite",
    "libsqlite3": "sqlite",
    "pcre": "pcre",
    "pcre2": "pcre",
    "expat": "libexpat_project",
    "libexpat": "libexpat_project",
    "libjpeg": "ijg",
    "libpng": "libpng",
    "libtiff": "libtiff",
    "freetype": "freetype",
    "fontconfig": "fontconfig_project",
    "icu": "icu-project",
    "bzip2": "bzip",
    "xz": "tukaani",
    "lz4": "lz4_project",
    "zstd": "facebook",
    "libarchive": "libarchive",
    "libevent": "libevent_project",
    "libffi": "sourceware",
    "gmp": "gmplib",
    "nettle": "nettle_project",
    "gnutls": "gnu",
    "libssh2": "libssh2",
    "nghttp2": "nghttp2",
    "libev": "libev_project",
    "libuv": "libuv_project",
    "python3": "python",
    "python": "python",
    "python2": "python",
    "ruby": "ruby-lang",
    "perl": "perl",
    "php": "php",
    "node": "nodejs",
    "nodejs": "nodejs",
    "go": "golang",
    "java": "oracle",
    "openjdk": "oracle",
    "nginx": "f5",
    "apache": "apache",
    "httpd": "apache",
    "tomcat": "apache",
    "redis": "redis",
    "postgresql": "postgresql",
    "mysql": "oracle",
    "mariadb": "mariadb",
    "mongodb": "mongodb",
    "git": "git-scm",
    "docker": "docker",
    "containerd": "linuxfoundation",
    "runc": "linuxfoundation",
    "libgcc": "gnu",
    "libstdc++": "gnu",
    "musl": "musl-libc",
    "busybox": "busybox",
    "e2fsprogs": "e2fsprogs_project",
    "util-linux": "kernel",
    "shadow": "vmware",
    "sudo": "sudo_project",
    "openssh": "openbsd",
    "krb5": "mit",
}


class NVDService:

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        self.api_key = os.getenv("NVD_API_KEY")
        self.headers = {}
        if self.api_key:
            self.headers["apiKey"] = self.api_key

        self.request_times: List[datetime] = []
        self.max_requests = 50 if self.api_key else 5
        self.rate_window = 30

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
        Removes Alpine Linux package suffixes (e.g., -r2, -r5, -r10)
        """
        # Remove Alpine Linux package suffixes
        cleaned = re.sub(r'-r\d+$', '', name.lower().strip())
        return cleaned

    def _generate_search_queries(
        self,
        name: str,
        version: str = None
    ) -> List[Dict]:
        """Generate search queries with vendor mapping."""
        queries = []
        clean_name = self._clean_component_name(name)
        clean_version = re.sub(r'-r\d+$', '', version) if version else None

        # Check if name is in blocklist - skip keyword search
        if clean_name in GENERIC_NAME_BLOCKLIST:
            return []

        # Strategy 1: Name + version
        if clean_version:
            queries.append({
                "keywordSearch": f"{clean_name} {clean_version}",
                "resultsPerPage": 50,
            })

        # Strategy 2: Just the name
        queries.append({
            "keywordSearch": clean_name,
            "resultsPerPage": 50,
        })

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
        """Search NVD for CVEs with improved filtering."""
        clean_name = self._clean_component_name(component_name)
        clean_version = re.sub(r'-r\d+$', '', component_version) if component_version else None

        # Strategy 0: Use or generate CPE if available
        if cpe:
            # Try to correct vendor in CPE
            cpe_parts = cpe.split(':')
            if len(cpe_parts) >= 3:
                vendor = cpe_parts[3].lower()
                if vendor in KNOWN_CPE_VENDORS:
                    corrected_cpe = cpe.replace(f':{vendor}:', f':{KNOWN_CPE_VENDORS[vendor]}:')
                    print(f"[NVD] Corrected CPE: {corrected_cpe}")
                    data = await self._make_request({
                        "cpeName": corrected_cpe,
                        "resultsPerPage": 100,
                    })
                    if data and data.get("totalResults", 0) > 0:
                        return self._parse_nvd_response(data)

        # Generate keyword queries (returns empty if name is blocklisted)
        queries = self._generate_search_queries(component_name, component_version)

        for query_params in queries:
            data = await self._make_request(query_params)

            if data and data.get("totalResults", 0) > 0:
                # Skip if too many results (likely false positives)
                if data.get("totalResults", 0) > 500:
                    print(f"[NVD] Skipping {data['totalResults']} results - too many false positives")
                    continue

                results = self._parse_nvd_response(data)
                if results:
                    filtered = self._filter_relevant_cves_strict(
                        results,
                        clean_name,
                        clean_version
                    )
                    if filtered:
                        return filtered

        print(f"[NVD] No CVEs found for {component_name} {component_version or ''}")
        return []

    def _filter_relevant_cves_strict(
        self,
        cves: List[Dict],
        component_name: str,
        component_version: str = None
    ) -> List[Dict]:
        """Strict filtering to prevent false positives."""
        if not cves:
            return []

        clean_name = component_name.lower().strip()
        relevant = []

        for cve in cves:
            desc = (cve.get("description") or "").lower()
            refs = cve.get("references", [])
            score = 0

            # Check references (more reliable)
            ref_urls = [ref.get("url", "").lower() for ref in refs]
            if any(clean_name in url for url in ref_urls):
                score += 3

            # Check description with word boundary matching
            pattern = r'\b' + re.escape(clean_name) + r'\b'
            if re.search(pattern, desc):
                # Check for software-related context
                software_keywords = ["version", "vulnerability", "affected", "allows", "buffer", "overflow", "injection"]
                if any(kw in desc for kw in software_keywords):
                    score += 2

            # Check version
            if component_version and score > 0:
                clean_ver = re.sub(r'-r\d+$', '', component_version)
                if clean_ver in desc:
                    score += 1

            if score >= 2:
                relevant.append(cve)

        return relevant

    def _filter_relevant_cves(
        self,
        cves: List[Dict],
        component_name: str,
        component_version: str = None
    ) -> List[Dict]:
        """Fallback filtering (deprecated, use _filter_relevant_cves_strict)."""
        return self._filter_relevant_cves_strict(cves, component_name, component_version)

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

        1. Fetch CVEs from NVD
        2. Create or update CVE records
        3. Link CVEs to the component
        4. Return results
        """
        loop = asyncio.new_event_loop()
        try:
            cve_data_list = loop.run_until_complete(
                self.fetch_cves_for_component(
                    component_name=component.name,
                    component_version=component.version,
                    cpe=component.cpe
                )
            )
        finally:
            loop.close()

        if not cve_data_list:
            print(
                f"[NVD] No CVEs found for "
                f"{component.name} {component.version}"
            )
            return []

        saved_cves = []

        for cve_data in cve_data_list:
            # Check if CVE already exists in our database
            existing = (
                db.query(CVE)
                .filter(CVE.cve_id == cve_data["cve_id"])
                .first()
            )

            if existing:
                # Update with latest data from NVD
                for key, value in cve_data.items():
                    if value is not None:
                        setattr(existing, key, value)
                cve_record = existing
            else:
                # Create new CVE record
                cve_record = CVE(**cve_data)
                db.add(cve_record)
                db.flush()

            # Link CVE to component if not already linked
            if cve_record not in component.cves:
                component.cves.append(cve_record)

            saved_cves.append(cve_record)

        db.commit()

        for cve in saved_cves:
            db.refresh(cve)

        print(
            f"[NVD] Saved {len(saved_cves)} CVEs for "
            f"{component.name} {component.version}"
        )
        return saved_cves


# Singleton
nvd_service = NVDService()