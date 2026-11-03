"""
Stage 1: Deterministic CPE Matcher

Parses CPE (Common Platform Enumeration) entries from each CVE
and compares them against the SBOM component's identity.

This is the highest-confidence, fastest stage. If the CVE has CPE
data and it doesn't match the component, we can definitively reject
the CVE without invoking any other stage.

CPE 2.3 Format:
  cpe:2.3:{part}:{vendor}:{product}:{version}:{update}:{edition}:{language}:{sw_edition}:{target_sw}:{target_hw}:{other}

Example:
  cpe:2.3:o:linux:linux_kernel:6.19:*:*:*:*:*:*:*
         │  │     │            │
         │  │     │            └─ version
         │  │     └─ product
         │  └─ vendor
         └─ part (o=OS, a=application, h=hardware)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)


class MatchVerdict(Enum):
    """Possible outcomes from a pipeline stage."""
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    UNCERTAIN = "UNCERTAIN"


@dataclass
class CPERecord:
    """Parsed representation of a CPE 2.3 string."""
    part: str        # 'a' (application), 'o' (OS), 'h' (hardware)
    vendor: str
    product: str
    version: str
    update: str = "*"
    edition: str = "*"
    language: str = "*"
    sw_edition: str = "*"
    target_sw: str = "*"
    target_hw: str = "*"
    other: str = "*"


@dataclass
class StageResult:
    """Result from any pipeline stage."""
    verdict: MatchVerdict
    confidence: int          # 0-100
    reasoning: str
    matched_cpe: Optional[str] = None


class CPEMatcher:
    """
    Stage 1: Parse CPE entries from CVE and compare against
    the SBOM component identity.

    Decision logic:
    - CVE has no CPE data → UNCERTAIN (pass to next stage)
    - CVE has CPE data, product matches, version in range → MATCH
    - CVE has CPE data, product matches, version out of range → NO_MATCH
    - CVE has CPE data, no product matches → NO_MATCH (strong signal)
    """

    # Common name normalizations: SBOM name → possible CPE product names
    NAME_ALIASES = {
        "lodash": ["lodash"],
        "express": ["express"],
        "react": ["react"],
        "angular": ["angular"],
        "jquery": ["jquery"],
        "django": ["django"],
        "flask": ["flask"],
        "spring-boot": ["spring_boot", "spring-boot"],
        "tensorflow": ["tensorflow"],
        "numpy": ["numpy"],
        "pandas": ["pandas"],
        "requests": ["requests"],
        "axios": ["axios"],
        "webpack": ["webpack"],
    }

    def evaluate(self, component: dict, cve: dict) -> StageResult:
        """
        Evaluate whether a CVE's CPE entries match the given component.

        Args:
            component: {
                "name": "carbon",
                "version": "2.1.1",
                "purl": "pkg:npm/carbon@2.1.1",
                "ecosystem": "npm"
            }
            cve: Raw CVE object from NVD API response.
                 Expected structure follows NVD API v2.0 format.

        Returns:
            StageResult with verdict, confidence, and reasoning.
        """
        cpe_entries = self._extract_cpe_entries(cve)

        # Case 1: CVE has no CPE data at all
        if not cpe_entries:
            return StageResult(
                verdict=MatchVerdict.UNCERTAIN,
                confidence=0,
                reasoning=(
                    "CVE has no CPE configuration data; "
                    "cannot determine match deterministically."
                )
            )

        component_name = component.get("name", "").lower().strip()
        component_version = component.get("version", "")

        if not component_name:
            return StageResult(
                verdict=MatchVerdict.UNCERTAIN,
                confidence=0,
                reasoning="Component has no name; cannot match against CPE."
            )

        # Iterate over all CPE entries and look for product match
        for cpe_entry in cpe_entries:
            criteria = cpe_entry.get("criteria", "")
            parsed = self._parse_cpe_string(criteria)
            if not parsed:
                continue

            # Check product match
            product_match = self._product_matches(parsed.product, component_name)

            if product_match:
                # Product matches — now check version range
                version_result = self._version_in_range(
                    component_version,
                    cpe_entry.get("versionStartIncluding"),
                    cpe_entry.get("versionEndExcluding"),
                    cpe_entry.get("versionStartExcluding"),
                    cpe_entry.get("versionEndIncluding"),
                    parsed.version,
                )

                if version_result is True:
                    return StageResult(
                        verdict=MatchVerdict.MATCH,
                        confidence=95,
                        reasoning=(
                            f"CPE product '{parsed.product}' matches component "
                            f"'{component_name}' and version '{component_version}' "
                            f"is within the affected range."
                        ),
                        matched_cpe=criteria,
                    )
                elif version_result is False:
                    return StageResult(
                        verdict=MatchVerdict.NO_MATCH,
                        confidence=90,
                        reasoning=(
                            f"CPE product '{parsed.product}' matches component "
                            f"'{component_name}' but version '{component_version}' "
                            f"is outside the affected range."
                        ),
                    )
                else:
                    # version_result is None — could not determine
                    return StageResult(
                        verdict=MatchVerdict.UNCERTAIN,
                        confidence=50,
                        reasoning=(
                            f"CPE product '{parsed.product}' matches component "
                            f"'{component_name}' but version range could not be "
                            f"determined (version data missing or unparseable)."
                        ),
                        matched_cpe=criteria,
                    )

        # CPE entries exist but NONE match this component's product name.
        # This is a STRONG signal that the CVE is a false positive.
        cpe_products = self._list_cpe_products(cpe_entries)
        return StageResult(
            verdict=MatchVerdict.NO_MATCH,
            confidence=85,
            reasoning=(
                f"CVE has {len(cpe_entries)} CPE entries but none match "
                f"component '{component_name}'. "
                f"CPE products found: {cpe_products}"
            ),
        )

    # ──────────────────────────────────────────────────────────────
    #  Internal helpers
    # ──────────────────────────────────────────────────────────────

    def _extract_cpe_entries(self, cve: dict) -> List[dict]:
        """
        Extract all vulnerable cpeMatch entries from CVE configurations.

        NVD API v2 structure:
        {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": true,
                                    "criteria": "cpe:2.3:o:linux:linux_kernel:*:...",
                                    "versionStartIncluding": "6.19",
                                    "versionEndExcluding": "7.0.13"
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        """
        entries = []
        configurations = cve.get("configurations", [])
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for cpe_match in cpe_matches:
                    if cpe_match.get("vulnerable", False):
                        entries.append(cpe_match)
        return entries

    def _parse_cpe_string(self, cpe_str: str) -> Optional[CPERecord]:
        """
        Parse a CPE 2.3 formatted string into a CPERecord.

        Example input:
            cpe:2.3:o:linux:linux_kernel:6.19:*:*:*:*:*:*:*

        Returns None if the string is malformed.
        """
        if not cpe_str or not cpe_str.startswith("cpe:2.3:"):
            return None

        parts = cpe_str.split(":")
        if len(parts) < 6:
            logger.warning(f"Malformed CPE string (too few parts): {cpe_str}")
            return None

        try:
            return CPERecord(
                part=parts[2],
                vendor=parts[3],
                product=parts[4],
                version=parts[5] if len(parts) > 5 else "*",
                update=parts[6] if len(parts) > 6 else "*",
                edition=parts[7] if len(parts) > 7 else "*",
                language=parts[8] if len(parts) > 8 else "*",
                sw_edition=parts[9] if len(parts) > 9 else "*",
                target_sw=parts[10] if len(parts) > 10 else "*",
                target_hw=parts[11] if len(parts) > 11 else "*",
                other=parts[12] if len(parts) > 12 else "*",
            )
        except IndexError:
            logger.warning(f"Error parsing CPE string: {cpe_str}")
            return None

    def _product_matches(self, cpe_product: str, component_name: str) -> bool:
        """
        Check if a CPE product name matches the SBOM component name.

        Handles:
        - Exact match
        - Underscore/hyphen normalization (linux_kernel ↔ linux-kernel)
        - Known aliases
        """
        cpe_product_lower = cpe_product.lower().strip()
        component_lower = component_name.lower().strip()

        # Exact match
        if cpe_product_lower == component_lower:
            return True

        # Underscore ↔ hyphen normalization
        normalized_cpe = cpe_product_lower.replace("_", "-")
        normalized_comp = component_lower.replace("_", "-")
        if normalized_cpe == normalized_comp:
            return True

        # Remove common prefixes/suffixes
        # e.g., "python-requests" vs "requests"
        stripped_cpe = cpe_product_lower.lstrip("python-").lstrip("node-").lstrip("ruby-")
        if stripped_cpe == component_lower:
            return True

        # Check known aliases
        aliases = self.NAME_ALIASES.get(component_lower, [])
        if cpe_product_lower in aliases:
            return True

        return False

    def _version_in_range(
        self,
        component_version: str,
        start_including: Optional[str],
        end_excluding: Optional[str],
        start_excluding: Optional[str],
        end_including: Optional[str],
        exact_version: Optional[str],
    ) -> Optional[bool]:
        """
        Check if the component version falls within the CVE's affected range.

        Returns:
            True  — version IS in the affected range
            False — version is NOT in the affected range
            None  — cannot determine (missing data or parse failure)
        """
        if not component_version:
            return None

        try:
            from packaging.version import Version, InvalidVersion
        except ImportError:
            logger.warning(
                "packaging library not installed; "
                "cannot perform version comparison."
            )
            return None

        # Parse component version
        try:
            comp_ver = Version(self._clean_version(component_version))
        except InvalidVersion:
            logger.debug(
                f"Cannot parse component version: {component_version}"
            )
            return None

        # Check exact version match
        if exact_version and exact_version not in ("*", "-"):
            try:
                exact = Version(self._clean_version(exact_version))
                return comp_ver == exact
            except InvalidVersion:
                pass

        # Range-based matching
        in_range = True
        has_constraint = False

        if start_including:
            try:
                start = Version(self._clean_version(start_including))
                has_constraint = True
                if comp_ver < start:
                    in_range = False
            except InvalidVersion:
                pass

        if end_excluding:
            try:
                end = Version(self._clean_version(end_excluding))
                has_constraint = True
                if comp_ver >= end:
                    in_range = False
            except InvalidVersion:
                pass

        if start_excluding:
            try:
                start = Version(self._clean_version(start_excluding))
                has_constraint = True
                if comp_ver <= start:
                    in_range = False
            except InvalidVersion:
                pass

        if end_including:
            try:
                end = Version(self._clean_version(end_including))
                has_constraint = True
                if comp_ver > end:
                    in_range = False
            except InvalidVersion:
                pass

        if has_constraint:
            return in_range

        # No version constraints found
        return None

    def _clean_version(self, version_str: str) -> str:
        """
        Clean version strings for parsing by the packaging library.

        Handles:
        - 'v' prefix: v1.2.3 → 1.2.3
        - Debian suffixes: 1.2.3-1 → 1.2.3
        - RPM suffixes: 1.2.3.el8 → 1.2.3
        - DFSG: 1.2.3+dfsg → 1.2.3
        """
        v = version_str.strip()
        if v.startswith("v"):
            v = v[1:]

        # Remove known suffixes that break version parsing
        for suffix_marker in ["-1", ".el7", ".el8", ".el9", "+dfsg", "~rc", "~beta", "~alpha"]:
            idx = v.find(suffix_marker)
            if idx > 0:
                v = v[:idx]

        return v

    def _list_cpe_products(self, cpe_entries: List[dict]) -> List[str]:
        """List all unique vendor/product pairs from CPE entries."""
        products = set()
        for entry in cpe_entries:
            parsed = self._parse_cpe_string(entry.get("criteria", ""))
            if parsed:
                products.add(f"{parsed.vendor}/{parsed.product}")
        return sorted(products)
