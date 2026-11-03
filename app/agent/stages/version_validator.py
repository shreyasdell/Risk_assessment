"""
Stage 3: Version Range Validator

Deep version range validation that checks whether the component's
version falls within the CVE's stated affected version range.

Handles multiple versioning schemes:
- Semantic versioning: 1.2.3, v1.2.3
- Calendar versioning: 2023.01.01
- Debian: 1.2.3-1, 1.2.3~rc1
- RPM: 1.2.3.el8
- Pre-release: 1.2.3-alpha.1, 1.2.3rc1
"""

from typing import Optional, List, Tuple
import re
import logging

from app.agent.stages.cpe_matcher import MatchVerdict, StageResult

logger = logging.getLogger(__name__)


class VersionValidator:
    """
    Stage 3: Validate whether the component version is within
    the CVE's affected version range.

    This stage assumes product matching has already been confirmed
    (or at least not rejected) by earlier stages.
    """

    def evaluate(self, component: dict, cve: dict) -> StageResult:
        """
        Check component version against CVE version constraints.

        Args:
            component: Component dict with version field.
            cve: Raw CVE object from NVD API.

        Returns:
            StageResult indicating version match status.
        """
        component_version = component.get("version", "")

        if not component_version:
            return StageResult(
                verdict=MatchVerdict.UNCERTAIN,
                confidence=0,
                reasoning="Component has no version information.",
            )

        # Extract all version constraints from CVE
        constraints = self._extract_version_constraints(cve)

        if not constraints:
            return StageResult(
                verdict=MatchVerdict.UNCERTAIN,
                confidence=0,
                reasoning="CVE has no version range constraints in CPE data.",
            )

        # Check each constraint set
        for constraint in constraints:
            result = self._check_version_against_constraint(
                component_version, constraint
            )

            if result is True:
                range_str = self._format_constraint(constraint)
                return StageResult(
                    verdict=MatchVerdict.MATCH,
                    confidence=90,
                    reasoning=(
                        f"Version '{component_version}' falls within "
                        f"affected range: {range_str}"
                    ),
                )
            elif result is False:
                range_str = self._format_constraint(constraint)
                return StageResult(
                    verdict=MatchVerdict.NO_MATCH,
                    confidence=85,
                    reasoning=(
                        f"Version '{component_version}' is outside "
                        f"affected range: {range_str}"
                    ),
                )

        # Could not conclusively check any constraint
        return StageResult(
            verdict=MatchVerdict.UNCERTAIN,
            confidence=20,
            reasoning=(
                f"Version comparison was inconclusive for "
                f"'{component_version}'. Found {len(constraints)} "
                f"constraint(s) but could not parse/compare."
            ),
        )

    # ──────────────────────────────────────────────────────────────
    #  Internal helpers
    # ──────────────────────────────────────────────────────────────

    def _extract_version_constraints(self, cve: dict) -> List[dict]:
        """
        Extract version range constraints from CVE configurations.

        Each constraint is a dict with keys like:
        {
            "start_including": "1.0.0",
            "end_excluding": "2.0.0",
            "cpe_criteria": "cpe:2.3:a:vendor:product:*:..."
        }
        """
        constraints = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if not cpe_match.get("vulnerable", False):
                        continue

                    constraint = {}

                    if "versionStartIncluding" in cpe_match:
                        constraint["start_including"] = cpe_match["versionStartIncluding"]
                    if "versionEndExcluding" in cpe_match:
                        constraint["end_excluding"] = cpe_match["versionEndExcluding"]
                    if "versionStartExcluding" in cpe_match:
                        constraint["start_excluding"] = cpe_match["versionStartExcluding"]
                    if "versionEndIncluding" in cpe_match:
                        constraint["end_including"] = cpe_match["versionEndIncluding"]

                    # Also extract exact version from CPE criteria
                    criteria = cpe_match.get("criteria", "")
                    parts = criteria.split(":") if criteria else []
                    if len(parts) > 5 and parts[5] not in ("*", "-"):
                        constraint["exact_version"] = parts[5]

                    constraint["cpe_criteria"] = criteria

                    if constraint:
                        constraints.append(constraint)

        return constraints

    def _check_version_against_constraint(
        self, version_str: str, constraint: dict
    ) -> Optional[bool]:
        """
        Compare a version string against a single constraint.

        Returns:
            True  — version is within the affected range
            False — version is outside the affected range
            None  — cannot determine
        """
        try:
            from packaging.version import Version, InvalidVersion
        except ImportError:
            logger.warning("packaging library not installed.")
            return None

        # Parse component version
        cleaned = self._clean_version(version_str)
        try:
            comp_ver = Version(cleaned)
        except InvalidVersion:
            logger.debug(f"Cannot parse version '{version_str}' (cleaned: '{cleaned}')")
            return None

        # Exact version match
        exact = constraint.get("exact_version")
        if exact:
            try:
                exact_ver = Version(self._clean_version(exact))
                return comp_ver == exact_ver
            except InvalidVersion:
                pass

        # Range-based matching
        in_range = True
        has_constraint = False

        for key, op in [
            ("start_including", ">="),
            ("end_excluding", "<"),
            ("start_excluding", ">"),
            ("end_including", "<="),
        ]:
            value = constraint.get(key)
            if not value:
                continue

            try:
                bound = Version(self._clean_version(value))
                has_constraint = True

                if op == ">=" and comp_ver < bound:
                    in_range = False
                elif op == "<" and comp_ver >= bound:
                    in_range = False
                elif op == ">" and comp_ver <= bound:
                    in_range = False
                elif op == "<=" and comp_ver > bound:
                    in_range = False

            except InvalidVersion:
                logger.debug(f"Cannot parse bound version '{value}' for constraint {key}")
                continue

        if has_constraint:
            return in_range

        return None

    def _clean_version(self, version_str: str) -> str:
        """
        Normalize version strings for the packaging library.

        Transformations:
        - v1.2.3 → 1.2.3
        - 1.2.3-1 → 1.2.3
        - 1.2.3.el8 → 1.2.3
        - 1.2.3+dfsg → 1.2.3
        - 1.2.3~rc1 → 1.2.3rc1
        """
        v = version_str.strip()

        # Remove 'v' prefix
        if v.startswith("v") or v.startswith("V"):
            v = v[1:]

        # Handle tilde (Debian pre-release): ~rc1 → rc1
        v = v.replace("~", "")

        # Remove +build metadata (keep pre-release)
        if "+" in v:
            v = v.split("+")[0]

        # Remove Debian revision (-1, -2, etc.)
        # But preserve pre-release like -alpha, -beta, -rc
        debian_rev = re.match(r'^(.+?)-(\d+)$', v)
        if debian_rev:
            v = debian_rev.group(1)

        # Remove RPM release suffixes
        for pattern in [r'\.el\d+.*$', r'\.fc\d+.*$', r'\.amzn\d+.*$']:
            v = re.sub(pattern, '', v)

        return v

    def _format_constraint(self, constraint: dict) -> str:
        """Format a constraint as a human-readable string."""
        parts = []

        if "exact_version" in constraint:
            parts.append(f"== {constraint['exact_version']}")

        if "start_including" in constraint:
            parts.append(f">= {constraint['start_including']}")
        if "start_excluding" in constraint:
            parts.append(f"> {constraint['start_excluding']}")
        if "end_excluding" in constraint:
            parts.append(f"< {constraint['end_excluding']}")
        if "end_including" in constraint:
            parts.append(f"<= {constraint['end_including']}")

        return " AND ".join(parts) if parts else "unknown range"
