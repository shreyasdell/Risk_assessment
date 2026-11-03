"""
Stage 2: PURL Ecosystem Resolver

Parses the component's PURL (Package URL) to determine its ecosystem
(npm, pypi, maven, etc.) and cross-references against the CVE's target
ecosystem as indicated by CPE entries.

Key insight: If a component is an npm package but the CVE affects a
Linux kernel module, it's a false positive regardless of name similarity.

PURL Format:
    pkg:{type}/{namespace}/{name}@{version}?{qualifiers}#{subpath}

Examples:
    pkg:npm/carbon@2.1.1
    pkg:pypi/requests@2.28.0
    pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
    pkg:deb/debian/curl@7.74.0-1.3+deb11u1
"""

from dataclasses import dataclass
from typing import Optional, List
import logging

from app.agent.stages.cpe_matcher import MatchVerdict, StageResult

logger = logging.getLogger(__name__)


@dataclass
class PURLComponents:
    """Parsed representation of a Package URL."""
    scheme: str             # always "pkg"
    type: str               # "npm", "pypi", "maven", etc.
    namespace: Optional[str]  # "@scope" for npm, groupId for maven
    name: str               # package name
    version: Optional[str]
    qualifiers: Optional[dict]
    subpath: Optional[str]


class PURLResolver:
    """
    Stage 2: Resolve PURL to ecosystem and cross-reference
    against CVE's target ecosystem.

    If there's a clear ecosystem mismatch, we can reject the CVE
    without further analysis.
    """

    # Mapping from PURL type to expected CPE characteristics
    ECOSYSTEM_MAP = {
        "npm": {
            "cpe_part": "a",
            "expected_target_sw": ["node.js", "nodejs", "*"],
            "vendors": ["nodejs", "npmjs", "npm"],
            "label": "npm (Node.js)",
        },
        "pypi": {
            "cpe_part": "a",
            "expected_target_sw": ["python", "python3", "*"],
            "vendors": ["python", "pypi", "python-pip", "pythonhosted"],
            "label": "PyPI (Python)",
        },
        "maven": {
            "cpe_part": "a",
            "expected_target_sw": ["java", "maven", "*"],
            "vendors": ["apache", "oracle", "eclipse", "spring", "redhat"],
            "label": "Maven (Java)",
        },
        "nuget": {
            "cpe_part": "a",
            "expected_target_sw": [".net", "dotnet", "*"],
            "vendors": ["microsoft", "nuget", "dotnet"],
            "label": "NuGet (.NET)",
        },
        "gem": {
            "cpe_part": "a",
            "expected_target_sw": ["ruby", "*"],
            "vendors": ["ruby", "rubygems", "ruby-lang"],
            "label": "RubyGems (Ruby)",
        },
        "golang": {
            "cpe_part": "a",
            "expected_target_sw": ["go", "golang", "*"],
            "vendors": ["golang", "google"],
            "label": "Go modules",
        },
        "cargo": {
            "cpe_part": "a",
            "expected_target_sw": ["rust", "*"],
            "vendors": ["rust", "rust-lang"],
            "label": "Cargo (Rust)",
        },
        "composer": {
            "cpe_part": "a",
            "expected_target_sw": ["php", "*"],
            "vendors": ["php", "composer"],
            "label": "Composer (PHP)",
        },
        "swift": {
            "cpe_part": "a",
            "expected_target_sw": ["swift", "ios", "macos", "*"],
            "vendors": ["apple", "swift"],
            "label": "Swift Package Manager",
        },
        "deb": {
            "cpe_part": "o",
            "expected_target_sw": ["*"],
            "vendors": ["debian", "ubuntu", "canonical"],
            "label": "Debian/Ubuntu package",
        },
        "rpm": {
            "cpe_part": "o",
            "expected_target_sw": ["*"],
            "vendors": ["redhat", "fedoraproject", "centos", "suse", "opensuse"],
            "label": "RPM package",
        },
        "apk": {
            "cpe_part": "o",
            "expected_target_sw": ["*"],
            "vendors": ["alpine"],
            "label": "Alpine APK",
        },
    }

    # CPE products that are clearly OS/kernel level
    KERNEL_PRODUCTS = {
        "linux_kernel", "kernel", "linux",
        "ubuntu_linux", "debian_linux", "enterprise_linux",
        "fedora", "centos", "suse_linux",
        "windows", "windows_10", "windows_11", "windows_server",
        "macos", "mac_os_x", "ios", "android",
    }

    # CPE vendors that are OS vendors
    OS_VENDORS = {
        "linux", "microsoft", "apple", "google",
        "canonical", "debian", "redhat", "fedoraproject",
        "suse", "opensuse", "centos", "alpine",
    }

    # Application-level PURL types (not OS packages)
    APPLICATION_ECOSYSTEMS = {
        "npm", "pypi", "maven", "nuget", "gem",
        "golang", "cargo", "composer", "swift",
        "cocoapods", "pub", "hex", "hackage",
    }

    def evaluate(self, component: dict, cve: dict) -> StageResult:
        """
        Evaluate ecosystem compatibility between component and CVE.

        Args:
            component: Component dict with purl and ecosystem fields.
            cve: Raw CVE object from NVD API.

        Returns:
            StageResult indicating ecosystem match/mismatch.
        """
        purl_str = component.get("purl", "")
        purl = self._parse_purl(purl_str) if purl_str else None

        # Also accept ecosystem passed directly
        ecosystem = None
        if purl:
            ecosystem = purl.type
        elif component.get("ecosystem"):
            ecosystem = component["ecosystem"].lower()

        if not ecosystem:
            return StageResult(
                verdict=MatchVerdict.UNCERTAIN,
                confidence=0,
                reasoning=(
                    "No PURL or ecosystem information available for component; "
                    "cannot determine ecosystem compatibility."
                ),
            )

        ecosystem_info = self.ECOSYSTEM_MAP.get(ecosystem)
        if not ecosystem_info:
            return StageResult(
                verdict=MatchVerdict.UNCERTAIN,
                confidence=0,
                reasoning=f"Unknown ecosystem '{ecosystem}'; cannot cross-reference.",
            )

        # Extract CPE entries from CVE
        cpe_entries = self._extract_cpe_entries(cve)

        if not cpe_entries:
            return StageResult(
                verdict=MatchVerdict.UNCERTAIN,
                confidence=0,
                reasoning="CVE has no CPE data to cross-reference against ecosystem.",
            )

        # Cross-reference ecosystem against CPE entries
        for entry in cpe_entries:
            parsed = self._parse_cpe_quick(entry.get("criteria", ""))
            if not parsed:
                continue

            cpe_part, cpe_vendor, cpe_product, cpe_target_sw = parsed

            # ── CRITICAL CHECK 1: Application package vs OS/kernel CVE ──
            if ecosystem in self.APPLICATION_ECOSYSTEMS:
                # Component is an application-level package

                if cpe_part == "o":
                    # CVE affects an operating system
                    return StageResult(
                        verdict=MatchVerdict.NO_MATCH,
                        confidence=90,
                        reasoning=(
                            f"Component is a {ecosystem_info['label']} package "
                            f"(application-level) but CVE affects OS-level product "
                            f"'{cpe_vendor}/{cpe_product}' (CPE part='o'). "
                            f"Ecosystem mismatch."
                        ),
                    )

                if cpe_product in self.KERNEL_PRODUCTS:
                    return StageResult(
                        verdict=MatchVerdict.NO_MATCH,
                        confidence=95,
                        reasoning=(
                            f"Component is a {ecosystem_info['label']} package but "
                            f"CVE affects kernel/OS product '{cpe_product}'. "
                            f"Clear ecosystem mismatch."
                        ),
                    )

                if cpe_part == "h":
                    # CVE affects hardware
                    return StageResult(
                        verdict=MatchVerdict.NO_MATCH,
                        confidence=92,
                        reasoning=(
                            f"Component is a {ecosystem_info['label']} package but "
                            f"CVE affects hardware (CPE part='h'): "
                            f"'{cpe_vendor}/{cpe_product}'. "
                            f"Ecosystem mismatch."
                        ),
                    )

            # ── CRITICAL CHECK 2: OS package vs application CVE ──
            if ecosystem in ("deb", "rpm", "apk"):
                # Component is an OS-level package
                if cpe_part == "a" and cpe_vendor not in self.OS_VENDORS:
                    # CVE is for an application by a non-OS vendor
                    # This is less definitive, so lower confidence
                    pass  # Let it through as UNCERTAIN

        # No definitive ecosystem mismatch found
        return StageResult(
            verdict=MatchVerdict.UNCERTAIN,
            confidence=30,
            reasoning=(
                f"Ecosystem cross-reference inconclusive. "
                f"Component ecosystem: {ecosystem_info['label']}. "
                f"No clear ecosystem mismatch detected in CPE entries."
            ),
        )

    # ──────────────────────────────────────────────────────────────
    #  Internal helpers
    # ──────────────────────────────────────────────────────────────

    def _parse_purl(self, purl_str: str) -> Optional[PURLComponents]:
        """
        Parse a Package URL string into components.

        Examples:
            pkg:npm/carbon@2.1.1
            pkg:npm/%40scope/name@1.0.0
            pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
            pkg:pypi/requests@2.28.0?repository_url=https://pypi.org
        """
        if not purl_str or not purl_str.startswith("pkg:"):
            return None

        try:
            remainder = purl_str[4:]  # Remove "pkg:"

            # Extract type
            slash_idx = remainder.index("/")
            purl_type = remainder[:slash_idx].lower()
            remainder = remainder[slash_idx + 1:]

            # Remove qualifiers and subpath for name/version parsing
            qualifiers = None
            subpath = None

            if "#" in remainder:
                hash_idx = remainder.index("#")
                subpath = remainder[hash_idx + 1:]
                remainder = remainder[:hash_idx]

            if "?" in remainder:
                q_idx = remainder.index("?")
                qualifier_str = remainder[q_idx + 1:]
                qualifiers = dict(
                    pair.split("=", 1) for pair in qualifier_str.split("&")
                    if "=" in pair
                )
                remainder = remainder[:q_idx]

            # Extract version
            version = None
            if "@" in remainder:
                at_idx = remainder.rindex("@")  # Use rindex for last @
                version = remainder[at_idx + 1:]
                remainder = remainder[:at_idx]

            # Extract namespace and name
            namespace = None
            name = remainder
            if "/" in remainder:
                last_slash = remainder.rindex("/")
                namespace = remainder[:last_slash]
                name = remainder[last_slash + 1:]

            # URL-decode name
            import urllib.parse
            name = urllib.parse.unquote(name)
            if namespace:
                namespace = urllib.parse.unquote(namespace)

            return PURLComponents(
                scheme="pkg",
                type=purl_type,
                namespace=namespace,
                name=name,
                version=version,
                qualifiers=qualifiers,
                subpath=subpath,
            )
        except (ValueError, IndexError) as e:
            logger.debug(f"Failed to parse PURL '{purl_str}': {e}")
            return None

    def _extract_cpe_entries(self, cve: dict) -> List[dict]:
        """Extract vulnerable CPE entries from CVE."""
        entries = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable", False):
                        entries.append(cpe_match)
        return entries

    def _parse_cpe_quick(self, cpe_str: str):
        """
        Quick CPE parse returning only the fields needed for ecosystem check.

        Returns: (part, vendor, product, target_sw) or None
        """
        if not cpe_str or not cpe_str.startswith("cpe:2.3:"):
            return None

        parts = cpe_str.split(":")
        if len(parts) < 6:
            return None

        part = parts[2]
        vendor = parts[3].lower()
        product = parts[4].lower()
        target_sw = parts[10].lower() if len(parts) > 10 else "*"

        return (part, vendor, product, target_sw)
