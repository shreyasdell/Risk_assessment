"""
Component Name Normalizer

Three-tier approach for normalizing component names and identifying vendors:
- Tier 1: Deterministic PURL parsing (fast, covers ~70%)
- Tier 2: Static lookup table (fast, covers top 200 common packages)
- Tier 3: LLM via Ollama (slow, cached, for ambiguous cases)
"""

import re
import httpx
from typing import Optional, Tuple, Dict
from sqlalchemy.orm import Session

from app.models.component import Component


class ComponentNormalizer:
    """
    Normalizes component names from different ecosystems into
    canonical NVD-searchable names and identifies vendors.
    """

    def __init__(self, ollama_url: str = "http://localhost:11434", model: str = "qwen2.5:7b"):
        self.ollama_url = ollama_url
        self.model = model
        self.lookup_table = self._build_lookup_table()

    def normalize_component(
        self,
        component: Component,
        db: Session
    ) -> Tuple[str, str, str]:
        """
        Normalize a component name and identify its vendor.

        Args:
            component: Component database record
            db: Database session

        Returns:
            Tuple of (normalized_name, identified_vendor, method_used)
        """
        # Check if already normalized
        if component.normalized_name and component.identified_vendor:
            return component.normalized_name, component.identified_vendor, "cached"

        raw_name = component.name
        purl = component.purl
        cpe = component.cpe
        supplier = component.supplier

        # Tier 1: Deterministic PURL parsing
        normalized, vendor = self._tier1_purl_parse(raw_name, purl, cpe, supplier)
        if normalized and vendor:
            self._save_normalization(db, component, normalized, vendor, "tier1_purl")
            return normalized, vendor, "tier1_purl"

        # Tier 2: Static lookup table
        normalized, vendor = self._tier2_lookup(raw_name, purl, cpe, supplier)
        if normalized and vendor:
            self._save_normalization(db, component, normalized, vendor, "tier2_lookup")
            return normalized, vendor, "tier2_lookup"

        # Tier 3: LLM via Ollama (last resort) - run async in sync context
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If loop is already running, create new one
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            normalized, vendor = loop.run_until_complete(
                self._tier3_llm(raw_name, purl, cpe, supplier)
            )
        except RuntimeError:
            # No event loop, create one
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            normalized, vendor = loop.run_until_complete(
                self._tier3_llm(raw_name, purl, cpe, supplier)
            )

        if normalized and vendor:
            self._save_normalization(db, component, normalized, vendor, "tier3_llm")
            return normalized, vendor, "tier3_llm"

        # Fallback: return original name
        self._save_normalization(db, component, raw_name, supplier or "Unknown", "fallback")
        return raw_name, supplier or "Unknown", "fallback"

    def get_search_name(self, display_name: str) -> str:
        """
        Convert display name (vendor/package) to NVD-searchable format.

        Logic:
        1. If name starts with "@" (npm scoped): keep as-is
        2. If name contains "/" (vendor/package format):
           - Check if vendor is redundant (contained in package name)
           - If redundant: return package name only
           - If not redundant: return "vendor package" (slash to space)
        3. If no slash: return as-is

        Examples:
        - laravel/framework → "laravel framework" (both needed)
        - guzzlehttp/guzzle → "guzzle" (redundant vendor)
        - symfony/process → "symfony process" (both needed)
        - @aws-sdk/client-ses → "@aws-sdk/client-ses" (npm scoped, keep as-is)
        - apache/log4j-core → "apache log4j-core" (both needed)
        - gnu/gcc → "gcc" (redundant vendor)
        """
        # Keep npm scoped packages as-is
        if display_name.startswith("@"):
            return display_name

        if "/" not in display_name:
            return display_name

        # Split vendor/package
        vendor, package = display_name.split("/", 1)

        # Check redundancy: is vendor name contained in package name?
        # guzzlehttp/guzzle → "guzzlehttp" is in "guzzle" (yes, redundant)
        # laravel/framework → "laravel" is NOT in "framework" (no, not redundant)
        if vendor.lower() in package.lower():
            # Vendor is redundant, return package only
            return package
        else:
            # Vendor and package are different, convert slash to space
            return f"{vendor} {package}"

    def _tier1_purl_parse(
        self,
        raw_name: str,
        purl: Optional[str],
        cpe: Optional[str],
        supplier: Optional[str]
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Tier 1: Deterministic PURL parsing.

        Always returns vendor/package format for display name.
        The get_search_name() method will convert to NVD-searchable format.

        PURL format: pkg:type/namespace/name@version
        Examples:
        - pkg:golang/github.com/Microsoft/hcsshim@v0.11.7
        - pkg:npm/%40aws-sdk/client-ses@3.194.0
        - pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
        - pkg:composer/laravel/framework@7.30.6
        """
        # Check if raw_name is already in vendor/package format (from parser)
        if "/" in raw_name and not raw_name.startswith("@"):
            # Extract vendor from vendor/package format
            vendor, package = raw_name.split("/", 1)
            # Map vendor to proper name
            if purl and "composer" in purl:
                mapped_vendor = self._map_composer_vendor(vendor)
                return raw_name, mapped_vendor
            else:
                return raw_name, vendor.title()

        if not purl or not purl.startswith("pkg:"):
            return None, None

        try:
            # Extract type and path
            parts = purl[4:].split("@")[0]  # Remove version
            purl_type, path = parts.split("/", 1)

            # Handle different ecosystem patterns
            # Always return vendor/package format for display name

            if purl_type == "golang":
                # pkg:golang/github.com/Microsoft/hcsshim
                # Extract: vendor = Microsoft, name = hcsshim
                # Return: display_name = "microsoft/hcsshim", vendor = Microsoft
                path_parts = path.split("/")
                if len(path_parts) >= 3:
                    vendor = path_parts[1]  # github.com/Microsoft/hcsshim -> Microsoft
                    name = path_parts[-1]     # hcsshim
                    return f"{vendor.lower()}/{name}", vendor

            elif purl_type == "npm":
                # pkg:npm/%40aws-sdk/client-ses or pkg:npm/semver
                # Extract: vendor = aws-sdk, name = client-ses
                # Return: display_name = "@aws-sdk/client-ses" or "semver", vendor = AWS
                path = path.replace("%40", "@")  # Decode @
                if "/" in path:
                    vendor, name = path.split("/", 1)
                    vendor = vendor.lstrip("@")  # Remove @ prefix
                    # Keep @ for scoped packages: @aws-sdk/client-ses
                    if path.startswith("@"):
                        return path, self._map_npm_vendor(vendor)
                    else:
                        return f"{vendor}/{name}", self._map_npm_vendor(vendor)
                else:
                    return path, self._map_npm_vendor(path)

            elif purl_type == "maven":
                # pkg:maven/org.apache.logging.log4j/log4j-core
                # Extract: vendor = Apache, name = log4j-core
                # Return: display_name = "apache/log4j-core", vendor = Apache
                parts = path.split("/")
                if len(parts) >= 2:
                    group_id = parts[0]
                    artifact_id = parts[-1]
                    vendor = self._extract_vendor_from_group(group_id)
                    return f"{vendor.lower()}/{artifact_id}", vendor

            elif purl_type == "composer":
                # pkg:composer/guzzlehttp/guzzle
                # Extract: vendor = GuzzleHTTP, name = guzzle
                # Return: display_name = "guzzlehttp/guzzle", vendor = GuzzleHTTP
                if "/" in path:
                    vendor, name = path.split("/", 1)
                    return f"{vendor}/{name}", self._map_composer_vendor(vendor)

            elif purl_type in ["apk", "alpine"]:
                # pkg:apk/alpine/libgcc
                # Extract: vendor = GNU, name = gcc
                # Return: display_name = "gnu/gcc", vendor = GNU
                name = path.split("/")[-1]
                vendor = self._map_alpine_vendor(name)
                package = self._map_alpine_package(name)
                return f"{vendor.lower()}/{package}", vendor

            elif purl_type in ["deb", "debian", "ubuntu"]:
                # pkg:deb/debian/libaudit-common
                # Extract: vendor = Linux Audit Project, name = audit
                # Return: display_name = "linux audit project/audit", vendor = Linux Audit Project
                name = path.split("/")[-1]
                vendor = self._map_debian_vendor(name)
                package = self._map_debian_package(name)
                return f"{vendor.lower()}/{package}", vendor

            elif purl_type == "pypi":
                # pkg:pypi/Flask
                # Extract: vendor = Pallets, name = Flask
                # Return: display_name = "pallets/flask", vendor = Pallets
                name = path.split("/")[-1]
                vendor = self._map_pypi_vendor(name)
                return f"{vendor.lower()}/{name}", vendor

        except Exception as e:
            print(f"[Normalizer] Tier 1 parsing failed: {e}")

        return None, None

    def _tier2_lookup(
        self,
        raw_name: str,
        purl: Optional[str],
        cpe: Optional[str],
        supplier: Optional[str]
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Tier 2: Static lookup table for top 200 common packages.
        """
        # Normalize key for lookup
        key = raw_name.lower().strip()

        # Check lookup table
        if key in self.lookup_table:
            return self.lookup_table[key]

        # Try with PURL name if available
        if purl:
            try:
                purl_name = purl.split("/")[-1].split("@")[0].lower()
                if purl_name in self.lookup_table:
                    return self.lookup_table[purl_name]
            except:
                pass

        return None, None

    async def _tier3_llm(
        self,
        raw_name: str,
        purl: Optional[str],
        cpe: Optional[str],
        supplier: Optional[str]
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Tier 3: LLM via Ollama for ambiguous cases.

        This is only called when Tier 1 and Tier 2 fail.
        """
        prompt = f"""You are a software package normalization expert. Given a component name and its metadata, extract:
1. The canonical product name (short, NVD-searchable)
2. The vendor/organization that maintains it

Component: {raw_name}
PURL: {purl or 'N/A'}
CPE: {cpe or 'N/A'}
Supplier: {supplier or 'N/A'}

Respond in JSON format:
{{"normalized_name": "string", "vendor": "string"}}

Examples:
- github.com/Microsoft/hcsshim -> {{"normalized_name": "microsoft hcsshim", "vendor": "Microsoft"}}
- @aws-sdk/client-ses -> {{"normalized_name": "aws-sdk client-ses", "vendor": "Amazon Web Services"}}
- org.apache.logging.log4j -> {{"normalized_name": "apache log4j", "vendor": "Apache Software Foundation"}}
- libaudit-common -> {{"normalized_name": "audit", "vendor": "Linux Audit Project"}}"""

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    f"{self.ollama_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json"
                    }
                )

                if response.status_code == 200:
                    result = response.json()
                    # Parse the LLM response
                    content = result.get("response", "{}")
                    # Extract JSON from response
                    import json
                    try:
                        parsed = json.loads(content)
                        normalized = parsed.get("normalized_name", "").strip()
                        vendor = parsed.get("vendor", "").strip()
                        if normalized and vendor:
                            return normalized, vendor
                    except json.JSONDecodeError:
                        # Try to extract JSON from text
                        match = re.search(r'\{[^}]+\}', content)
                        if match:
                            parsed = json.loads(match.group())
                            normalized = parsed.get("normalized_name", "").strip()
                            vendor = parsed.get("vendor", "").strip()
                            if normalized and vendor:
                                return normalized, vendor

        except Exception as e:
            print(f"[Normalizer] Tier 3 LLM failed: {e}")

        return None, None

    def _save_normalization(
        self,
        db: Session,
        component: Component,
        normalized_name: str,
        vendor: str,
        method: str
    ):
        """Save normalization result to database."""
        component.normalized_name = normalized_name
        component.identified_vendor = vendor
        db.commit()

    def _build_lookup_table(self) -> Dict[str, Tuple[str, str]]:
        """
        Build static lookup table for top 200 common packages.
        Returns dict mapping lowercase name -> (normalized_name, vendor)
        """
        table = {
            # Common npm packages
            "react": ("react", "Meta"),
            "react-dom": ("react-dom", "Meta"),
            "angular": ("angular", "Google"),
            "@angular/core": ("angular core", "Google"),
            "vue": ("vue", "Vue.js"),
            "lodash": ("lodash", "OpenJS Foundation"),
            "axios": ("axios", "Axios"),
            "express": ("express", "OpenJS Foundation"),
            "moment": ("moment", "Moment.js"),
            "webpack": ("webpack", "Webpack"),
            "babel": ("babel", "Babel"),
            "typescript": ("typescript", "Microsoft"),
            "@types/node": ("typescript node", "Microsoft"),
            "eslint": ("eslint", "OpenJS Foundation"),
            "prettier": ("prettier", "Prettier"),
            "jest": ("jest", "Meta"),
            "mobx": ("mobx", "MobX"),
            "redux": ("redux", "Redux"),
            "next.js": ("next.js", "Vercel"),
            "gatsby": ("gatsby", "Gatsby"),
            "nuxt": ("nuxt", "Nuxt"),
            "svelte": ("svelte", "Svelte"),
            "solid-js": ("solid-js", "SolidJS"),
            "qwik": ("qwik", "Builder.io"),
            "astro": ("astro", "Astro"),
            "remix": ("remix", "Shopify"),
            
            # Common Python packages
            "flask": ("flask", "Pallets"),
            "django": ("django", "Django Software Foundation"),
            "requests": ("requests", "Kenneth Reitz"),
            "numpy": ("numpy", "NumPy"),
            "pandas": ("pandas", "Pandas"),
            "scipy": ("scipy", "SciPy"),
            "matplotlib": ("matplotlib", "Matplotlib"),
            "pillow": ("pillow", "Pillow"),
            "sqlalchemy": ("sqlalchemy", "SQLAlchemy"),
            "pytest": ("pytest", "Pytest"),
            "celery": ("celery", "Celery"),
            "gunicorn": ("gunicorn", "Gunicorn"),
            "uwsgi": ("uwsgi", "uWSGI"),
            "fastapi": ("fastapi", "FastAPI"),
            "tornado": ("tornado", "Tornado"),
            "aiohttp": ("aiohttp", "AIOHTTP"),
            "httpx": ("httpx", "HTTPX"),
            "pydantic": ("pydantic", "Pydantic"),
            "typer": ("typer", "Typer"),
            "rich": ("rich", "Rich"),
            "click": ("click", "Click"),
            "poetry": ("poetry", "Python Poetry"),
            "pip": ("pip", "PyPA"),
            "setuptools": ("setuptools", "PyPA"),
            "wheel": ("wheel", "PyPA"),
            "virtualenv": ("virtualenv", "PyPA"),
            
            # Common Java/Maven packages
            "log4j": ("log4j", "Apache Software Foundation"),
            "log4j-core": ("log4j-core", "Apache Software Foundation"),
            "log4j-api": ("log4j-api", "Apache Software Foundation"),
            "spring-boot": ("spring boot", "VMware"),
            "spring-framework": ("spring framework", "VMware"),
            "spring-core": ("spring core", "VMware"),
            "jackson": ("jackson", "FasterXML"),
            "jackson-databind": ("jackson-databind", "FasterXML"),
            "jackson-core": ("jackson-core", "FasterXML"),
            "hibernate": ("hibernate", "Red Hat"),
            "struts": ("struts", "Apache Software Foundation"),
            "tomcat": ("tomcat", "Apache Software Foundation"),
            "jetty": ("jetty", "Eclipse Foundation"),
            "maven": ("maven", "Apache Software Foundation"),
            "gradle": ("gradle", "Gradle"),
            "ant": ("ant", "Apache Software Foundation"),
            "commons-lang": ("commons-lang", "Apache Software Foundation"),
            "commons-io": ("commons-io", "Apache Software Foundation"),
            "commons-text": ("commons-text", "Apache Software Foundation"),
            "guava": ("guava", "Google"),
            "gson": ("gson", "Google"),
            
            # Common Go packages
            "golang.org/x/net": ("golang net", "Go Team"),
            "golang.org/x/sys": ("golang sys", "Go Team"),
            "golang.org/x/text": ("golang text", "Go Team"),
            "github.com/golang/protobuf": ("protobuf", "Go Team"),
            "github.com/gorilla/mux": ("gorilla mux", "Gorilla"),
            "github.com/gin-gonic/gin": ("gin", "Gin"),
            "github.com/labstack/echo": ("echo", "Labstack"),
            "github.com/stretchr/testify": ("testify", "Testify"),
            
            # Common PHP/Composer packages
            "guzzle": ("guzzle", "GuzzleHTTP"),
            "guzzlehttp/guzzle": ("guzzle", "GuzzleHTTP"),
            "guzzlehttp/guzzlehttp": ("guzzlehttp", "GuzzleHTTP"),
            "monolog": ("monolog", "Monolog"),
            "symfony": ("symfony", "Symfony"),
            "laravel": ("laravel", "Laravel"),
            "doctrine": ("doctrine", "Doctrine"),
            "twig": ("twig", "Twig"),
            "smarty": ("smarty", "Smarty"),
            
            # Common system packages (Alpine/Debian)
            "libgcc": ("gcc", "GNU"),
            "libstdc++": ("gcc", "GNU"),
            "glibc": ("glibc", "GNU"),
            "openssl": ("openssl", "OpenSSL Project"),
            "libssl": ("openssl", "OpenSSL Project"),
            "libcrypto": ("openssl", "OpenSSL Project"),
            "zlib": ("zlib", "zlib"),
            "libz": ("zlib", "zlib"),
            "libxml2": ("libxml2", "XMLSoft"),
            "libxslt": ("libxslt", "XMLSoft"),
            "libcurl": ("curl", "Daniel Stenberg"),
            "curl": ("curl", "Daniel Stenberg"),
            "libaudit": ("audit", "Linux Audit Project"),
            "libaudit-common": ("audit", "Linux Audit Project"),
            "e2fsprogs": ("e2fsprogs", "Theodore Ts'o"),
            "libe2fs": ("e2fsprogs", "Theodore Ts'o"),
            "openssh": ("openssh", "OpenBSD"),
            "libssh": ("libssh", "libssh"),
            "readline": ("readline", "GNU"),
            "ncurses": ("ncurses", "GNU"),
            "libncurses": ("ncurses", "GNU"),
            "sqlite": ("sqlite", "SQLite Consortium"),
            "libsqlite": ("sqlite", "SQLite Consortium"),
            "postgresql": ("postgresql", "PostgreSQL Global Development Group"),
            "libpq": ("postgresql", "PostgreSQL Global Development Group"),
            "mysql": ("mysql", "Oracle"),
            "libmysqlclient": ("mysql", "Oracle"),
            "mariadb": ("mariadb", "MariaDB Foundation"),
            "libmariadb": ("mariadb", "MariaDB Foundation"),
            "redis": ("redis", "Redis Labs"),
            "nginx": ("nginx", "Nginx"),
            "apache2": ("apache", "Apache Software Foundation"),
            "httpd": ("apache", "Apache Software Foundation"),
            "lighttpd": ("lighttpd", "Lighttpd"),
            "bash": ("bash", "GNU"),
            "coreutils": ("coreutils", "GNU"),
            "util-linux": ("util-linux", "Karel Zak"),
            "procps": ("procps", "Procps-ng"),
            "psmisc": ("psmisc", "Psmisc"),
            "shadow": ("shadow", "Shadow"),
            "iproute2": ("iproute2", "iproute2"),
            "iptables": ("iptables", "Netfilter"),
            "nftables": ("nftables", "Netfilter"),
            "systemd": ("systemd", "systemd"),
            "dbus": ("dbus", "freedesktop.org"),
            "libdbus": ("dbus", "freedesktop.org"),
            "glib": ("glib", "GNOME"),
            "libglib": ("glib", "GNOME"),
            "gtk": ("gtk", "GNOME"),
            "libgtk": ("gtk", "GNOME"),
            "qt5": ("qt", "Qt Company"),
            "qt6": ("qt", "Qt Company"),
            "libqt5": ("qt", "Qt Company"),
            "libqt6": ("qt", "Qt Company"),
            "ffmpeg": ("ffmpeg", "FFmpeg"),
            "libavcodec": ("ffmpeg", "FFmpeg"),
            "libavformat": ("ffmpeg", "FFmpeg"),
            "imagemagick": ("imagemagick", "ImageMagick"),
            "libmagick": ("imagemagick", "ImageMagick"),
            "poppler": ("poppler", "Poppler"),
            "libpoppler": ("poppler", "Poppler"),
            "fontconfig": ("fontconfig", "Keith Packard"),
            "libfontconfig": ("fontconfig", "Keith Packard"),
            "freetype": ("freetype", "David Turner"),
            "libfreetype": ("freetype", "David Turner"),
            "harfbuzz": ("harfbuzz", "Behdad Esfahbod"),
            "libharfbuzz": ("harfbuzz", "Behdad Esfahbod"),
            "graphite": ("graphite", "Graphite"),
            "libgraphite": ("graphite", "Graphite"),
            "pango": ("pango", "GNOME"),
            "libpango": ("pango", "GNOME"),
            "cairo": ("cairo", "Cairo"),
            "libcairo": ("cairo", "Cairo"),
            "pixman": ("pixman", "Pixman"),
            "libpixman": ("pixman", "Pixman"),
            "libpng": ("libpng", "PNG Group"),
            "libjpeg": ("libjpeg", "Independent JPEG Group"),
            "libtiff": ("libtiff", "Libtiff"),
            "lcms": ("lcms", "Little CMS"),
            "liblcms": ("lcms", "Little CMS"),
            "openjpeg": ("openjpeg", "UCLouvain"),
            "libopenjp2": ("openjpeg", "UCLouvain"),
            "libwebp": ("libwebp", "WebP"),
            "libjbig": ("jbig", "ISO/IEC"),
            "liblzma": ("xz", "XZ Utils"),
            "xz": ("xz", "XZ Utils"),
            "libbz2": ("bzip2", "Julian Seward"),
            "bzip2": ("bzip2", "Julian Seward"),
            "liblz4": ("lz4", "LZ4"),
            "lz4": ("lz4", "LZ4"),
            "libzstd": ("zstd", "Facebook"),
            "zstd": ("zstd", "Facebook"),
            "libidn": ("libidn", "Simon Josefsson"),
            "libunistring": ("libunistring", "GNU"),
            "libpcre": ("pcre", "PCRE"),
            "pcre": ("pcre", "PCRE"),
            "libpcre2": ("pcre2", "PCRE"),
            "pcre2": ("pcre2", "PCRE"),
            "libexpat": ("expat", "Expat"),
            "expat": ("expat", "Expat"),
            "libgcrypt": ("libgcrypt", "GnuPG"),
            "libgpg-error": ("libgpg-error", "GnuPG"),
            "gnutls": ("gnutls", "GnuTLS"),
            "libgnutls": ("gnutls", "GnuTLS"),
            "nettle": ("nettle", "Nettle"),
            "libnettle": ("nettle", "Nettle"),
            "hogweed": ("hogweed", "Nettle"),
            "libhogweed": ("hogweed", "Nettle"),
            "gmp": ("gmp", "GNU"),
            "libgmp": ("gmp", "GNU"),
            "mpfr": ("mpfr", "MPFR"),
            "libmpfr": ("mpfr", "MPFR"),
            "mpc": ("mpc", "MPC"),
            "libmpc": ("mpc", "MPC"),
            "isl": ("isl", "Sven Verdoolaege"),
            "libisl": ("isl", "Sven Verdoolaege"),
            "cloog": ("cloog", "CLooG"),
            "libcloog": ("cloog", "CLooG"),
            "libtool": ("libtool", "GNU"),
            "autoconf": ("autoconf", "GNU"),
            "automake": ("automake", "GNU"),
            "m4": ("m4", "GNU"),
            "bison": ("bison", "GNU"),
            "flex": ("flex", "The Flex Project"),
            "make": ("make", "GNU"),
            "cmake": ("cmake", "Kitware"),
            "ninja": ("ninja", "Kitware"),
            "meson": ("meson", "Meson"),
            "scons": ("scons", "SCons"),
            "waf": ("waf", "Waf"),
            "rake": ("rake", "Ruby"),
            "ruby": ("ruby", "Ruby"),
            "perl": ("perl", "Perl"),
            "python": ("python", "Python Software Foundation"),
            "python3": ("python", "Python Software Foundation"),
            "libpython": ("python", "Python Software Foundation"),
            "nodejs": ("node", "OpenJS Foundation"),
            "node": ("node", "OpenJS Foundation"),
            "npm": ("npm", "npm"),
            "yarn": ("yarn", "Yarn"),
            "pnpm": ("pnpm", "pnpm"),
            "rust": ("rust", "Rust"),
            "cargo": ("cargo", "Rust"),
            "go": ("go", "Go Team"),
            "libgo": ("go", "Go Team"),
            "java": ("java", "Oracle"),
            "openjdk": ("java", "Oracle"),
            "libjvm": ("java", "Oracle"),
            "libjava": ("java", "Oracle"),
            "kotlin": ("kotlin", "JetBrains"),
            "scala": ("scala", "Scala"),
            "groovy": ("groovy", "Apache Software Foundation"),
            "gradle": ("gradle", "Gradle"),
            "ant": ("ant", "Apache Software Foundation"),
            "maven": ("maven", "Apache Software Foundation"),
            "ivy": ("ivy", "Apache Software Foundation"),
            "leiningen": ("leiningen", "Leiningen"),
            "boot": ("boot", "Leiningen"),
        }
        return table

    def _map_npm_vendor(self, vendor: str) -> str:
        """Map npm vendor names to canonical vendor."""
        vendor_map = {
            "aws-sdk": "Amazon Web Services",
            "angular": "Google",
            "react": "Meta",
            "vue": "Vue.js",
            "next": "Vercel",
            "gatsby": "Gatsby",
            "nuxt": "Nuxt",
            "svelte": "Svelte",
            "solid-js": "SolidJS",
            "qwik": "Builder.io",
            "astro": "Astro",
            "remix": "Shopify",
            "express": "OpenJS Foundation",
            "lodash": "OpenJS Foundation",
            "moment": "Moment.js",
            "webpack": "Webpack",
            "babel": "Babel",
            "eslint": "OpenJS Foundation",
            "prettier": "Prettier",
            "jest": "Meta",
            "mobx": "MobX",
            "redux": "Redux",
        }
        return vendor_map.get(vendor.lower(), vendor)

    def _map_composer_vendor(self, vendor: str) -> str:
        """Map Composer vendor names to canonical vendor."""
        vendor_map = {
            "guzzlehttp": "GuzzleHTTP",
            "symfony": "Symfony",
            "laravel": "Laravel",
            "doctrine": "Doctrine",
            "twig": "Twig",
            "smarty": "Smarty",
            "monolog": "Monolog",
        }
        return vendor_map.get(vendor.lower(), vendor)

    def _map_alpine_package(self, name: str) -> str:
        """Map Alpine package names to canonical names."""
        # Remove lib prefix for some packages
        if name.startswith("lib"):
            base = name[3:]
            # Map common lib prefixes
            if base in ["gcc", "ssl", "crypto", "z", "xml2", "xslt", "curl", "audit"]:
                return base
        return name

    def _map_alpine_vendor(self, name: str) -> str:
        """Map Alpine packages to vendors."""
        vendor_map = {
            "libgcc": "GNU",
            "glibc": "GNU",
            "openssl": "OpenSSL Project",
            "libssl": "OpenSSL Project",
            "libcrypto": "OpenSSL Project",
            "zlib": "zlib",
            "libz": "zlib",
            "libxml2": "XMLSoft",
            "libxslt": "XMLSoft",
            "libcurl": "Daniel Stenberg",
            "curl": "Daniel Stenberg",
            "libaudit": "Linux Audit Project",
            "libaudit-common": "Linux Audit Project",
            "e2fsprogs": "Theodore Ts'o",
            "libe2fs": "Theodore Ts'o",
            "openssh": "OpenBSD",
            "libssh": "libssh",
            "readline": "GNU",
            "ncurses": "GNU",
            "libncurses": "GNU",
            "sqlite": "SQLite Consortium",
            "libsqlite": "SQLite Consortium",
            "postgresql": "PostgreSQL Global Development Group",
            "libpq": "PostgreSQL Global Development Group",
            "mysql": "Oracle",
            "libmysqlclient": "Oracle",
            "mariadb": "MariaDB Foundation",
            "libmariadb": "MariaDB Foundation",
            "redis": "Redis Labs",
            "nginx": "Nginx",
            "apache2": "Apache Software Foundation",
            "httpd": "Apache Software Foundation",
            "lighttpd": "Lighttpd",
            "bash": "GNU",
            "coreutils": "GNU",
            "util-linux": "Karel Zak",
            "procps": "Procps-ng",
            "psmisc": "Psmisc",
            "shadow": "Shadow",
            "iproute2": "iproute2",
            "iptables": "Netfilter",
            "nftables": "Netfilter",
            "systemd": "systemd",
            "dbus": "freedesktop.org",
            "libdbus": "freedesktop.org",
            "glib": "GNOME",
            "libglib": "GNOME",
            "gtk": "GNOME",
            "libgtk": "GNOME",
            "qt5": "Qt Company",
            "qt6": "Qt Company",
            "libqt5": "Qt Company",
            "libqt6": "Qt Company",
            "ffmpeg": "FFmpeg",
            "libavcodec": "FFmpeg",
            "libavformat": "FFmpeg",
            "imagemagick": "ImageMagick",
            "libmagick": "ImageMagick",
            "poppler": "Poppler",
            "libpoppler": "Poppler",
            "fontconfig": "Keith Packard",
            "libfontconfig": "Keith Packard",
            "freetype": "David Turner",
            "libfreetype": "David Turner",
            "harfbuzz": "Behdad Esfahbod",
            "libharfbuzz": "Behdad Esfahbod",
            "graphite": "Graphite",
            "libgraphite": "Graphite",
            "pango": "GNOME",
            "libpango": "GNOME",
            "cairo": "Cairo",
            "libcairo": "Cairo",
            "pixman": "Pixman",
            "libpixman": "Pixman",
            "libpng": "PNG Group",
            "libjpeg": "Independent JPEG Group",
            "libtiff": "Libtiff",
            "lcms": "Little CMS",
            "liblcms": "Little CMS",
            "openjpeg": "UCLouvain",
            "libopenjp2": "UCLouvain",
            "libwebp": "WebP",
            "libjbig": "ISO/IEC",
            "liblzma": "XZ Utils",
            "xz": "XZ Utils",
            "libbz2": "Julian Seward",
            "bzip2": "Julian Seward",
            "liblz4": "LZ4",
            "lz4": "LZ4",
            "libzstd": "Facebook",
            "zstd": "Facebook",
            "libidn": "Simon Josefsson",
            "libunistring": "GNU",
            "libpcre": "PCRE",
            "pcre": "PCRE",
            "libpcre2": "PCRE",
            "pcre2": "PCRE",
            "libexpat": "Expat",
            "expat": "Expat",
            "libgcrypt": "GnuPG",
            "libgpg-error": "GnuPG",
            "gnutls": "GnuTLS",
            "libgnutls": "GnuTLS",
            "nettle": "Nettle",
            "libnettle": "Nettle",
            "hogweed": "Nettle",
            "libhogweed": "Nettle",
            "gmp": "GNU",
            "libgmp": "GNU",
            "mpfr": "MPFR",
            "libmpfr": "MPFR",
            "mpc": "MPC",
            "libmpc": "MPC",
            "isl": "Sven Verdoolaege",
            "libisl": "Sven Verdoolaege",
            "cloog": "CLooG",
            "libcloog": "CLooG",
            "libtool": "GNU",
            "autoconf": "GNU",
            "automake": "GNU",
            "m4": "GNU",
            "bison": "GNU",
            "flex": "The Flex Project",
            "make": "GNU",
            "cmake": "Kitware",
            "ninja": "Kitware",
            "meson": "Meson",
            "scons": "SCons",
            "waf": "Waf",
            "rake": "Ruby",
            "ruby": "Ruby",
            "perl": "Perl",
            "python": "Python Software Foundation",
            "python3": "Python Software Foundation",
            "libpython": "Python Software Foundation",
            "nodejs": "OpenJS Foundation",
            "node": "OpenJS Foundation",
            "npm": "npm",
            "yarn": "Yarn",
            "pnpm": "pnpm",
            "rust": "Rust",
            "cargo": "Rust",
            "go": "Go Team",
            "libgo": "Go Team",
            "java": "Oracle",
            "openjdk": "Oracle",
            "libjvm": "Oracle",
            "libjava": "Oracle",
            "kotlin": "JetBrains",
            "scala": "Scala",
            "groovy": "Apache Software Foundation",
            "gradle": "Gradle",
            "ant": "Apache Software Foundation",
            "maven": "Apache Software Foundation",
            "ivy": "Apache Software Foundation",
            "leiningen": "Leiningen",
            "boot": "Leiningen",
        }
        return vendor_map.get(name, name)

    def _map_debian_package(self, name: str) -> str:
        """Map Debian package names to canonical names."""
        # Similar to Alpine but with Debian-specific mappings
        if name.startswith("lib"):
            base = name[3:]
            if base in ["audit", "ssl", "crypto", "z", "xml2", "xslt", "curl"]:
                return base
        return name

    def _map_debian_vendor(self, name: str) -> str:
        """Map Debian packages to vendors."""
        # Reuse Alpine vendor map for now
        return self._map_alpine_vendor(name)

    def _map_pypi_vendor(self, name: str) -> str:
        """Map Python package names to vendors."""
        vendor_map = {
            "flask": "Pallets",
            "django": "Django Software Foundation",
            "requests": "Kenneth Reitz",
            "numpy": "NumPy",
            "pandas": "Pandas",
            "scipy": "SciPy",
            "matplotlib": "Matplotlib",
            "pillow": "Pillow",
            "sqlalchemy": "SQLAlchemy",
            "pytest": "Pytest",
            "celery": "Celery",
            "gunicorn": "Gunicorn",
            "uwsgi": "uWSGI",
            "fastapi": "FastAPI",
            "tornado": "Tornado",
            "aiohttp": "AIOHTTP",
            "httpx": "HTTPX",
            "pydantic": "Pydantic",
            "typer": "Typer",
            "rich": "Rich",
            "click": "Click",
            "poetry": "Python Poetry",
            "pip": "PyPA",
            "setuptools": "PyPA",
            "wheel": "PyPA",
            "virtualenv": "PyPA",
        }
        return vendor_map.get(name.lower(), name)

    def _extract_vendor_from_group(self, group_id: str) -> str:
        """Extract vendor from Maven group ID."""
        # org.apache.logging.log4j -> Apache
        # com.google.guava -> Google
        # io.github -> GitHub
        # org.springframework -> Spring (VMware)
        
        vendor_map = {
            "org.apache": "Apache Software Foundation",
            "com.google": "Google",
            "org.springframework": "VMware",
            "com.fasterxml": "FasterXML",
            "io.github": "GitHub",
            "com.microsoft": "Microsoft",
            "org.eclipse": "Eclipse Foundation",
            "com.amazonaws": "Amazon Web Services",
            "software.amazon": "Amazon Web Services",
            "io.netty": "Netty",
            "org.jboss": "Red Hat",
            "org.hibernate": "Red Hat",
            "org.reactivestreams": "Reactive Streams",
            "io.reactivex": "ReactiveX",
            "org.junit": "JUnit",
            "org.mockito": "Mockito",
            "org.testng": "TestNG",
            "org.slf4j": "SLF4J",
            "ch.qos.logback": "QOS.ch",
            "org.aspectj": "AspectJ",
            "org.ow2": "OW2",
            "org.jvnet": "jvnet",
            "org.glassfish": "Eclipse Foundation",
            "javax": "Oracle",
            "jakarta": "Eclipse Foundation",
        }
        
        # Check exact matches
        for prefix, vendor in vendor_map.items():
            if group_id.startswith(prefix):
                return vendor
        
        # Extract second-to-last part as vendor
        parts = group_id.split(".")
        if len(parts) >= 2:
            return parts[-2].capitalize()
        
        return group_id

    def clean_version(self, version: str, purl_type: Optional[str] = None) -> str:
        """
        Clean version strings by removing distro-specific suffixes.
        
        Examples:
        - Alpine: 4.4.1-r2 -> 4.4.1
        - Debian: 1:3.0.9-1 -> 3.0.9
        - Go: v1.2.3 -> 1.2.3
        - Git suffixes: 13.2.1_git20231014 -> 13.2.1
        """
        if not version:
            return version

        cleaned = version

        # Remove 'v' prefix (Go, Git tags)
        if cleaned.startswith("v"):
            cleaned = cleaned[1:]

        # Remove Debian epoch (1:3.0.9-1 -> 3.0.9-1)
        if ":" in cleaned and purl_type in ["deb", "debian", "ubuntu"]:
            cleaned = cleaned.split(":", 1)[1]

        # Remove Debian revision (3.0.9-1 -> 3.0.9)
        if "-" in cleaned and purl_type in ["deb", "debian", "ubuntu"]:
            # Only remove if it looks like a revision (digits only)
            parts = cleaned.rsplit("-", 1)
            if parts[1].replace(".", "").isdigit():
                cleaned = parts[0]

        # Remove Alpine revision (4.4.1-r2 -> 4.4.1)
        if "-r" in cleaned and purl_type in ["apk", "alpine"]:
            cleaned = cleaned.split("-r")[0]

        # Remove git suffixes (13.2.1_git20231014 -> 13.2.1)
        if "_git" in cleaned:
            cleaned = cleaned.split("_git")[0]

        return cleaned


# Singleton
component_normalizer = ComponentNormalizer()
