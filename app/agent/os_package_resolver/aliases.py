"""
OS Package Alias Mapping.

Maps Linux distribution package names to canonical upstream products.
"""

from typing import Optional, Dict, Tuple


class OSPackageAliases:
    """Maps distribution package names to canonical vendor/product."""
    
    # Mapping of package_name -> (canonical_vendor, canonical_product)
    ALIASES = {
        # GNU C Library
        "libc6": ("gnu", "glibc"),
        "libc6-dev": ("gnu", "glibc"),
        "libc-bin": ("gnu", "glibc"),
        "glibc": ("gnu", "glibc"),
        "glibc-common": ("gnu", "glibc"),
        "glibc-devel": ("gnu", "glibc"),
        "glibc-headers": ("gnu", "glibc"),
        "glibc-langpack-en": ("gnu", "glibc"),
        "glibc-minimal-langpack": ("gnu", "glibc"),
        "glibc-all-langpacks": ("gnu", "glibc"),
        "glibc-utils": ("gnu", "glibc"),
        "glibc-debuginfo": ("gnu", "glibc"),
        "glibc-debuginfo-common": ("gnu", "glibc"),
        "glibc-debuginfo-static": ("gnu", "glibc"),
        "glibc-i18n": ("gnu", "glibc"),
        "glibc-locale-source": ("gnu", "glibc"),
        "glibc-locale-source-common": ("gnu", "glibc"),
        "glibc-locale-source-archive": ("gnu", "glibc"),
        "glibc-locale-source-extra": ("gnu", "glibc"),
        "glibc-locale-source-srpm": ("gnu", "glibc"),
        "glibc-locale-source-srpm-common": ("gnu", "glibc"),
        "glibc-locale-source-srpm-extra": ("gnu", "glibc"),
        "glibc-locale-source-srpm-archive": ("gnu", "glibc"),
        "glibc-locale-source-srpm-minimal": ("gnu", "glibc"),
        "glibc-locale-source-srpm-minimal-common": ("gnu", "glibc"),
        "glibc-locale-source-srpm-minimal-extra": ("gnu", "glibc"),
        "glibc-locale-source-srpm-minimal-archive": ("gnu", "glibc"),
        
        # OpenSSL
        "libssl1.1": ("openssl", "openssl"),
        "libssl-dev": ("openssl", "openssl"),
        "libssl3": ("openssl", "openssl"),
        "libssl1.0.0": ("openssl", "openssl"),
        "libssl1.0.2": ("openssl", "openssl"),
        "libssl1.0.1": ("openssl", "openssl"),
        "libssl1.0": ("openssl", "openssl"),
        "libssl": ("openssl", "openssl"),
        "openssl": ("openssl", "openssl"),
        "openssl-devel": ("openssl", "openssl"),
        "openssl-libs": ("openssl", "openssl"),
        "openssl-static": ("openssl", "openssl"),
        "openssl-debuginfo": ("openssl", "openssl"),
        "openssl-perl": ("openssl", "openssl"),
        "openssl-pkcs11": ("openssl", "openssl"),
        "openssl-engines": ("openssl", "openssl"),
        
        # Bzip2
        "libbz2-1.0": ("bzip", "bzip2"),
        "libbz2-dev": ("bzip", "bzip2"),
        "libbz2-1.0-dev": ("bzip", "bzip2"),
        "bzip2": ("bzip", "bzip2"),
        "bzip2-devel": ("bzip", "bzip2"),
        "bzip2-libs": ("bzip", "bzip2"),
        "bzip2-static": ("bzip", "bzip2"),
        "bzip2-debuginfo": ("bzip", "bzip2"),
        
        # Zlib
        "zlib1g": ("zlib", "zlib"),
        "zlib1g-dev": ("zlib", "zlib"),
        "zlib": ("zlib", "zlib"),
        "zlib-devel": ("zlib", "zlib"),
        "zlib-libs": ("zlib", "zlib"),
        "zlib-static": ("zlib", "zlib"),
        "zlib-debuginfo": ("zlib", "zlib"),
        "minizip": ("zlib", "zlib"),
        "minizip-devel": ("zlib", "zlib"),
        
        # libxml2
        "libxml2": ("xmlsoft", "libxml2"),
        "libxml2-dev": ("xmlsoft", "libxml2"),
        "libxml2-2": ("xmlsoft", "libxml2"),
        "libxml2-devel": ("xmlsoft", "libxml2"),
        "libxml2-libs": ("xmlsoft", "libxml2"),
        "libxml2-static": ("xmlsoft", "libxml2"),
        "libxml2-debuginfo": ("xmlsoft", "libxml2"),
        "libxml2-python": ("xmlsoft", "libxml2"),
        
        # libxslt
        "libxslt1.1": ("xmlsoft", "libxslt"),
        "libxslt1-dev": ("xmlsoft", "libxslt"),
        "libxslt": ("xmlsoft", "libxslt"),
        "libxslt-devel": ("xmlsoft", "libxslt"),
        "libxslt-libs": ("xmlsoft", "libxslt"),
        "libxslt-python": ("xmlsoft", "libxslt"),
        
        # libcurl
        "libcurl3": ("daniel_stenberg", "curl"),
        "libcurl4": ("daniel_stenberg", "curl"),
        "libcurl4-openssl-dev": ("daniel_stenberg", "curl"),
        "libcurl-dev": ("daniel_stenberg", "curl"),
        "curl": ("daniel_stenberg", "curl"),
        "curl-devel": ("daniel_stenberg", "curl"),
        "libcurl-libs": ("daniel_stenberg", "curl"),
        "libcurl-static": ("daniel_stenberg", "curl"),
        
        # libpng
        "libpng12-0": ("png", "libpng"),
        "libpng16-16": ("png", "libpng"),
        "libpng-dev": ("png", "libpng"),
        "libpng": ("png", "libpng"),
        "libpng-devel": ("png", "libpng"),
        "libpng-libs": ("png", "libpng"),
        "libpng-static": ("png", "libpng"),
        
        # libjpeg
        "libjpeg8": ("independent_jpeg_group", "libjpeg"),
        "libjpeg62": ("independent_jpeg_group", "libjpeg"),
        "libjpeg-turbo": ("libjpeg_turbo", "libjpeg-turbo"),
        "libjpeg-turbo-devel": ("libjpeg_turbo", "libjpeg-turbo"),
        "libjpeg-turbo-libs": ("libjpeg_turbo", "libjpeg-turbo"),
        "libjpeg-turbo-static": ("libjpeg_turbo", "libjpeg-turbo"),
        
        # libtiff
        "libtiff5": ("libtiff", "libtiff"),
        "libtiff-dev": ("libtiff", "libtiff"),
        "libtiff": ("libtiff", "libtiff"),
        "libtiff-devel": ("libtiff", "libtiff"),
        "libtiff-libs": ("libtiff", "libtiff"),
        "libtiff-static": ("libtiff", "libtiff"),
        "libtiff-tools": ("libtiff", "libtiff"),
        
        # liblzma (xz)
        "liblzma5": ("xz", "xz"),
        "liblzma-dev": ("xz", "xz"),
        "xz": ("xz", "xz"),
        "xz-devel": ("xz", "xz"),
        "xz-libs": ("xz", "xz"),
        "xz-static": ("xz", "xz"),
        "xz-lzma-compat": ("xz", "xz"),
        "xz-lzma-compat-devel": ("xz", "xz"),
        
        # liblz4
        "liblz4-1": ("lz4", "lz4"),
        "liblz4-dev": ("lz4", "lz4"),
        "lz4": ("lz4", "lz4"),
        "lz4-devel": ("lz4", "lz4"),
        "lz4-libs": ("lz4", "lz4"),
        "lz4-static": ("lz4", "lz4"),
        
        # libzstd
        "libzstd1": ("facebook", "zstd"),
        "libzstd-dev": ("facebook", "zstd"),
        "zstd": ("facebook", "zstd"),
        "zstd-devel": ("facebook", "zstd"),
        "zstd-libs": ("facebook", "zstd"),
        "zstd-static": ("facebook", "zstd"),
        
        # libexpat
        "libexpat1": ("expat", "expat"),
        "libexpat1-dev": ("expat", "expat"),
        "expat": ("expat", "expat"),
        "expat-devel": ("expat", "expat"),
        "expat-libs": ("expat", "expat"),
        
        # libgcrypt
        "libgcrypt20": ("gnupg", "libgcrypt"),
        "libgcrypt20-dev": ("gnupg", "libgcrypt"),
        "libgcrypt": ("gnupg", "libgcrypt"),
        "libgcrypt-devel": ("gnupg", "libgcrypt"),
        "libgcrypt-libs": ("gnupg", "libgcrypt"),
        
        # libgpg-error
        "libgpg-error0": ("gnupg", "libgpg-error"),
        "libgpg-error-dev": ("gnupg", "libgpg-error"),
        "libgpg-error": ("gnupg", "libgpg-error"),
        "libgpg-error-devel": ("gnupg", "libgpg-error"),
        
        # GnuTLS
        "gnutls28": ("gnutls", "gnutls"),
        "gnutls28-dev": ("gnutls", "gnutls"),
        "gnutls": ("gnutls", "gnutls"),
        "gnutls-devel": ("gnutls", "gnutls"),
        "gnutls-libs": ("gnutls", "gnutls"),
        "gnutls-utils": ("gnutls", "gnutls"),
        
        # Nettle
        "libnettle8": ("nettle", "nettle"),
        "libnettle-dev": ("nettle", "nettle"),
        "nettle": ("nettle", "nettle"),
        "nettle-devel": ("nettle", "nettle"),
        "nettle-libs": ("nettle", "nettle"),
        "hogweed": ("nettle", "nettle"),
        "libhogweed": ("nettle", "nettle"),
        
        # GMP
        "libgmp10": ("gnu", "gmp"),
        "libgmp-dev": ("gnu", "gmp"),
        "gmp": ("gnu", "gmp"),
        "gmp-devel": ("gnu", "gmp"),
        "gmp-libs": ("gnu", "gmp"),
        "gmp-static": ("gnu", "gmp"),
        
        # PCRE
        "libpcre3": ("pcre", "pcre"),
        "libpcre3-dev": ("pcre", "pcre"),
        "libpcre2-8-0": ("pcre", "pcre2"),
        "libpcre2-dev": ("pcre", "pcre2"),
        "pcre": ("pcre", "pcre"),
        "pcre-devel": ("pcre", "pcre"),
        "pcre-libs": ("pcre", "pcre"),
        "pcre2": ("pcre", "pcre2"),
        "pcre2-devel": ("pcre", "pcre2"),
        "pcre2-libs": ("pcre", "pcre2"),
        
        # SQLite
        "libsqlite3-0": ("sqlite", "sqlite"),
        "libsqlite3-dev": ("sqlite", "sqlite"),
        "sqlite3": ("sqlite", "sqlite"),
        "sqlite-devel": ("sqlite", "sqlite"),
        "sqlite-libs": ("sqlite", "sqlite"),
        
        # PostgreSQL
        "libpq5": ("postgresql", "postgresql"),
        "libpq-dev": ("postgresql", "postgresql"),
        "postgresql": ("postgresql", "postgresql"),
        "postgresql-devel": ("postgresql", "postgresql"),
        "postgresql-libs": ("postgresql", "postgresql"),
        "postgresql-server": ("postgresql", "postgresql"),
        
        # MySQL
        "libmysqlclient21": ("oracle", "mysql"),
        "libmysqlclient-dev": ("oracle", "mysql"),
        "mysql": ("oracle", "mysql"),
        "mysql-devel": ("oracle", "mysql"),
        "mysql-libs": ("oracle", "mysql"),
        "mysql-server": ("oracle", "mysql"),
        
        # MariaDB
        "libmariadb3": ("mariadb", "mariadb"),
        "libmariadb-dev": ("mariadb", "mariadb"),
        "mariadb": ("mariadb", "mariadb"),
        "mariadb-devel": ("mariadb", "mariadb"),
        "mariadb-libs": ("mariadb", "mariadb"),
        "mariadb-server": ("mariadb", "mariadb"),
        
        # Redis
        "redis": ("redis_labs", "redis"),
        "redis-server": ("redis_labs", "redis"),
        "redis-devel": ("redis_labs", "redis"),
        
        # Nginx
        "nginx": ("nginx", "nginx"),
        "nginx-devel": ("nginx", "nginx"),
        "nginx-libs": ("nginx", "nginx"),
        "nginx-mod-http-perl": ("nginx", "nginx"),
        "nginx-mod-http-xslt": ("nginx", "nginx"),
        
        # Apache HTTPD
        "apache2": ("apache", "httpd"),
        "httpd": ("apache", "httpd"),
        "httpd-devel": ("apache", "httpd"),
        "httpd-libs": ("apache", "httpd"),
        "httpd-tools": ("apache", "httpd"),
        "httpd-mod_ssl": ("apache", "httpd"),
        
        # Lighttpd
        "lighttpd": ("lighttpd", "lighttpd"),
        "lighttpd-devel": ("lighttpd", "lighttpd"),
        "lighttpd-mod_fastcgi": ("lighttpd", "lighttpd"),
        
        # Bash
        "bash": ("gnu", "bash"),
        "bash-completion": ("gnu", "bash"),
        
        # Coreutils
        "coreutils": ("gnu", "coreutils"),
        
        # Util-linux
        "util-linux": ("karel_zak", "util-linux"),
        "util-linux-libs": ("karel_zak", "util-linux"),
        
        # Procps
        "procps": ("procps-ng", "procps"),
        "procps-ng": ("procps-ng", "procps"),
        
        # Psmisc
        "psmisc": ("psmisc", "psmisc"),
        
        # Shadow
        "shadow": ("shadow", "shadow"),
        "shadow-utils": ("shadow", "shadow"),
        
        # IPRoute2
        "iproute2": ("iproute2", "iproute2"),
        "iproute": ("iproute2", "iproute2"),
        
        # Iptables
        "iptables": ("netfilter", "iptables"),
        "iptables-services": ("netfilter", "iptables"),
        
        # Nftables
        "nftables": ("netfilter", "nftables"),
        
        # Systemd
        "systemd": ("systemd", "systemd"),
        "systemd-libs": ("systemd", "systemd"),
        "systemd-devel": ("systemd", "systemd"),
        "systemd-udev": ("systemd", "systemd"),
        
        # D-Bus
        "dbus": ("freedesktop", "dbus"),
        "dbus-libs": ("freedesktop", "dbus"),
        "dbus-devel": ("freedesktop", "dbus"),
        "dbus-x11": ("freedesktop", "dbus"),
        
        # GLib
        "libglib2.0-0": ("gnome", "glib"),
        "glib2": ("gnome", "glib"),
        "glib2-devel": ("gnome", "glib"),
        "glib2-libs": ("gnome", "glib"),
        
        # GTK
        "libgtk-3-0": ("gnome", "gtk"),
        "gtk3": ("gnome", "gtk"),
        "gtk3-devel": ("gnome", "gtk"),
        "gtk3-libs": ("gnome", "gtk"),
        "libgtk-4-1": ("gnome", "gtk"),
        "gtk4": ("gnome", "gtk"),
        "gtk4-devel": ("gnome", "gtk"),
        
        # Qt
        "libqt5core5a": ("qt_company", "qt"),
        "qt5-qtbase": ("qt_company", "qt"),
        "qt5-qtbase-devel": ("qt_company", "qt"),
        "qt5-qtbase-gui": ("qt_company", "qt"),
        "qt6-qtbase": ("qt_company", "qt"),
        "qt6-qtbase-devel": ("qt_company", "qt"),
        "qt6-qtbase-gui": ("qt_company", "qt"),
        
        # FFmpeg
        "ffmpeg": ("ffmpeg", "ffmpeg"),
        "ffmpeg-devel": ("ffmpeg", "ffmpeg"),
        "ffmpeg-libs": ("ffmpeg", "ffmpeg"),
        "libavcodec": ("ffmpeg", "ffmpeg"),
        "libavcodec-devel": ("ffmpeg", "ffmpeg"),
        "libavformat": ("ffmpeg", "ffmpeg"),
        "libavformat-devel": ("ffmpeg", "ffmpeg"),
        "libavutil": ("ffmpeg", "ffmpeg"),
        "libavutil-devel": ("ffmpeg", "ffmpeg"),
        "libswscale": ("ffmpeg", "ffmpeg"),
        "libswscale-devel": ("ffmpeg", "ffmpeg"),
        
        # ImageMagick
        "imagemagick": ("imagemagick", "imagemagick"),
        "imagemagick-devel": ("imagemagick", "imagemagick"),
        "imagemagick-libs": ("imagemagick", "imagemagick"),
        "libmagick": ("imagemagick", "imagemagick"),
        "libmagick++": ("imagemagick", "imagemagick"),
        "libmagickwand": ("imagemagick", "imagemagick"),
        
        # Poppler
        "poppler": ("poppler", "poppler"),
        "poppler-devel": ("poppler", "poppler"),
        "poppler-libs": ("poppler", "poppler"),
        "poppler-utils": ("poppler", "poppler"),
        "poppler-cpp": ("poppler", "poppler"),
        "poppler-cpp-devel": ("poppler", "poppler"),
        "poppler-glib": ("poppler", "poppler"),
        "poppler-glib-devel": ("poppler", "poppler"),
        "poppler-qt": ("poppler", "poppler"),
        "poppler-qt-devel": ("poppler", "poppler"),
        
        # Fontconfig
        "fontconfig": ("keith_packard", "fontconfig"),
        "fontconfig-devel": ("keith_packard", "fontconfig"),
        "fontconfig-libs": ("keith_packard", "fontconfig"),
        
        # FreeType
        "freetype": ("david_turner", "freetype"),
        "freetype-devel": ("david_turner", "freetype"),
        "freetype-libs": ("david_turner", "freetype"),
        
        # HarfBuzz
        "harfbuzz": ("behdad_esfahbod", "harfbuzz"),
        "harfbuzz-devel": ("behdad_esfahbod", "harfbuzz"),
        "harfbuzz-libs": ("behdad_esfahbod", "harfbuzz"),
        "harfbuzz-icu": ("behdad_esfahbod", "harfbuzz"),
        
        # Graphite
        "graphite2": ("graphite", "graphite"),
        "graphite2-devel": ("graphite", "graphite"),
        "graphite2-libs": ("graphite", "graphite"),
        
        # Pango
        "pango": ("gnome", "pango"),
        "pango-devel": ("gnome", "pango"),
        "pango-libs": ("gnome", "pango"),
        "pango-devel-libs": ("gnome", "pango"),
        
        # Cairo
        "cairo": ("cairo", "cairo"),
        "cairo-devel": ("cairo", "cairo"),
        "cairo-libs": ("cairo", "cairo"),
        
        # Pixman
        "pixman": ("pixman", "pixman"),
        "pixman-devel": ("pixman", "pixman"),
        "pixman-libs": ("pixman", "pixman"),
        
        # OpenJPEG
        "openjpeg2": ("uclouvain", "openjpeg"),
        "openjpeg2-devel": ("uclouvain", "openjpeg"),
        "openjpeg2-libs": ("uclouvain", "openjpeg"),
        "libopenjp2-7": ("uclouvain", "openjpeg"),
        
        # WebP
        "libwebp6": ("webp", "libwebp"),
        "libwebp-dev": ("webp", "libwebp"),
        "libwebp-devel": ("webp", "libwebp"),
        "libwebp-libs": ("webp", "libwebp"),
        "libwebp-tools": ("webp", "libwebp"),
        
        # JBIG
        "libjbig0": ("iso_iec", "jbig"),
        "libjbig-dev": ("iso_iec", "jbig"),
        "jbigkit": ("iso_iec", "jbig"),
        
        # Make
        "make": ("gnu", "make"),
        "make-devel": ("gnu", "make"),
        "make-libs": ("gnu", "make"),
        
        # CMake
        "cmake": ("kitware", "cmake"),
        "cmake-devel": ("kitware", "cmake"),
        "cmake-libs": ("kitware", "cmake"),
        "cmake-data": ("kitware", "cmake"),
        
        # Ninja
        "ninja-build": ("kitware", "ninja"),
        "ninja": ("kitware", "ninja"),
        
        # Meson
        "meson": ("meson", "meson"),
        "meson-python": ("meson", "meson"),
        
        # SCons
        "scons": ("scons", "scons"),
        
        # Waf
        "waf": ("waf", "waf"),
        
        # Rake
        "rake": ("ruby", "rake"),
        
        # Ruby
        "ruby": ("ruby", "ruby"),
        "ruby-devel": ("ruby", "ruby"),
        "ruby-libs": ("ruby", "ruby"),
        "rubygems": ("ruby", "rubygems"),
        
        # Perl
        "perl": ("perl", "perl"),
        "perl-devel": ("perl", "perl"),
        "perl-libs": ("perl", "perl"),
        "perl-core": ("perl", "perl"),
        
        # Python
        "python3": ("python", "python"),
        "python3-devel": ("python", "python"),
        "python3-libs": ("python", "python"),
        "python": ("python", "python"),
        "python-devel": ("python", "python"),
        "python-libs": ("python", "python"),
        "libpython3": ("python", "python"),
        
        # Node.js
        "nodejs": ("openjs", "node"),
        "nodejs-devel": ("openjs", "node"),
        "node": ("openjs", "node"),
        "npm": ("npm", "npm"),
        
        # Yarn
        "yarn": ("yarn", "yarn"),
        
        # pnpm
        "pnpm": ("pnpm", "pnpm"),
        
        # Rust
        "rust": ("rust", "rust"),
        "rust-devel": ("rust", "rust"),
        "cargo": ("rust", "cargo"),
        "cargo-devel": ("rust", "cargo"),
        
        # Go
        "golang": ("go_team", "go"),
        "golang-devel": ("go_team", "go"),
        "go": ("go_team", "go"),
        "go-devel": ("go_team", "go"),
        "libgo": ("go_team", "go"),
        
        # Java
        "java": ("oracle", "java"),
        "java-devel": ("oracle", "java"),
        "java-11-openjdk": ("oracle", "java"),
        "java-17-openjdk": ("oracle", "java"),
        "java-21-openjdk": ("oracle", "java"),
        "openjdk": ("oracle", "java"),
        "openjdk-devel": ("oracle", "java"),
        "libjvm": ("oracle", "java"),
        "libjava": ("oracle", "java"),
        
        # Kotlin
        "kotlin": ("jetbrains", "kotlin"),
        "kotlin-devel": ("jetbrains", "kotlin"),
        
        # Scala
        "scala": ("scala", "scala"),
        "scala-devel": ("scala", "scala"),
        
        # Groovy
        "groovy": ("apache", "groovy"),
        "groovy-devel": ("apache", "groovy"),
        
        # Gradle
        "gradle": ("gradle", "gradle"),
        
        # Ant
        "ant": ("apache", "ant"),
        "ant-devel": ("apache", "ant"),
        
        # Maven
        "maven": ("apache", "maven"),
        "maven-devel": ("apache", "maven"),
        
        # Leiningen
        "leiningen": ("leiningen", "leiningen"),
        
        # Boot
        "boot": ("leiningen", "boot"),
    }
    
    @classmethod
    def resolve(cls, package_name: str, ecosystem: str) -> Optional[Tuple[str, str]]:
        """
        Resolve a package name to canonical vendor/product.
        
        Args:
            package_name: Distribution package name (e.g., "libc6", "libssl1.1")
            ecosystem: Package ecosystem (deb, rpm, apk)
        
        Returns:
            Tuple of (canonical_vendor, canonical_product) or None if no mapping exists
        """
        # Check exact match
        if package_name in cls.ALIASES:
            return cls.ALIASES[package_name]
        
        # Check with common prefixes removed
        if package_name.startswith("lib"):
            # Try without lib prefix
            base = package_name[3:]
            if base in cls.ALIASES:
                return cls.ALIASES[base]
            
            # Try removing version suffix (e.g., libssl1.1 -> libssl)
            import re
            match = re.match(r'^(.*?)[\d.]+$', package_name)
            if match:
                base = match.group(1)
                if base in cls.ALIASES:
                    return cls.ALIASES[base]
        
        return None
