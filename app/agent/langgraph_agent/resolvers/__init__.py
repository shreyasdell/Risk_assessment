"""
Deterministic resolvers for component enrichment.

Each resolver can derive vendor/product/search_name/ecosystem directly from PURL
without requiring LLM calls. LLM is used only as a fallback when deterministic resolution fails.
"""

from .maven import MavenResolver
from .npm import NPMResolver
from .composer import ComposerResolver
from .golang import GolangResolver
from .pypi import PyPIResolver
from .nuget import NuGetResolver
from .cargo import CargoResolver

__all__ = [
    'MavenResolver',
    'NPMResolver',
    'ComposerResolver',
    'GolangResolver',
    'PyPIResolver',
    'NuGetResolver',
    'CargoResolver',
]
