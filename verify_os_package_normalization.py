#!/usr/bin/env python3
"""
OS Package Normalization Verification Script

Analyzes the impact of OS package normalization on CVE discovery.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import SessionLocal
from app.models.component import Component
from app.models.cve import CVE
from sqlalchemy import func
from collections import defaultdict


def analyze_os_packages():
    """Analyze OS packages and their CVE discovery patterns."""
    db = SessionLocal()
    
    try:
        print("=" * 80)
        print("OS Package Normalization Analysis")
        print("=" * 80)
        
        # 1. Count OS packages by ecosystem
        print("\n1. OS Package Distribution by Ecosystem")
        print("-" * 80)
        os_packages = db.query(
            Component.package_ecosystem,
            func.count(Component.id).label('count')
        ).filter(
            Component.package_ecosystem.isnot(None)
        ).group_by(Component.package_ecosystem).all()
        
        for ecosystem, count in os_packages:
            print(f"  {ecosystem}: {count} components")
        
        total_os = sum(count for _, count in os_packages)
        print(f"  Total OS packages: {total_os}")
        
        # 2. Top packages with canonical mapping
        print("\n2. Packages with Canonical Mapping")
        print("-" * 80)
        canonical_packages = db.query(
            Component.name,
            Component.canonical_vendor,
            Component.canonical_product,
            Component.search_name
        ).filter(
            Component.canonical_vendor.isnot(None),
            Component.canonical_product.isnot(None)
        ).limit(20).all()
        
        for name, vendor, product, search_name in canonical_packages:
            print(f"  {name} -> {vendor}/{product} (search: {search_name})")
        
        # 3. Packages using fallback (no canonical mapping)
        print("\n3. Packages Using Fallback (No Canonical Mapping)")
        print("-" * 80)
        fallback_packages = db.query(
            Component.name,
            Component.package_ecosystem
        ).filter(
            Component.package_ecosystem.isnot(None),
            Component.canonical_vendor.is_(None)
        ).limit(20).all()
        
        for name, ecosystem in fallback_packages:
            print(f"  {name} ({ecosystem}) - no canonical mapping")
        
        # 4. CVE count for OS packages
        print("\n4. CVE Count for OS Packages")
        print("-" * 80)
        os_package_cves = db.query(
            Component.name,
            Component.canonical_product,
            func.count(Component.cves).label('cve_count')
        ).filter(
            Component.package_ecosystem.isnot(None)
        ).join(Component.cves).group_by(
            Component.name,
            Component.canonical_product
        ).order_by(func.count(Component.cves).desc()).limit(20).all()
        
        for name, canonical_product, cve_count in os_package_cves:
            canonical = canonical_product if canonical_product else "no mapping"
            print(f"  {name} ({canonical}): {cve_count} CVEs")
        
        # 5. Comparison: canonical vs non-canonical
        print("\n5. CVE Count Comparison: Canonical vs Non-Canonical")
        print("-" * 80)
        
        # Canonical packages
        canonical_cves = db.query(
            func.count(Component.cves).label('cve_count')
        ).filter(
            Component.canonical_vendor.isnot(None),
            Component.canonical_product.isnot(None)
        ).join(Component.cves).scalar() or 0
        
        canonical_count = db.query(func.count(Component.id)).filter(
            Component.canonical_vendor.isnot(None),
            Component.canonical_product.isnot(None)
        ).scalar() or 0
        
        # Non-canonical OS packages
        non_canonical_cves = db.query(
            func.count(Component.cves).label('cve_count')
        ).filter(
            Component.package_ecosystem.isnot(None),
            Component.canonical_vendor.is_(None)
        ).join(Component.cves).scalar() or 0
        
        non_canonical_count = db.query(func.count(Component.id)).filter(
            Component.package_ecosystem.isnot(None),
            Component.canonical_vendor.is_(None)
        ).scalar() or 0
        
        print(f"  Canonical packages: {canonical_count} components, {canonical_cves} CVEs")
        print(f"  Non-canonical packages: {non_canonical_count} components, {non_canonical_cves} CVEs")
        
        if canonical_count > 0:
            canonical_avg = canonical_cves / canonical_count
            print(f"  Average CVEs per canonical package: {canonical_avg:.2f}")
        
        if non_canonical_count > 0:
            non_canonical_avg = non_canonical_cves / non_canonical_count
            print(f"  Average CVEs per non-canonical package: {non_canonical_avg:.2f}")
        
        # 6. Search name quality
        print("\n6. Search Name Quality")
        print("-" * 80)
        search_names = db.query(
            Component.name,
            Component.search_name,
            Component.canonical_product
        ).filter(
            Component.package_ecosystem.isnot(None)
        ).limit(20).all()
        
        for name, search_name, canonical_product in search_names:
            quality = "GOOD" if canonical_product else "FALLBACK"
            print(f"  {name} -> '{search_name}' ({quality})")
        
        # 7. Summary
        print("\n7. Summary")
        print("-" * 80)
        print(f"  Total OS packages: {total_os}")
        print(f"  Packages with canonical mapping: {canonical_count}")
        print(f"  Packages without canonical mapping: {non_canonical_count}")
        
        if total_os > 0:
            coverage = (canonical_count / total_os) * 100
            print(f"  Canonical coverage: {coverage:.1f}%")
        
        print("\n" + "=" * 80)
        print("Analysis Complete")
        print("=" * 80)
        
    finally:
        db.close()


if __name__ == "__main__":
    analyze_os_packages()
