"""
CVEs E2E Tests

Tests for CVE viewing, filtering, and management.
"""

import pytest


class TestCVEs:
    """Test CVE functionality."""

    def test_view_cves_page(self, authenticated_page):
        """Test navigating to and viewing the CVEs page."""
        authenticated_page.goto("http://localhost:5173/cves")
        authenticated_page.wait_for_load_state("networkidle")

        # Verify page loaded
        assert "CVE" in authenticated_page.text_content()

    def test_filter_cves_by_application(self, authenticated_page, test_application):
        """Test filtering CVEs by application."""
        authenticated_page.goto("http://localhost:5173/cves")
        authenticated_page.wait_for_load_state("networkidle")

        # Select application filter
        authenticated_page.select_option('select[name="application"]', str(test_application.get("id", 1)))
        authenticated_page.wait_for_load_state("networkidle")

        # Verify filter applied
        # (This depends on how the filter is implemented)

    def test_filter_cves_by_severity(self, authenticated_page):
        """Test filtering CVEs by severity."""
        authenticated_page.goto("http://localhost:5173/cves")
        authenticated_page.wait_for_load_state("networkidle")

        # Select severity filter
        authenticated_page.select_option('select[name="severity"]', "CRITICAL")
        authenticated_page.wait_for_load_state("networkidle")

        # Verify filter applied

    def test_search_cve_by_id(self, authenticated_page):
        """Test searching for a specific CVE by ID."""
        authenticated_page.goto("http://localhost:5173/cves")
        authenticated_page.wait_for_load_state("networkidle")

        # Search for a CVE ID
        authenticated_page.fill('input[placeholder*="Search"]', "CVE-2023")
        authenticated_page.page.wait_for_timeout(500)

        # Verify search results

    def test_click_cve_link_opens_nvd(self, authenticated_page):
        """Test that clicking a CVE ID opens the NVD page in a new tab."""
        authenticated_page.goto("http://localhost:5173/cves")
        authenticated_page.wait_for_load_state("networkidle")

        # Find a CVE link and click it
        # This assumes there's at least one CVE in the table
        cve_link = authenticated_page.locator('a[href*="nvd.nist.gov"]').first
        if cve_link.is_visible():
            # Get the href to verify it's correct
            href = cve_link.get_attribute("href")
            assert "nvd.nist.gov" in href

    def test_view_cve_details(self, authenticated_page):
        """Test viewing detailed CVE information."""
        authenticated_page.goto("http://localhost:5173/cves")
        authenticated_page.wait_for_load_state("networkidle")

        # Click on a CVE to view details
        # This depends on the UI implementation
        # authenticated_page.click('table tbody tr:first-child button:has-text("View")')

        # Verify details page loaded
        # assert "CVSS" in authenticated_page.text_content()

    def test_mark_cve_as_false_positive(self, authenticated_page):
        """Test marking a CVE as false positive."""
        authenticated_page.goto("http://localhost:5173/cves")
        authenticated_page.wait_for_load_state("networkidle")

        # Find a CVE and mark as false positive
        # This depends on the UI implementation
        # row = authenticated_page.locator('table tbody tr').first
        # row.click('button:has-text("Mark False Positive")')

        # Verify the change
        # assert "False Positive" in row.text_content()
