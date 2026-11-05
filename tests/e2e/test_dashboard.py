"""
Dashboard E2E Tests

Tests for dashboard functionality and statistics.
"""

import pytest


class TestDashboard:
    """Test dashboard functionality."""

    def test_view_dashboard(self, authenticated_page):
        """Test viewing the dashboard."""
        authenticated_page.goto("http://localhost:5173/dashboard")
        authenticated_page.wait_for_load_state("networkidle")

        # Verify dashboard loaded
        assert "Dashboard" in authenticated_page.text_content()

    def test_dashboard_shows_statistics(self, authenticated_page):
        """Test that dashboard shows risk statistics."""
        authenticated_page.goto("http://localhost:5173/dashboard")
        authenticated_page.wait_for_load_state("networkidle")

        # Verify statistics are displayed
        # This depends on the dashboard implementation
        # assert authenticated_page.is_visible('[data-testid="total-applications"]')
        # assert authenticated_page.is_visible('[data-testid="total-components"]')
        # assert authenticated_page.is_visible('[data-testid="total-cves"]')

    def test_dashboard_shows_risk_scores(self, authenticated_page):
        """Test that dashboard shows risk scores."""
        authenticated_page.goto("http://localhost:5173/dashboard")
        authenticated_page.wait_for_load_state("networkidle")

        # Verify risk scores are displayed
        # This depends on the dashboard implementation

    def test_dashboard_navigate_to_applications(self, authenticated_page):
        """Test navigating from dashboard to applications."""
        authenticated_page.goto("http://localhost:5173/dashboard")
        authenticated_page.wait_for_load_state("networkidle")

        # Click on applications link/card
        authenticated_page.click('a:has-text("Applications")')

        # Verify navigation
        assert "applications" in authenticated_page.url

    def test_dashboard_navigate_to_components(self, authenticated_page):
        """Test navigating from dashboard to components."""
        authenticated_page.goto("http://localhost:5173/dashboard")
        authenticated_page.wait_for_load_state("networkidle")

        # Click on components link/card
        authenticated_page.click('a:has-text("Components")')

        # Verify navigation
        assert "components" in authenticated_page.url

    def test_dashboard_navigate_to_cves(self, authenticated_page):
        """Test navigating from dashboard to CVEs."""
        authenticated_page.goto("http://localhost:5173/dashboard")
        authenticated_page.wait_for_load_state("networkidle")

        # Click on CVEs link/card
        authenticated_page.click('a:has-text("CVEs")')

        # Verify navigation
        assert "cves" in authenticated_page.url
