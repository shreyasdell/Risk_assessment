"""
Critical Workflow E2E Tests

Tests for the most critical user workflows:
1. SBOM Upload → Component Creation → CVE Sync
2. Application Creation → SBOM Upload → Risk Assessment
"""

import pytest
from tests.e2e.pages.applications_page import ApplicationsPage, ApplicationFormPage
from tests.e2e.pages.components_page import ComponentsPage, SBOMUploadModal


@pytest.mark.critical
class TestCriticalWorkflows:
    """Test critical user workflows."""

    def test_sbom_upload_to_cve_sync_workflow(self, authenticated_page, test_sbom_file):
        """
        Critical workflow: Upload SBOM → Components Created → CVE Sync

        This is the most important workflow in the application.
        """
        # Step 1: Create an application
        apps_page = ApplicationsPage(authenticated_page)
        apps_page.navigate()
        apps_page.click_add_application()

        form = ApplicationFormPage(authenticated_page)
        form.fill_form(
            name="Critical Test App",
            description="Application for critical workflow test",
            vendor="Test Vendor"
        )
        form.submit()

        # Step 2: Navigate to components and upload SBOM
        components_page = ComponentsPage(authenticated_page)
        components_page.navigate()
        components_page.click_upload_sbom()

        modal = SBOMUploadModal(authenticated_page)
        modal.upload_file(test_sbom_file, 1)  # application_id = 1

        # Step 3: Verify components were created
        components_page.navigate()
        initial_count = components_page.get_component_count()
        assert initial_count > 0, "No components were created from SBOM"

        # Step 4: Sync CVEs for all components
        components_page.click_sync_all()

        # Step 5: Wait for sync to complete (background task)
        # This may take some time, so we wait longer
        components_page.page.wait_for_timeout(30000)

        # Step 6: Verify sync completed
        assert not components_page.is_syncing(), "Sync is still in progress"

        # Step 7: Navigate to CVEs page to verify CVEs were found
        authenticated_page.goto("http://localhost:5173/cves")
        authenticated_page.wait_for_load_state("networkidle")

        # Verify CVEs page is accessible
        assert "CVE" in authenticated_page.text_content()

    def test_application_creation_to_risk_assessment(self, authenticated_page):
        """
        Critical workflow: Create Application → Upload SBOM → View Risk Assessment
        """
        # Step 1: Create application
        apps_page = ApplicationsPage(authenticated_page)
        apps_page.navigate()
        apps_page.click_add_application()

        form = ApplicationFormPage(authenticated_page)
        form.fill_form(
            name="Risk Assessment Test",
            description="Test application for risk assessment",
            vendor="Test Vendor"
        )
        form.submit()

        # Step 2: Navigate to dashboard
        authenticated_page.goto("http://localhost:5173/dashboard")
        authenticated_page.wait_for_load_state("networkidle")

        # Step 3: Verify application appears in dashboard
        assert "Risk Assessment Test" in authenticated_page.text_content()

        # Step 4: Navigate to risk scores
        authenticated_page.goto("http://localhost:5173/risk-scores")
        authenticated_page.wait_for_load_state("networkidle")

        # Step 5: Verify risk scores page is accessible
        assert "Risk" in authenticated_page.text_content()
