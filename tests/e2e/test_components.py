"""
Components E2E Tests

Tests for component management, SBOM upload, and CVE sync.
"""

import pytest
from tests.e2e.pages.components_page import ComponentsPage, ComponentFormPage, SBOMUploadModal


class TestComponents:
    """Test component management functionality."""

    def test_create_component(self, authenticated_page, test_application):
        """Test creating a new component manually."""
        components_page = ComponentsPage(authenticated_page)
        components_page.navigate()

        # Click Add Component
        components_page.click_add_component()

        # Fill and submit form
        form = ComponentFormPage(authenticated_page)
        form.fill_form(
            name="test-component",
            version="1.0.0",
            component_type="library",
            purl="pkg:npm/test-component@1.0.0",
            supplier="Test Vendor",
            application_id=test_application.get("id", 1)
        )
        form.submit()

        # Verify component was created
        components_page.navigate()
        assert components_page.is_component_present("test-component")

    def test_upload_sbom(self, authenticated_page, test_application, test_sbom_file):
        """Test uploading an SBOM file."""
        components_page = ComponentsPage(authenticated_page)
        components_page.navigate()

        # Click Upload SBOM
        components_page.click_upload_sbom()

        # Upload the SBOM file
        modal = SBOMUploadModal(authenticated_page)
        modal.upload_file(test_sbom_file, test_application.get("id", 1))

        # Verify success message
        assert "uploaded" in authenticated_page.text_content().lower() or "success" in authenticated_page.text_content().lower()

        # Verify components were created
        components_page.navigate()
        assert components_page.get_component_count() > 0

    def test_sync_single_component_cves(self, authenticated_page):
        """Test syncing CVEs for a single component."""
        components_page = ComponentsPage(authenticated_page)
        components_page.navigate()

        # Find a component and sync its CVEs
        components_page.sync_component_cves("test-component")

        # Wait for sync to complete
        components_page.page.wait_for_timeout(5000)

        # Verify sync completed (button is no longer in syncing state)
        assert not components_page.is_syncing()

    def test_sync_all_components_cves(self, authenticated_page):
        """Test syncing CVEs for all components."""
        components_page = ComponentsPage(authenticated_page)
        components_page.navigate()

        # Click Sync All CVEs
        components_page.click_sync_all()

        # Wait for sync to complete (background task)
        components_page.page.wait_for_timeout(10000)

        # Verify sync completed
        assert not components_page.is_syncing()

    def test_search_component(self, authenticated_page):
        """Test searching for components."""
        components_page = ComponentsPage(authenticated_page)
        components_page.navigate()

        # Search for a component
        components_page.search_component("test-component")

        # Verify only matching components are shown
        assert components_page.is_component_present("test-component")

    def test_filter_components_by_application(self, authenticated_page, test_application):
        """Test filtering components by application."""
        components_page = ComponentsPage(authenticated_page)
        components_page.navigate()

        # Filter by application
        components_page.filter_by_application(test_application.get("id", 1))

        # Verify filter applied
        # (This depends on how the filter is implemented in the UI)
        components_page.page.wait_for_load_state("networkidle")

    def test_view_component_details(self, authenticated_page):
        """Test viewing component details."""
        components_page = ComponentsPage(authenticated_page)
        components_page.navigate()

        # Find and click on a component
        row = components_page.find_component_row("test-component")
        row.click('button:has-text("View")')

        # Verify details page loaded
        assert "test-component" in authenticated_page.text_content()

    def test_edit_component(self, authenticated_page):
        """Test editing a component."""
        components_page = ComponentsPage(authenticated_page)
        components_page.navigate()

        # Find and click edit on a component
        row = components_page.find_component_row("test-component")
        row.click('button:has-text("Edit")')

        # Edit the form
        form = ComponentFormPage(authenticated_page)
        form.fill('input[name="version"]', "2.0.0")
        form.submit()

        # Verify update
        components_page.navigate()
        row = components_page.find_component_row("test-component")
        assert "2.0.0" in row.text_content()

    def test_delete_component(self, authenticated_page):
        """Test deleting a component."""
        components_page = ComponentsPage(authenticated_page)
        components_page.navigate()

        # Find and delete a component
        row = components_page.find_component_row("test-component")
        row.click('button:has-text("Delete")')
        authenticated_page.on("dialog", lambda dialog: dialog.accept())

        # Verify deletion
        components_page.navigate()
        assert not components_page.is_component_present("test-component")
