"""
Applications E2E Tests

Tests for application CRUD operations and management.
"""

import pytest
from tests.e2e.pages.applications_page import ApplicationsPage, ApplicationFormPage


class TestApplications:
    """Test application management functionality."""

    def test_create_application(self, authenticated_page):
        """Test creating a new application."""
        apps_page = ApplicationsPage(authenticated_page)
        apps_page.navigate()

        # Click Add Application
        apps_page.click_add_application()

        # Fill and submit form
        form = ApplicationFormPage(authenticated_page)
        form.fill_form(
            name="Test Application",
            description="Test description",
            vendor="Test Vendor"
        )
        form.submit()

        # Verify application was created
        apps_page.navigate()
        assert apps_page.is_application_present("Test Application")

    def test_view_application_details(self, authenticated_page, test_application):
        """Test viewing application details."""
        apps_page = ApplicationsPage(authenticated_page)
        apps_page.navigate()

        # Find and click on the test application
        row = apps_page.find_application_row(test_application["name"])
        row.click('button:has-text("View")')

        # Verify details page loaded
        assert test_application["name"] in authenticated_page.text_content()

    def test_edit_application(self, authenticated_page, test_application):
        """Test editing an application."""
        apps_page = ApplicationsPage(authenticated_page)
        apps_page.navigate()

        # Find and click edit on the test application
        row = apps_page.find_application_row(test_application["name"])
        row.click('button:has-text("Edit")')

        # Edit the form
        form = ApplicationFormPage(authenticated_page)
        form.fill('input[name="name"]', "Updated Application Name")
        form.submit()

        # Verify update
        apps_page.navigate()
        assert apps_page.is_application_present("Updated Application Name")

    def test_delete_application(self, authenticated_page):
        """Test deleting an application."""
        apps_page = ApplicationsPage(authenticated_page)
        apps_page.navigate()

        # Create a test application first
        apps_page.click_add_application()
        form = ApplicationFormPage(authenticated_page)
        form.fill_form(name="To Be Deleted", description="Will be deleted")
        form.submit()

        # Delete it
        apps_page.delete_application("To Be Deleted")

        # Verify deletion
        assert not apps_page.is_application_present("To Be Deleted")

    def test_search_application(self, authenticated_page, test_application):
        """Test searching for applications."""
        apps_page = ApplicationsPage(authenticated_page)
        apps_page.navigate()

        # Search for the test application
        apps_page.search_application(test_application["name"])

        # Verify only matching applications are shown
        assert apps_page.is_application_present(test_application["name"])

    def test_upload_codebase_to_application(self, authenticated_page, test_application, test_codebase_zip):
        """Test uploading codebase to an application."""
        apps_page = ApplicationsPage(authenticated_page)
        apps_page.navigate()

        # Find the test application and click Upload Codebase
        row = apps_page.find_application_row(test_application["name"])
        row.click('button:has-text("Upload Codebase")')

        # Upload the ZIP file
        authenticated_page.set_input_files('input[type="file"]', test_codebase_zip)
        authenticated_page.click('button:has-text("Upload")')
        authenticated_page.wait_for_load_state("networkidle")

        # Verify success message
        assert "uploaded successfully" in authenticated_page.text_content().lower()
