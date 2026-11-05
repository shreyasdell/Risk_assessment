"""
Components Page Object Model
"""

from tests.e2e.pages.base_page import BasePage


class ComponentsPage(BasePage):
    """Page object for the components page."""

    def __init__(self, page):
        super().__init__(page)
        self.url = "http://localhost:5173/components"
        self.add_button = 'button:has-text("Add Component")'
        self.upload_sbom_button = 'button:has-text("Upload SBOM")'
        self.sync_all_button = 'button:has-text("Sync All CVEs")'
        self.table = 'table tbody'
        self.search_input = 'input[placeholder*="Search"]'
        self.application_filter = 'select[name="application"]'

    def navigate(self):
        """Navigate to components page."""
        super().navigate(self.url)

    def click_add_component(self):
        """Click the Add Component button."""
        self.click(self.add_button)

    def click_upload_sbom(self):
        """Click the Upload SBOM button."""
        self.click(self.upload_sbom_button)

    def click_sync_all(self):
        """Click the Sync All CVEs button."""
        self.click(self.sync_all_button)

    def get_component_count(self) -> int:
        """Get the number of components in the table."""
        return self.page.locator(f"{self.table} tr").count()

    def search_component(self, name: str):
        """Search for a component by name."""
        self.fill(self.search_input, name)
        self.page.wait_for_timeout(500)

    def filter_by_application(self, application_id: int):
        """Filter components by application."""
        self.page.select_option(self.application_filter, str(application_id))
        self.page.wait_for_load_state("networkidle")

    def find_component_row(self, name: str):
        """Find a table row for a specific component."""
        rows = self.page.locator(f"{self.table} tr")
        for i in range(rows.count()):
            row = rows.nth(i)
            if name in row.text_content():
                return row
        return None

    def sync_component_cves(self, component_name: str):
        """Sync CVEs for a specific component."""
        row = self.find_component_row(component_name)
        if row:
            row.locator('button:has-text("Sync CVEs")').click()
            self.page.wait_for_load_state("networkidle")

    def is_component_present(self, name: str) -> bool:
        """Check if a component is present in the table."""
        return self.find_component_row(name) is not None

    def is_syncing(self) -> bool:
        """Check if sync is in progress."""
        return self.page.is_visible('button:has-text("Syncing...")')


class ComponentFormPage(BasePage):
    """Page object for the component form modal."""

    def __init__(self, page):
        super().__init__(page)
        self.name_input = 'input[name="name"]'
        self.version_input = 'input[name="version"]'
        self.type_input = 'select[name="component_type"]'
        self.purl_input = 'input[name="purl"]'
        self.vendor_input = 'input[name="supplier"]'
        self.description_input = 'textarea[name="description"]'
        self.license_input = 'input[name="license"]'
        self.application_input = 'select[name="application_id"]'
        self.submit_button = 'button[type="submit"]'
        self.cancel_button = 'button:has-text("Cancel")'

    def fill_form(self, name: str, version: str = "", component_type: str = "library",
                  purl: str = "", supplier: str = "", description: str = "",
                  license: str = "", application_id: int = None):
        """Fill the component form."""
        self.fill(self.name_input, name)
        if version:
            self.fill(self.version_input, version)
        if component_type:
            self.page.select_option(self.type_input, component_type)
        if purl:
            self.fill(self.purl_input, purl)
        if supplier:
            self.fill(self.vendor_input, supplier)
        if description:
            self.fill(self.description_input, description)
        if license:
            self.fill(self.license_input, license)
        if application_id:
            self.page.select_option(self.application_input, str(application_id))

    def submit(self):
        """Submit the form."""
        self.click(self.submit_button)

    def cancel(self):
        """Cancel the form."""
        self.click(self.cancel_button)

    def is_visible(self) -> bool:
        """Check if the form modal is visible."""
        return super().is_visible(self.name_input)


class SBOMUploadModal(BasePage):
    """Page object for the SBOM upload modal."""

    def __init__(self, page):
        super().__init__(page)
        self.file_input = 'input[type="file"]'
        self.application_input = 'select[name="application_id"]'
        self.upload_button = 'button:has-text("Upload")'
        self.cancel_button = 'button:has-text("Cancel")'

    def upload_file(self, file_path: str, application_id: int = None):
        """Upload an SBOM file."""
        self.page.set_input_files(self.file_input, file_path)
        if application_id:
            self.page.select_option(self.application_input, str(application_id))
        self.click(self.upload_button)
        self.page.wait_for_load_state("networkidle")

    def is_visible(self) -> bool:
        """Check if the modal is visible."""
        return super().is_visible(self.file_input)
