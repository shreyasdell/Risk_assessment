"""
Applications Page Object Model
"""

from tests.e2e.pages.base_page import BasePage


class ApplicationsPage(BasePage):
    """Page object for the applications page."""

    def __init__(self, page):
        super().__init__(page)
        self.url = "http://localhost:5173/applications"
        self.add_button = 'button:has-text("Add Application")'
        self.table = 'table tbody'

    def navigate(self):
        """Navigate to applications page."""
        super().navigate(self.url)

    def click_add_application(self):
        """Click the Add Application button."""
        self.click(self.add_button)

    def get_application_count(self) -> int:
        """Get the number of applications in the table."""
        return self.page.locator(f"{self.table} tr").count()

    def find_application_row(self, name: str):
        """Find a table row for a specific application."""
        rows = self.page.locator(f"{self.table} tr")
        for i in range(rows.count()):
            row = rows.nth(i)
            if name in row.text_content():
                return row
        return None

    def delete_application(self, name: str):
        """Delete an application by name."""
        row = self.find_application_row(name)
        if row:
            row.locator('button:has-text("Delete")').click()
            self.page.on("dialog", lambda dialog: dialog.accept())
            self.page.wait_for_load_state("networkidle")

    def is_application_present(self, name: str) -> bool:
        """Check if an application is present in the table."""
        return self.find_application_row(name) is not None


class ApplicationFormPage(BasePage):
    """Page object for the application form modal."""

    def __init__(self, page):
        super().__init__(page)
        self.name_input = 'input[type="text"]'
        self.description_input = 'textarea'  # No name attribute
        self.vendor_input = 'input[type="text"]'  # No name attribute
        self.submit_button = 'button[type="submit"]'
        self.cancel_button = 'button:has-text("Cancel")'

    def fill_form(self, name: str, description: str = "", vendor: str = ""):
        """Fill the application form."""
        # Fill by order of appearance in form
        self.page.fill('input[type="text"]', name)
        if description:
            self.page.fill('textarea', description)
        if vendor:
            # Vendor is the 3rd text input
            inputs = self.page.locator('input[type="text"]')
            if inputs.count() >= 3:
                inputs.nth(2).fill(vendor)

    def submit(self):
        """Submit the form."""
        self.click(self.submit_button)

    def cancel(self):
        """Cancel the form."""
        self.click(self.cancel_button)

    def is_visible(self) -> bool:
        """Check if the form modal is visible."""
        return self.is_visible('input[type="text"]')
