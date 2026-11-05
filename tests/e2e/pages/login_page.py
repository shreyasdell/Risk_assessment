"""
Login Page Object Model
"""

from tests.e2e.pages.base_page import BasePage


class LoginPage(BasePage):
    """Page object for the login page."""

    def __init__(self, page):
        super().__init__(page)
        self.url = "http://localhost:5173/login"
        self.username_input = 'input[placeholder="Enter your username"]'
        self.password_input = 'input[placeholder="Enter your password"]'
        self.submit_button = 'button[type="submit"]'

    def navigate(self):
        """Navigate to login page."""
        super().navigate(self.url)

    def login(self, username: str, password: str):
        """Perform login with given credentials."""
        self.fill(self.username_input, username)
        self.fill(self.password_input, password)
        self.click(self.submit_button)
        # Wait for redirect to dashboard
        self.page.wait_for_url("http://localhost:5173/dashboard", timeout=10000)

    def is_loaded(self) -> bool:
        """Check if login page is loaded."""
        return self.is_visible(self.username_input)
