"""
Base Page Object Model

Provides common methods for all page objects.
"""

from playwright.sync_api import Page, Locator


class BasePage:
    """Base class for all page objects."""

    def __init__(self, page: Page):
        self.page = page

    def navigate(self, url: str):
        """Navigate to a URL."""
        self.page.goto(url)
        self.page.wait_for_load_state("networkidle")

    def click(self, selector: str):
        """Click an element."""
        self.page.click(selector)
        self.page.wait_for_load_state("networkidle")

    def fill(self, selector: str, value: str):
        """Fill an input field."""
        self.page.fill(selector, value)

    def get_text(self, selector: str) -> str:
        """Get text content of an element."""
        return self.page.text_content(selector)

    def is_visible(self, selector: str) -> bool:
        """Check if an element is visible."""
        return self.page.is_visible(selector)

    def wait_for_element(self, selector: str, timeout: int = 5000):
        """Wait for an element to be visible."""
        self.page.wait_for_selector(selector, timeout=timeout)

    def wait_for_text(self, selector: str, text: str, timeout: int = 5000):
        """Wait for an element to contain specific text."""
        self.page.wait_for_selector(f"{selector}:has-text('{text}')", timeout=timeout)

    def screenshot(self, filename: str):
        """Take a screenshot."""
        self.page.screenshot(path=filename)

    def get_locator(self, selector: str) -> Locator:
        """Get a locator for an element."""
        return self.page.locator(selector)
