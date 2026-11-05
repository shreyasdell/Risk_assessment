"""
Authentication E2E Tests

Tests for login, logout, and authentication flows.
"""

import pytest
from tests.e2e.pages.login_page import LoginPage


class TestAuthentication:
    """Test authentication functionality."""

    def test_login_with_valid_credentials(self, page):
        """Test successful login with valid credentials."""
        login_page = LoginPage(page)
        login_page.navigate()
        login_page.login("admin", "admin123")

        # Verify redirect to dashboard
        assert page.url == "http://localhost:5173/dashboard"

    def test_login_with_invalid_credentials(self, page):
        """Test login failure with invalid credentials."""
        login_page = LoginPage(page)
        login_page.navigate()

        # Fill credentials but don't use the login method (which waits for redirect)
        login_page.fill(login_page.username_input, "admin")
        login_page.fill(login_page.password_input, "wrongpassword")
        login_page.click(login_page.submit_button)

        # Wait a moment for the error to appear
        page.wait_for_timeout(2000)

        # Verify we're still on login page (no redirect on failure)
        assert "login" in page.url

    def test_logout(self, authenticated_page):
        """Test logout functionality."""
        # Navigate to dashboard
        authenticated_page.goto("http://localhost:5173/dashboard")
        authenticated_page.wait_for_load_state("networkidle")

        # Click logout button
        authenticated_page.click('button:has-text("Logout")')

        # Wait for redirect to login page
        authenticated_page.wait_for_url("http://localhost:5173/login", timeout=10000)

        # Verify we're on login page
        assert "login" in authenticated_page.url

    def test_protected_route_redirects_to_login(self, page):
        """Test that protected routes redirect to login when not authenticated."""
        # Try to access a protected route
        page.goto("http://localhost:5173/applications")

        # Should redirect to login
        assert "login" in page.url
