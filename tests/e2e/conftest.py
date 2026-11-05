"""
Playwright E2E Test Configuration and Fixtures

This file contains shared fixtures and configuration for all E2E tests.
"""

import pytest
from playwright.sync_api import Page, BrowserContext, Browser
from typing import Generator

# Test configuration
BASE_URL = "http://localhost:8000"
FRONTEND_URL = "http://localhost:5173"

# Test credentials
TEST_USER = {
    "username": "admin",
    "password": "admin123"
}


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    """
    Configure browser context for all tests.
    """
    return {
        **browser_context_args,
        "viewport": {"width": 1920, "height": 1080},
        "ignore_https_errors": True,
        "locale": "en-US",
        "timezone_id": "America/New_York",
    }


@pytest.fixture(scope="function")
def authenticated_page(page: Page) -> Generator[Page, None, None]:
    """
    Fixture that provides an authenticated page.
    Logs in before test, logs out after test.
    """
    # Navigate to login page
    page.goto(f"{FRONTEND_URL}/login")

    # Fill login form
    page.fill('input[name="username"]', TEST_USER["username"])
    page.fill('input[name="password"]', TEST_USER["password"])
    page.click('button[type="submit"]')

    # Wait for successful login (redirect to dashboard)
    page.wait_for_url(f"{FRONTEND_URL}/dashboard")
    page.wait_for_load_state("networkidle")

    yield page

    # Cleanup: logout after test
    page.goto(f"{FRONTEND_URL}/logout")
    page.wait_for_load_state("networkidle")


@pytest.fixture(scope="function")
def api_authenticated_page(page: Page) -> Generator[Page, None, None]:
    """
    Fixture that provides a page with API authentication token.
    Uses direct API login for faster test setup.
    """
    # Get auth token via API
    from playwright.sync_api import APIRequestContext

    api_context = page.request
    response = api_context.post(
        f"{BASE_URL}/auth/login",
        data={
            "username": TEST_USER["username"],
            "password": TEST_USER["password"]
        }
    )

    assert response.status == 200
    token_data = response.json()
    access_token = token_data["access_token"]

    # Store token in localStorage
    page.goto(f"{FRONTEND_URL}/")
    page.evaluate(f"localStorage.setItem('token', '{access_token}')")

    yield page

    # Cleanup
    page.evaluate("localStorage.removeItem('token')")


@pytest.fixture(scope="function")
def test_application(authenticated_page: Page) -> dict:
    """
    Fixture that creates a test application and returns its details.
    Cleans up the application after the test.
    """
    app_name = "Test E2E Application"
    app_description = "Application for E2E testing"

    # Navigate to applications page
    authenticated_page.goto(f"{FRONTEND_URL}/applications")
    authenticated_page.wait_for_load_state("networkidle")

    # Click "Add Application" button
    authenticated_page.click('button:has-text("Add Application")')
    authenticated_page.wait_for_selector('input[name="name"]')

    # Fill application form
    authenticated_page.fill('input[name="name"]', app_name)
    authenticated_page.fill('textarea[name="description"]', app_description)
    authenticated_page.fill('input[name="vendor"]', "Test Vendor")

    # Submit form
    authenticated_page.click('button[type="submit"]')
    authenticated_page.wait_for_load_state("networkidle")

    # Get application ID from URL or table
    # For simplicity, we'll return the name and let tests find it
    yield {
        "name": app_name,
        "description": app_description,
        "vendor": "Test Vendor"
    }

    # Cleanup: delete the application
    authenticated_page.goto(f"{FRONTEND_URL}/applications")
    authenticated_page.wait_for_load_state("networkidle")

    # Find and delete the test application
    rows = authenticated_page.query_selector_all('table tbody tr')
    for row in rows:
        if app_name in row.text_content():
            row.click('button:has-text("Delete")')
            authenticated_page.on("dialog", lambda dialog: dialog.accept())
            break


@pytest.fixture(scope="function")
def test_sbom_file(tmp_path) -> str:
    """
    Fixture that creates a test SBOM file for upload.
    Returns the file path.
    """
    import json

    # Create a minimal CycloneDX SBOM
    sbom_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "Test Application",
                "version": "1.0.0"
            }
        },
        "components": [
            {
                "type": "library",
                "name": "test-package",
                "version": "1.0.0",
                "purl": "pkg:npm/test-package@1.0.0",
                "licenses": [{"license": {"id": "MIT"}}]
            }
        ]
    }

    sbom_path = tmp_path / "test-sbom.json"
    with open(sbom_path, "w") as f:
        json.dump(sbom_data, f)

    return str(sbom_path)


@pytest.fixture(scope="function")
def test_codebase_zip(tmp_path) -> str:
    """
    Fixture that creates a test codebase ZIP file.
    Returns the file path.
    """
    import zipfile

    zip_path = tmp_path / "test-codebase.zip"
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        # Add a simple test file
        zipf.writestr("test.py", "print('Hello, World!')")
        zipf.writestr("README.md", "# Test Codebase")

    return str(zip_path)


@pytest.fixture(scope="function")
def wait_for_sync_completion(page: Page):
    """
    Helper fixture that waits for CVE sync to complete.
    """
    def _wait(timeout_ms=30000):
        """
        Wait for sync button to return to normal state.
        """
        page.wait_for_selector('button:not(:has-text("Syncing..."))', timeout=timeout_ms)
        page.wait_for_load_state("networkidle")

    return _wait
