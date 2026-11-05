# E2E Tests with Playwright

This directory contains end-to-end tests for the Third Party Risk Assessment Tool using Playwright with pytest.

## Setup

### Prerequisites

1. Python 3.10+
2. Node.js 18+ (for frontend)
3. System dependencies for Playwright browsers

### Installation

```bash
# Install Python dependencies
pip install pytest-playwright

# Install Playwright browsers
playwright install chromium
```

### System Dependencies

On Ubuntu/Debian:
```bash
sudo apt-get install -y libxcb-shm0 libx11-xcb1 libxrandr2 libxcomposite1 libxcursor1 libxdamage1 libxi6 libxext6 libxfixes3 libx11-6 libxcb1 libgtk-3-0t64 libpangocairo-1.0-0 libpango-1.0-0 libatk1.0-0t64 libcairo-gobject2 libcairo2 libgdk-pixbuf-2.0-0 libglib2.0-0t64 libxrender1 libasound2t64 libfreetype6 libfontconfig1 libdbus-1-3
```

## Running Tests

### Run all tests
```bash
pytest tests/e2e/
```

### Run specific test file
```bash
pytest tests/e2e/test_auth.py
```

### Run with specific browser
```bash
pytest tests/e2e/ --browser=chromium
```

### Run in headed mode (visible browser)
```bash
pytest tests/e2e/ --headed
```

### Run with screenshots on failure
```bash
pytest tests/e2e/ --screenshot=only-on-failure
```

### Run with video recording
```bash
pytest tests/e2e/ --video=retain-on-failure
```

### Run critical workflow tests only
```bash
pytest tests/e2e/ -m critical
```

## Test Structure

```
tests/e2e/
├── conftest.py                 # Pytest fixtures and configuration
├── pytest.ini                  # Pytest configuration
├── README.md                   # This file
├── pages/                      # Page Object Model
│   ├── base_page.py           # Base page class
│   ├── login_page.py          # Login page
│   ├── applications_page.py   # Applications page
│   └── components_page.py     # Components page
└── test_*.py                  # Test files
    ├── test_auth.py           # Authentication tests
    ├── test_applications.py  # Application management tests
    ├── test_components.py     # Component management tests
    ├── test_cves.py           # CVE management tests
    ├── test_dashboard.py      # Dashboard tests
    └── test_critical_workflow.py  # Critical workflow tests
```

## Page Object Model

The tests use the Page Object Model pattern for maintainability:

- **BasePage**: Common methods for all pages (click, fill, wait, etc.)
- **LoginPage**: Login page interactions
- **ApplicationsPage**: Applications list and form
- **ComponentsPage**: Components list, SBOM upload, CVE sync
- **ApplicationFormPage**: Application creation/editing form
- **ComponentFormPage**: Component creation/editing form
- **SBOMUploadModal**: SBOM upload modal

## Fixtures

### authenticated_page
Provides a page with authenticated session (logs in before test, logs out after).

### api_authenticated_page
Provides a page with API authentication token (faster, no UI login).

### test_application
Creates a test application and returns its details. Cleans up after test.

### test_sbom_file
Creates a minimal test SBOM file for upload.

### test_codebase_zip
Creates a minimal test codebase ZIP file for upload.

### wait_for_sync_completion
Helper function to wait for CVE sync to complete.

## Test Categories

### Authentication Tests (`test_auth.py`)
- Login with valid credentials
- Login with invalid credentials
- Logout
- Protected route redirects to login

### Application Tests (`test_applications.py`)
- Create application
- View application details
- Edit application
- Delete application
- Search application
- Upload codebase to application

### Component Tests (`test_components.py`)
- Create component manually
- Upload SBOM
- Sync single component CVEs
- Sync all component CVEs
- Search component
- Filter by application
- View component details
- Edit component
- Delete component

### CVE Tests (`test_cves.py`)
- View CVEs page
- Filter by application
- Filter by severity
- Search by CVE ID
- Click CVE link opens NVD
- View CVE details
- Mark as false positive

### Dashboard Tests (`test_dashboard.py`)
- View dashboard
- Dashboard shows statistics
- Dashboard shows risk scores
- Navigate to applications
- Navigate to components
- Navigate to CVEs

### Critical Workflow Tests (`test_critical_workflow.py`)
- SBOM upload → CVE sync workflow
- Application creation → risk assessment workflow

## Configuration

Edit `pytest.ini` to change:
- Browser type (`--browser=chromium` / `firefox` / `webkit`)
- Headed mode (`--headed=true` / `false`)
- Screenshot behavior (`--screenshot=on` / `only-on-failure` / `off`)
- Video recording (`--video=on` / `retain-on-failure` / `off`)
- Timeout values

## Troubleshooting

### Tests fail with "browser not found"
```bash
playwright install chromium
```

### Tests fail with "missing dependencies"
Install system dependencies (see Setup section).

### Tests timeout
Increase timeout in `pytest.ini` or use `--timeout=120000`.

### Frontend not accessible
Ensure frontend is running on `http://localhost:5173`

### Backend not accessible
Ensure backend is running on `http://localhost:8000`

## Best Practices

1. **Use Page Objects**: Always use page object methods instead of direct Playwright calls
2. **Wait for Network Idle**: Use `wait_for_load_state("networkidle")` after navigation
3. **Use Fixtures**: Leverage fixtures for common setup/teardown
4. **Descriptive Test Names**: Use clear, descriptive test names
5. **Independent Tests**: Each test should be independent and not rely on other tests
6. **Cleanup**: Always clean up created data in fixtures
7. **Screenshots on Failure**: Enable screenshots for debugging failed tests

## CI/CD Integration

Add to your CI pipeline:

```yaml
# Example GitHub Actions
- name: Run E2E tests
  run: |
    pytest tests/e2e/ --browser=chromium --video=retain-on-failure
- name: Upload test artifacts
  if: failure()
  uses: actions/upload-artifact@v3
  with:
    name: test-results
    path: test-results/
```
