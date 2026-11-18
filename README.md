# Third Party Risk Assessment Tool

A FastAPI-based backend for managing third-party risk assessment with CVE intelligence integration, AI-powered analysis, and automated vulnerability scanning.

## Features

- **Authentication & Authorization**
  - JWT-based authentication
  - Role-based access control (admin, analyst, viewer)
  - User management (admin only)

- **Vendor Management**
  - Create, update, delete vendors
  - Vendor statistics and risk calculation
  - Application inventory per vendor

- **Application Management**
  - Create, update, delete applications
  - SBOM upload (CycloneDX, SPDX formats)
  - Codebase upload for component enrichment
  - Component inventory tracking

- **CVE Intelligence**
  - NVD API integration for CVE discovery
  - CVE.org API for precise verification
  - Two-phase CVE discovery and verification
  - CVE caching layer for performance
  - Individual component CVE sync
  - Bulk CVE sync with progress tracking
  - CVE filter agent with LLM analysis (Qwen via Ollama)
  - LangGraph agent for component enrichment
  - Confidence-based filtering

- **Risk Assessment**
  - Automated risk score calculation
  - Risk score history tracking
  - Severity distribution analysis
  - Component-level risk aggregation

- **Remediation Management**
  - Remediation recommendations
  - NIST compliance mappings
  - Patch availability tracking
  - Exploit status monitoring

- **Reporting**
  - Professional PDF report generation
  - Executive summary and full report options
  - Modular report architecture
  - Dell-style enterprise formatting

- **Audit & Logging**
  - Comprehensive audit trail
  - Recent activity tracking
  - User action logging

- **Search**
  - Full-text search across entities
  - Advanced filtering capabilities

- **Clean Architecture**
  - Separate modules for API, services, models
  - PostgreSQL database with SQLAlchemy ORM
  - Alembic database migrations
  - Podman/Docker support

## Project Structure

```
.
├── app/
│   ├── api/                    # API endpoints
│   │   ├── auth.py            # Authentication endpoints
│   │   ├── vendors.py         # Vendor endpoints
│   │   ├── applications.py    # Application endpoints
│   │   ├── components.py      # Component and SBOM endpoints
│   │   ├── cves.py            # CVE endpoints (sync, search, bulk sync)
│   │   ├── risk_scores.py     # Risk score calculation endpoints
│   │   ├── remediations.py    # Remediation management
│   │   ├── audit_logs.py      # Audit logging
│   │   ├── nist.py            # NIST compliance recommendations
│   │   ├── search.py          # Full-text search
│   │   ├── reports.py         # PDF report generation
│   │   ├── cache.py           # Cache management
│   │   └── normalize.py       # Component normalization
│   ├── auth/                  # Authentication module
│   │   ├── security.py        # JWT and password utilities
│   │   ├── dependencies.py   # Auth dependencies
│   │   └── rbac.py            # Role-based access control
│   ├── core/                  # Core configuration
│   │   ├── config.py          # Settings
│   │   └── database.py        # Database connection
│   ├── models/                # Database models
│   │   ├── user.py
│   │   ├── vendor.py
│   │   ├── application.py
│   │   ├── component.py
│   │   ├── cve.py
│   │   ├── risk_score.py
│   │   ├── remediation.py
│   │   ├── audit_log.py
│   │   └── sync_job.py        # Background sync job tracking
│   ├── schemas/               # Pydantic schemas
│   │   ├── user.py
│   │   ├── vendor.py
│   │   ├── application.py
│   │   ├── component.py
│   │   ├── cve.py
│   │   ├── risk_score.py
│   │   └── remediation.py
│   ├── services/              # Business logic
│   │   ├── auth_service.py
│   │   ├── vendor_service.py
│   │   ├── application_service.py
│   │   ├── component_service.py
│   │   ├── nvd_service.py     # NVD API integration
│   │   ├── cve_org_service.py # CVE.org API integration
│   │   ├── cve_cache_service.py # CVE caching layer
│   │   ├── risk_score_service.py
│   │   ├── remediation_service.py
│   │   ├── report_service.py  # PDF report generation
│   │   └── reporting/         # Modular report generation
│   │       ├── report_config.py
│   │       ├── report_service.py
│   │       ├── builders/
│   │       │   └── report_builder.py
│   │       └── sections/
│   │           ├── base_section.py
│   │           ├── cover_section.py
│   │           ├── executive_summary_section.py
│   │           ├── component_inventory_section.py
│   │           ├── vulnerability_details_section.py
│   │           ├── remediation_section.py
│   │           ├── risk_summary_section.py
│   │           └── appendix_section.py
│   ├── agent/                 # AI-powered analysis
│   │   ├── cve_filter_agent.py  # CVE filtering orchestrator
│   │   ├── stages/            # Pipeline stages
│   │   │   ├── cpe_matcher.py
│   │   │   ├── purl_resolver.py
│   │   │   ├── version_validator.py
│   │   │   ├── llm_reasoner.py
│   │   │   └── confidence_aggregator.py
│   │   └── normalizer/        # Component normalization
│   │       └── normalizer.py
│   └── sbom/                  # SBOM parsing
│       ├── parser.py           # CycloneDX and SPDX parsers
│       └── codebase_analyzer.py # Codebase file analysis
├── alembic/                   # Database migrations
│   ├── versions/
│   │   ├── 001_initial_migration.py
│   │   ├── 002_add_components_and_cves.py
│   │   ├── 003_add_risk_remediation_audit_nist_tables.py
│   │   ├── 004_add_vendor_enhancements.py
│   │   ├── 005_add_user_role.rbac.py
│   │   ├── 006_remove_purl_unique_constraint.py
│   │   ├── 007_add_cve_agent_fields.py
│   │   ├── 008_add_codebase_uploads.py
│   │   └── 009_add_sync_jobs_table.py
├── src/                       # Frontend (React)
│   ├── pages/                 # React pages
│   │   ├── LoginPage.jsx
│   │   ├── DashboardPage.jsx
│   │   ├── VendorsPage.jsx
│   │   ├── ApplicationsPage.jsx
│   │   ├── ComponentsPage.jsx
│   │   ├── CVEsPage.jsx
│   │   ├── RiskScoresPage.jsx
│   │   ├── RemediationsPage.jsx
│   │   ├── AuditLogsPage.jsx
│   │   └── CVERecommendationsPage.jsx
│   ├── api/                   # API client
│   │   └── client.js
│   └── context/               # React context
│       └── AuthContext.jsx
├── main.py                    # Application entry point
├── requirements.txt           # Python dependencies
├── Dockerfile                 # Container image configuration
└── docker-compose.yml       # Container compose configuration
```

## Setup

### Using Podman Compose (Recommended)

1. Install podman-compose if not already installed:
```bash
pip install podman-compose
```

2. Copy the example environment file:
```bash
cp .env.example .env
```

3. Start the services:
```bash
podman-compose up -d
```

4. Run database migrations:
```bash
podman-compose exec web alembic upgrade head
```

5. Access the API at http://localhost:8000
6. Access the interactive API documentation at http://localhost:8000/docs

7. Stop services:
```bash
podman-compose down
```

8. Stop and remove volumes (clean slate):
```bash
podman-compose down -v
```

### Local Development (Without Containers)

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up PostgreSQL database and update `.env` with your database URL

4. Run database migrations:
```bash
alembic upgrade head
```

5. Start the server:
```bash
uvicorn main:app --reload
```

## API Endpoints

### Authentication
- `POST /auth/register` - Register a new user
- `POST /auth/login` - Login and get JWT token
- `GET /auth/me` - Get current user info
- `GET /auth/users` - List all users (admin only)
- `GET /auth/users/{user_id}` - Get specific user (admin only)
- `PUT /auth/users/{user_id}` - Update user (admin only)
- `DELETE /auth/users/{user_id}` - Delete user (admin only)

### Vendors
- `POST /vendors/` - Create a new vendor
- `GET /vendors/` - List all vendors
- `GET /vendors/{vendor_id}` - Get specific vendor
- `PUT /vendors/{vendor_id}` - Update vendor
- `DELETE /vendors/{vendor_id}` - Delete vendor
- `GET /vendors/stats` - Get vendor statistics
- `GET /vendors/{vendor_id}/applications` - Get applications for vendor
- `POST /vendors/{vendor_id}/calculate-risk` - Calculate risk for vendor

### Applications
- `POST /applications/` - Create a new application
- `GET /applications/` - List all applications (optional filter by vendor_id)
- `GET /applications/{application_id}` - Get specific application
- `PUT /applications/{application_id}` - Update application
- `DELETE /applications/{application_id}` - Delete application
- `POST /applications/upload-codebase` - Upload codebase for component enrichment

### Components
- `POST /components/` - Create a new component
- `GET /components/` - List all components (optional filter by application_id, sbom_id)
- `GET /components/{component_id}` - Get specific component
- `PUT /components/{component_id}` - Update component
- `DELETE /components/{component_id}` - Delete component
- `POST /components/upload-sbom` - Upload and parse SBOM file (CycloneDX, SPDX)
- `POST /components/normalize` - Normalize component using LangGraph agent

### CVEs
- `GET /cves/` - List CVEs (supports filtering by severity, cvss, application_id, verification_status)
- `GET /cves/{cve_id}` - Get specific CVE
- `GET /cves/by-cve-id/{cve_id_str}` - Get CVE by CVE ID string
- `POST /cves/` - Create a new CVE
- `PUT /cves/{cve_id}` - Update CVE
- `DELETE /cves/{cve_id}` - Delete CVE
- `POST /cves/sync/{component_id}` - Sync CVEs for a single component
- `POST /cves/sync-all` - Bulk sync CVEs for all components (returns job_id for progress tracking)
- `GET /cves/sync-jobs/{job_id}` - Get sync job progress
- `GET /cves/component/{component_id}` - Get CVEs for a component
- `POST /cves/link` - Link CVE to component
- `DELETE /cves/unlink` - Unlink CVE from component
- `GET /cves/component/{component_id}/linked` - Get linked CVEs for component

### Risk Scores
- `POST /risk-scores/calculate/{application_id}` - Calculate risk score for application
- `POST /risk-scores/calculate-all` - Calculate risk scores for all applications
- `GET /risk-scores/application/{application_id}` - Get risk score for application
- `GET /risk-scores/application/{application_id}/history` - Get risk score history
- `GET /risk-scores/` - Get all risk scores

### NIST Recommendations
- `GET /nist` - Get all NIST recommendations
- `GET /nist/cwe/{cwe_id}` - Get NIST recommendations by CWE
- `GET /nist/cve/{cve_id}` - Get NIST recommendation for specific CVE
- `POST /nist` - Create NIST recommendation

### Remediations
- `GET /remediations/` - List all remediations
- `GET /remediations/{id}` - Get specific remediation
- `POST /remediations/` - Create remediation
- `PUT /remediations/{id}` - Update remediation
- `DELETE /remediations/{id}` - Delete remediation

### Reports
- `GET /reports/generate-pdf` - Generate PDF vulnerability assessment report
  - Query params: `application_id` (optional), `report_type` ('full' or 'executive')

### Dashboard
- `GET /dashboard/` - Get complete dashboard data
- `GET /dashboard/refresh-component-count` - Refresh component count
- `GET /dashboard/vendor/{vendor_id}` - Get dashboard data for specific vendor
- `GET /dashboard/application/{application_id}` - Get dashboard data for specific application

### Audit Logs
- `GET /audit-logs/` - List all audit logs
- `GET /audit-logs/recent` - Get recent activity

### Search
- `GET /search/` - Full-text search across entities

### Cache
- `DELETE /cache/clear` - Clear CVE cache

## Database Models

### User
- id, username, email, hashed_password
- role (admin, analyst, viewer)
- is_active, is_admin
- created_at, updated_at

### Vendor
- id, name, country, business_owner
- contact, service_type, hosting_model
- created_at, updated_at

### Application
- id, name, description, owner, business_unit
- criticality (low, medium, high, critical)
- internet_facing (boolean)
- data_classification (public, internal, confidential, restricted)
- environment (development, staging, production)
- vendor_id (foreign key)
- created_at, updated_at

### Component
- id, name, version, component_type (library, framework, sdk, tool, platform, os, database, other)
- purl (Package URL), supplier, description, license, cpe
- application_id (foreign key), sbom_id
- Enrichment fields (from LangGraph agent):
  - constructed_cpe
  - search_name
  - clean_version
  - normalized_name
- created_at, updated_at

### CVE
- id, cve_id, description, cvss_score, cvss_vector
- severity (none, low, medium, high, critical)
- cwe_id, published_date, modified_date
- exploit_available, patch_available
- references, nvd_url
- CVE.org cache fields:
  - cveorg_affected_products (JSON)
  - cveorg_fetched_at
  - cveorg_raw (JSON)
- Agent fields (from CVE Filter Agent):
  - agent_confidence (0-100)
  - agent_verdict (RELEVANT, NOT_RELEVANT, NEEDS_REVIEW)
  - agent_reasoning
  - match_method
  - stage_details (JSON)
  - is_false_positive
  - agent_processing_time
  - agent_processed_at
- created_at, updated_at

### RiskScore
- id, application_id (foreign key)
- overall_score (0-100)
- severity_level (low, medium, high, critical)
- critical_count, high_count, medium_count, low_count
- calculated_at

### Remediation
- id, cve_id (foreign key), application_id (foreign key)
- recommendation, priority (low, medium, high, critical)
- status (open, in_progress, completed, deferred)
- assigned_to, due_date
- created_at, updated_at

### AuditLog
- id, user_id (foreign key)
- action (create, update, delete, sync, etc.)
- entity_type (vendor, application, component, cve, etc.)
- entity_id
- details (JSON)
- timestamp

### SyncJob
- id, application_id (foreign key)
- status (running, completed, failed)
- total_components, processed_components
- current_component
- total_verified_cves
- started_at, completed_at

## Database Migrations

Create a new migration:
```bash
alembic revision --autogenerate -m "description"
```

Apply migrations:
```bash
alembic upgrade head
```

Rollback migrations:
```bash
alembic downgrade -1
```

## Security

- Passwords are hashed using bcrypt
- JWT tokens for authentication
- Role-based access control (admin, analyst, viewer)
- CORS middleware configured
- Input validation with Pydantic schemas
- SQL injection prevention via SQLAlchemy ORM

## CVE Verification Architecture

The system uses a two-phase approach for CVE discovery and verification:

### Phase 1: Discovery (NVD API)
- Keyword-based search using component name and version
- Multiple search strategies for better coverage
- Returns list of potentially relevant CVE IDs

### Phase 2: Verification (CVE.org API)
- Precise CPE matching using structured affected products data
- Version range validation
- AI-powered analysis for ambiguous cases (LLM via Ollama)
- Confidence scoring (0-100)
- Caching layer to reduce API calls

### CVE Filter Agent Pipeline
1. **CPE Matcher**: Matches component CPE against CVE CPEs
2. **PURL Resolver**: Resolves ecosystem mismatches
3. **Version Validator**: Validates version ranges
4. **LLM Reasoner**: Uses Qwen 2.5 7B for ambiguous cases
5. **Confidence Aggregator**: Aggregates results and produces final verdict

### Confidence Thresholds
- **VERIFIED (75+)**: High confidence, no manual review needed
- **NEEDS_REVIEW (50-74)**: Medium confidence, manual review recommended
- **REJECTED (<50)**: Low confidence, not relevant

## PDF Reporting

The system generates professional PDF vulnerability assessment reports with:

- **Modular Architecture**: Separate sections for cover, executive summary, component inventory, vulnerability details, remediation, risk summary, and appendix
- **Enterprise Formatting**: Dell-style colors and professional layout
- **Report Types**: Full report and executive summary options
- **Severity Indicators**: Color-coded severity banners
- **Pagination Safety**: Prevents content splitting across pages

## External Dependencies

- **Ollama**: Required for LLM-based CVE analysis (Qwen 2.5 7B model)
- **PostgreSQL**: Database backend
- **ReportLab**: PDF generation library
