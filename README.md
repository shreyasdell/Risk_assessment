# Third Party Risk Assessment Tool

A FastAPI-based backend for managing third-party risk assessment with CVE intelligence integration.

## Features

- JWT-based authentication
- Vendor management
- Application inventory
- SBOM upload and parsing (CycloneDX, SPDX formats)
- Component management
- CVE intelligence (model ready for NVD integration)
- Clean architecture with separate modules
- PostgreSQL database with SQLAlchemy ORM
- Alembic database migrations
- Podman support

## Project Structure

```
.
├── app/
│   ├── api/              # API endpoints
│   │   ├── auth.py       # Authentication endpoints
│   │   ├── vendors.py    # Vendor endpoints
│   │   ├── applications.py # Application endpoints
│   │   └── components.py # Component and SBOM endpoints
│   ├── auth/             # Authentication module
│   │   ├── security.py   # JWT and password utilities
│   │   └── dependencies.py # Auth dependencies
│   ├── core/             # Core configuration
│   │   ├── config.py     # Settings
│   │   └── database.py   # Database connection
│   ├── models/           # Database models
│   │   ├── user.py
│   │   ├── vendor.py
│   │   ├── application.py
│   │   ├── component.py
│   │   └── cve.py
│   ├── schemas/          # Pydantic schemas
│   │   ├── user.py
│   │   ├── vendor.py
│   │   ├── application.py
│   │   ├── component.py
│   │   └── cve.py
│   ├── services/         # Business logic
│   │   ├── auth_service.py
│   │   ├── vendor_service.py
│   │   ├── application_service.py
│   │   ├── component_service.py
│   │   └── sbom_service.py
│   └── sbom/             # SBOM parsing
│       └── parser.py     # CycloneDX and SPDX parsers
├── alembic/              # Database migrations
├── main.py               # Application entry point
├── requirements.txt      # Python dependencies
├── Dockerfile            # Container image configuration
└── docker-compose.yml    # Container compose configuration (works with podman-compose)
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

### Vendors
- `POST /vendors/` - Create a new vendor
- `GET /vendors/` - List all vendors
- `GET /vendors/{vendor_id}` - Get specific vendor
- `PUT /vendors/{vendor_id}` - Update vendor
- `DELETE /vendors/{vendor_id}` - Delete vendor

### Applications
- `POST /applications/` - Create a new application
- `GET /applications/` - List all applications (optional filter by vendor_id)
- `GET /applications/{application_id}` - Get specific application
- `PUT /applications/{application_id}` - Update application
- `DELETE /applications/{application_id}` - Delete application

### Components
- `POST /components/` - Create a new component
- `GET /components/` - List all components (optional filter by application_id, sbom_id)
- `GET /components/{component_id}` - Get specific component
- `PUT /components/{component_id}` - Update component
- `DELETE /components/{component_id}` - Delete component
- `POST /components/upload-sbom` - Upload and parse SBOM file (CycloneDX, SPDX)

### Dashboard
- `GET /dashboard/summary` - Get overall summary statistics
- `GET /dashboard/` - Get complete dashboard data
- `GET /dashboard/criticality-distribution` - Get application distribution by criticality
- `GET /dashboard/environment-distribution` - Get application distribution by environment
- `GET /dashboard/component-type-distribution` - Get component distribution by type
- `GET /dashboard/top-vendors` - Get top vendors by application count
- `GET /dashboard/top-applications` - Get top applications by component count
- `GET /dashboard/recent-activity` - Get recent activity across all entities
- `GET /dashboard/vendor/{vendor_id}` - Get dashboard data for specific vendor
- `GET /dashboard/application/{application_id}` - Get dashboard data for specific application

## Database Models

### User
- id, username, email, hashed_password
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
- created_at, updated_at

### CVE
- id, cve_id, description, cvss_score, cvss_vector
- severity (none, low, medium, high, critical)
- cwe_id, published_date, modified_date
- exploit_available, patch_available
- references, nvd_url
- created_at, updated_at

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
- Role-based access control (admin, regular user)
- CORS middleware configured
