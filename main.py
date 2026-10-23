from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import auth, vendors, applications, components, dashboard, cves, risk_scores, remediations, audit_logs, nist, search, reports
from app.middleware.rate_limit import rate_limit_middleware
from app.middleware.csrf import csrf_middleware

app = FastAPI(
    title="Third Party Risk Assessment Tool",
    description="API for managing third-party risk assessment with CVE intelligence integration",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add security middleware
app.middleware("http")(rate_limit_middleware)
# Note: CSRF middleware disabled for development - enable in production
# app.middleware("http")(csrf_middleware)

app.include_router(auth.router)
app.include_router(vendors.router)
app.include_router(applications.router)
app.include_router(components.router)
app.include_router(cves.router)
app.include_router(risk_scores.router)
app.include_router(remediations.router)
app.include_router(audit_logs.router)
app.include_router(nist.router)
app.include_router(dashboard.router)
app.include_router(search.router)
app.include_router(reports.router)


@app.get("/")
def read_root():
    return {"message": "Third Party Risk Assessment Tool API", "version": "1.0.0"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}
