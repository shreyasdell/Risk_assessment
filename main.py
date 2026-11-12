from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
import logging
from app.api import auth, vendors, applications, components, dashboard, cves, risk_scores, remediations, audit_logs, nist, search, reports, cache, normalize
from app.agent.router import router as agent_router
from app.middleware.rate_limit import rate_limit_middleware
from app.middleware.csrf import csrf_middleware

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Third Party Risk Assessment Tool",
    description="API for managing third-party risk assessment with CVE intelligence integration",
    version="1.0.0"
)

# Polling endpoints to log at DEBUG level instead of INFO
POLLING_ENDPOINTS = {
    "/cves/tasks/",
    "/risk-scores/",
}

@app.middleware("http")
async def filter_polling_logs(request: Request, call_next):
    """Middleware to reduce polling endpoint logs to DEBUG level."""
    path = request.url.path
    # Check if this is a polling endpoint
    is_polling = any(path.startswith(ep) for ep in POLLING_ENDPOINTS)
    
    if is_polling:
        # Temporarily set logger to DEBUG for this request
        original_level = logger.level
        logger.setLevel(logging.DEBUG)
        try:
            response = await call_next(request)
        finally:
            logger.setLevel(original_level)
        return response
    else:
        response = await call_next(request)
        return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add security middleware
# Note: Rate limiting disabled for development - enable in production
# app.middleware("http")(rate_limit_middleware)
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
app.include_router(cache.router)
app.include_router(normalize.router)
app.include_router(agent_router)


@app.get("/")
def read_root():
    return {"message": "Third Party Risk Assessment Tool API", "version": "1.0.0"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}
