from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
import logging
import sys
from app.api import auth, vendors, applications, components, dashboard, cves, risk_scores, remediations, audit_logs, nist, search, reports, cache, normalize
from app.agent.router import router as agent_router
from app.middleware.rate_limit import rate_limit_middleware
from app.middleware.csrf import csrf_middleware

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Suppress uvicorn access logs for polling endpoints
class PollingLogFilter(logging.Filter):
    def __init__(self):
        super().__init__()
        self.polling_endpoints = ["/cves/tasks/", "/risk-scores/"]
    
    def filter(self, record):
        # Check if the log message contains a polling endpoint
        message = record.getMessage()
        if any(ep in message for ep in self.polling_endpoints):
            return False  # Don't log this message
        return True

# Apply the filter to uvicorn's access logger
uvicorn_logger = logging.getLogger("uvicorn.access")
uvicorn_logger.addFilter(PollingLogFilter())
# Set uvicorn access logger to WARNING level to suppress INFO logs
uvicorn_logger.setLevel(logging.WARNING)

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
