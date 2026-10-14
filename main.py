from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import auth, vendors, applications, components, dashboard

app = FastAPI(
    title="Third Party Risk Assessment Tool",
    description="API for managing third-party risk assessment with CVE intelligence integration",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(vendors.router)
app.include_router(applications.router)
app.include_router(components.router)
app.include_router(dashboard.router)


@app.get("/")
def read_root():
    return {"message": "Third Party Risk Assessment Tool API", "version": "1.0.0"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}
