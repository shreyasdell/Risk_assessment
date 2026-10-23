# OWASP Security Implementation Details

## A01:2021 - Broken Access Control

**Location: `app/auth/dependencies.py`**
```python
def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
```

**Location: All API endpoints (e.g., `app/api/vendors.py`)**
```python
@router.post("/", response_model=VendorResponse, status_code=status.HTTP_201_CREATED)
def create_vendor_endpoint(
    vendor: VendorCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)  # Auth required
):
```

---

## A02:2021 - Cryptographic Failures

**Location: `app/auth/security.py`**
```python
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
```

**Location: `.env` (environment variables)**
```
SECRET_KEY=your-secret-key-here
NVD_API_KEY=F1943853-58DC-45C8-AE28-0D9B87165329
```

**Location: `app/core/config.py`**
```python
class Settings(BaseSettings):
    SECRET_KEY: str = Field(default="dev-secret-key")
    NVD_API_KEY: Optional[str] = None
```

---

## A03:2021 - Injection

**Location: All service files using SQLAlchemy ORM (e.g., `app/services/vendor_service.py`)**
```python
def get_vendor_by_name(db: Session, name: str):
    return db.query(Vendor).filter(Vendor.name == name).first()  # Parameterized query
```

**Location: `app/schemas/vendor.py` (Input validation)**
```python
class VendorBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    contact: Optional[EmailStr] = Field(None)  # Email validation
    
    @field_validator('name')
    @classmethod
    def name_must_not_contain_special_chars(cls, v):
        if not re.match(r'^[a-zA-Z0-9\s\-_.]+$', v):
            raise ValueError('Name must not contain special characters')
        return v.strip()
```

---

## A04:2021 - Insecure Design

**Location: `app/services/risk_service.py` (Risk assessment engine)**
```python
def calculate_risk_score(db: Session, application_id: int):
    # Multi-factor risk scoring algorithm
    cvss_weight = 0.40
    criticality_weight = 0.20
    internet_facing_weight = 0.15
    exploit_available_weight = 0.10
    patch_delay_weight = 0.10
    vendor_risk_weight = 0.05
```

**Location: `app/services/nist_service.py` (NIST recommendations)**
```python
def get_recommendation_for_cwe(db: Session, cwe_id: str):
    return db.query(NISTRecommendation).filter(NISTRecommendation.cwe_id == cwe_id).first()
```

---

## A05:2021 - Security Misconfiguration

**Location: `.env` (Environment-based configuration)**
```
DATABASE_URL=postgresql://user:password@localhost/dbname
SECRET_KEY=your-secret-key
NVD_API_KEY=your-api-key
```

**Location: `main.py` (CORS configuration)**
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Specific origins only
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Location: `app/middleware/rate_limit.py` (Rate limiting)**
```python
class RateLimiter:
    def __init__(self):
        self.rate_limits = {
            'default': 100,  # 100 requests per minute
            'auth': 5,       # 5 requests per minute for auth
            'upload': 10,    # 10 requests per minute for uploads
        }
```

---

## A06:2021 - Vulnerable and Outdated Components

**Location: `app/services/nvd_service.py` (CVE intelligence)**
```python
async def search_cves(component_name: str, version: str = None):
    # Search NVD API for vulnerabilities
    params = {
        'keyword': search_term,
        'resultsPerPage': 20
    }
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{NVD_API_URL}/cves/2.0",
            params=params,
            headers=headers
        )
```

**Location: `app/api/components.py` (SBOM upload)**
```python
@router.post("/upload-sbom")
async def upload_sbom(
    file: UploadFile,
    application_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    # Parse SBOM and extract components
    components = parse_sbom(file_content, file_type)
```

---

## A07:2021 - Identification and Authentication Failures

**Location: `app/api/auth.py`**
```python
@router.post("/login")
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    user = authenticate_user(db, credentials.username, credentials.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}
```

**Location: `app/auth/security.py` (JWT creation)**
```python
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
```

---

## A08:2021 - Software and Data Integrity Failures

**Location: `app/services/audit_service.py` (Audit logging)**
```python
def log(
    db: Session,
    action: str,
    resource_type: str,
    resource_id: Optional[int] = None,
    description: str = None,
    username: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
):
    audit_log = AuditLog(
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        description=description,
        username=username,
        ip_address=ip_address,
        user_agent=user_agent
    )
    db.add(audit_log)
    db.commit()
```

**Location: `app/models/vendor.py` (Database constraints)**
```python
class Vendor(Base):
    __tablename__ = "vendors"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False)  # Unique constraint
    # Foreign key constraints ensure referential integrity
```

---

## A09:2021 - Security Logging and Monitoring Failures

**Location: `app/api/audit_logs.py`**
```python
@router.get("/")
def list_audit_logs(
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    return audit_service.get_logs(
        db=db,
        action=action,
        resource_type=resource_type,
        username=username,
        limit=limit,
        skip=skip
    )
```

**Location: `app/middleware/rate_limit.py` (Monitoring rate limits)**
```python
async def rate_limit_middleware(request: Request, call_next):
    if not rate_limiter.is_allowed(client_ip, endpoint_type):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )
```

---

## A10:2021 - Server-Side Request Forgery (SSRF)

**Location: `app/services/nvd_service.py` (Trusted external API)**
```python
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"  # Trusted domain only

async def search_cves(component_name: str, version: str = None):
    # Only calls trusted NVD API, no user-controlled URLs
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{NVD_API_URL}/cves/2.0",  # Hardcoded trusted URL
            params=params,
            headers=headers,
            timeout=30.0
        )
```

---

## Additional Security Implementations

### CSRF Protection
**Location: `app/middleware/csrf.py`**
```python
def verify_csrf_token(request: Request) -> bool:
    if request.method in ['GET', 'HEAD', 'OPTIONS']:
        return True
    
    csrf_token = request.headers.get('X-CSRF-Token')
    if not csrf_token:
        return False
    
    if len(csrf_token) < 32:
        return False
    
    return True
```

### Input Validation
**Location: `app/schemas/application.py`**
```python
class ApplicationBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    owner: Optional[str] = Field(None, max_length=100)
    vendor_id: Optional[int] = Field(None, ge=1)  # Must be positive integer
    
    @field_validator('name')
    @classmethod
    def name_must_not_contain_special_chars(cls, v):
        if not re.match(r'^[a-zA-Z0-9\s\-_.]+$', v):
            raise ValueError('Name must not contain special characters')
        return v.strip()
```

### Rate Limiting
**Location: `main.py`**
```python
from app.middleware.rate_limit import rate_limit_middleware

app.middleware("http")(rate_limit_middleware)
```

---

## File Summary

| OWASP Category | Implementation File |
|----------------|---------------------|
| A01 - Access Control | `app/auth/dependencies.py`, All API files |
| A02 - Cryptography | `app/auth/security.py`, `.env`, `app/core/config.py` |
| A03 - Injection | All service files, All schema files |
| A04 - Insecure Design | `app/services/risk_service.py`, `app/services/nist_service.py` |
| A05 - Misconfiguration | `.env`, `main.py`, `app/middleware/rate_limit.py` |
| A06 - Vulnerable Components | `app/services/nvd_service.py`, `app/api/components.py` |
| A07 - Authentication | `app/api/auth.py`, `app/auth/security.py` |
| A08 - Data Integrity | `app/services/audit_service.py`, All model files |
| A09 - Logging | `app/api/audit_logs.py`, `app/middleware/rate_limit.py` |
| A10 - SSRF | `app/services/nvd_service.py` |
| CSRF Protection | `app/middleware/csrf.py` |
| Input Validation | `app/schemas/vendor.py`, `app/schemas/application.py`, `app/schemas/component.py` |
| Rate Limiting | `app/middleware/rate_limit.py`, `main.py` |
