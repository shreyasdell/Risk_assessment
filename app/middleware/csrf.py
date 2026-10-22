from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer
import secrets
import os


security = HTTPBearer(auto_error=False)


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def verify_csrf_token(request: Request) -> bool:
    # Skip CSRF for GET, HEAD, OPTIONS
    if request.method in ['GET', 'HEAD', 'OPTIONS']:
        return True
    
    # Check CSRF token in headers
    csrf_token = request.headers.get('X-CSRF-Token')
    if not csrf_token:
        return False
    
    # In production, verify against session or database
    # For now, just check if token is present and valid format
    if len(csrf_token) < 32:
        return False
    
    return True


async def csrf_middleware(request: Request, call_next):
    if not verify_csrf_token(request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing or invalid"
        )
    
    response = await call_next(request)
    
    # Add CSRF token to response for state-changing requests
    if request.method in ['GET', 'HEAD', 'OPTIONS']:
        response.headers['X-CSRF-Token'] = generate_csrf_token()
    
    return response
