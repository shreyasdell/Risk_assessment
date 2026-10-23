from fastapi import Request, HTTPException, status
from collections import defaultdict
from time import time
from typing import Dict


class RateLimiter:
    def __init__(self):
        self.requests: Dict[str, list] = defaultdict(list)
        self.rate_limits = {
            'default': 200,  # 200 requests per minute (increased for development)
            'auth': 20,      # 20 requests per minute for auth endpoints (increased)
            'upload': 20,    # 20 requests per minute for uploads (increased)
        }

    def is_allowed(self, key: str, endpoint_type: str = 'default') -> bool:
        now = time()
        rate_limit = self.rate_limits.get(endpoint_type, self.rate_limits['default'])
        
        # Clean old requests
        self.requests[key] = [req_time for req_time in self.requests[key] if now - req_time < 60]
        
        if len(self.requests[key]) >= rate_limit:
            return False
        
        self.requests[key].append(now)
        return True


rate_limiter = RateLimiter()


async def rate_limit_middleware(request: Request, call_next):
    # Skip OPTIONS requests (CORS preflight)
    if request.method == 'OPTIONS':
        response = await call_next(request)
        return response
    
    client_ip = request.client.host if request.client else "unknown"
    path = request.url.path
    
    # Determine endpoint type
    endpoint_type = 'default'
    if '/auth/' in path:
        endpoint_type = 'auth'
    elif '/upload' in path:
        endpoint_type = 'upload'
    
    if not rate_limiter.is_allowed(client_ip, endpoint_type):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )
    
    response = await call_next(request)
    return response
