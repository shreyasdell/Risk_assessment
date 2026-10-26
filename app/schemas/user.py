from pydantic import BaseModel, EmailStr, field_validator
from datetime import datetime
from typing import Optional
from app.models.user import UserRole


class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: UserRole = UserRole.VIEWER


class UserCreate(UserBase):
    password: str


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None  # Deprecated, kept for backward compatibility

    @field_validator('role')
    @classmethod
    def validate_role_assignment(cls, v, info):
        # Only admins can change roles (this is checked in the endpoint)
        return v


class UserResponse(UserBase):
    id: int
    is_active: bool
    is_admin: bool  # Deprecated, kept for backward compatibility
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None
