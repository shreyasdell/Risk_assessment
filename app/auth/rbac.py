from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.auth.dependencies import get_current_active_user
from app.models.user import User


def require_admin(current_user: User = Depends(get_current_active_user)) -> User:
    """Require admin role"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


def require_admin_or_analyst(current_user: User = Depends(get_current_active_user)) -> User:
    """Require admin or analyst role"""
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst or admin access required"
        )
    return current_user


def require_write_access(current_user: User = Depends(get_current_active_user)) -> User:
    """Require write access (admin or analyst)"""
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write access requires analyst or admin role"
        )
    return current_user


def require_delete_access(current_user: User = Depends(get_current_active_user)) -> User:
    """Require delete access (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Delete access requires admin role"
        )
    return current_user


def require_user_management(current_user: User = Depends(get_current_active_user)) -> User:
    """Require user management access (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User management requires admin role"
        )
    return current_user
