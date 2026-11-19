from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.user import UserCreate, UserResponse, UserLogin, Token, UserUpdate
from app.services.auth_service import create_user, login_user, get_user_by_username, get_user_by_email, update_user
from app.auth.dependencies import get_current_active_user
from app.auth.rbac import require_admin, require_user_management
from app.models.user import User
from app.services.audit_service import audit_service

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(request: Request, user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    db_user = get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    result = create_user(db=db, user=user)
    
    # Log registration
    audit_service.log(
        db=db,
        action="CREATE",
        resource_type="user",
        resource_id=result.id,
        description=f"User registered: {user.username}",
        details={"username": user.username, "email": user.email, "role": user.role},
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    return result


@router.post("/login", response_model=Token)
def login(request: Request, user_login: UserLogin, db: Session = Depends(get_db)):
    token = login_user(db=db, user_login=user_login)
    if not token:
        # Log failed login attempt
        audit_service.log(
            db=db,
            action="LOGIN_FAILED",
            resource_type="user",
            description=f"Failed login attempt for username: {user_login.username}",
            details={"username": user_login.username},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Log successful login
    user = get_user_by_username(db, username=user_login.username)
    if user:
        audit_service.log(
            db=db,
            action="LOGIN",
            resource_type="user",
            resource_id=user.id,
            description=f"User logged in: {user.username}",
            details={"username": user.username, "role": user.role},
            user_id=user.id,
            username=user.username,
            user_role=user.role,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
    
    return token


@router.get("/me", response_model=UserResponse)
def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@router.get("/users", response_model=list[UserResponse])
def read_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_user_management)
):
    users = db.query(User).offset(skip).limit(limit).all()
    return users


@router.get("/users/{user_id}", response_model=UserResponse)
def read_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_user_management)
):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.put("/users/{user_id}", response_model=UserResponse)
def update_user_endpoint(
    request: Request,
    user_id: int,
    user_update: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_user_management)
):
    # Only admins can change roles
    if user_update.role and current_user.role.lower() != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can change user roles"
        )
    
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Store old values for audit
    old_values = {
        "username": db_user.username,
        "email": db_user.email,
        "role": db_user.role,
        "is_active": db_user.is_active
    }
    
    result = update_user(db=db, user_id=user_id, user_update=user_update)
    
    # Log user update
    audit_service.log(
        db=db,
        action="UPDATE",
        resource_type="user",
        resource_id=user_id,
        description=f"User updated: {db_user.username}",
        details={
            "old_values": old_values,
            "new_values": {
                "username": result.username,
                "email": result.email,
                "role": result.role,
                "is_active": result.is_active
            },
            "changed_by": current_user.username
        },
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    return result


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_user_management)
):
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Store user info for audit before deletion
    user_info = {
        "username": db_user.username,
        "email": db_user.email,
        "role": db_user.role
    }
    
    db.delete(db_user)
    db.commit()
    
    # Log user deletion
    audit_service.log(
        db=db,
        action="DELETE",
        resource_type="user",
        resource_id=user_id,
        description=f"User deleted: {user_info['username']}",
        details={"deleted_user": user_info, "deleted_by": current_user.username},
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    return None
