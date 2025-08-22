from fastapi import APIRouter, Depends, HTTPException, status, Response, Cookie
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import Optional
from datetime import timedelta
from jose import JWTError

from app.database import get_db
from app.schemas import UserCreate, UserOut, Token, UserLogin
from app.crud import user as user_crud
from app.services.auth import verify_password
from app.services.jwt import create_access_token, decode_token, SECRET_KEY, ALGORITHM

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# Refresh token settings
REFRESH_TOKEN_EXPIRE_DAYS = 7

async def get_current_user(
    token: str = Depends(oauth2_scheme), 
    db: Session = Depends(get_db)
) -> UserOut:
    """
    Get the current authenticated user from JWT token
    
    Args:
        token: JWT token from Authorization header
        db: Database session
    
    Returns:
        UserOut schema of authenticated user
        
    Raises:
        HTTPException: If token is invalid or user not found
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decode JWT token
        payload = decode_token(token)
        user_id = payload.get("sub")
        
        if user_id is None:
            raise credentials_exception
            
    except JWTError:
        raise credentials_exception
        
    # Get user from database
    user = user_crud.get_by_id(db, int(user_id))
    
    if user is None or not user.is_active:
        raise credentials_exception
        
    return user

@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    db: Session = Depends(get_db)
):
    """
    Register a new user
    
    Args:
        user_data: User registration data
        db: Database session
        
    Returns:
        Created user data
        
    Raises:
        HTTPException: If username or email already exists
    """
    # Check if username already exists
    if user_crud.get_by_username(db, user_data.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
        
    # Check if email already exists
    if user_crud.get_by_email(db, user_data.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create new user
    try:
        user = user_crud.create_user(db, user_data)
        return user
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/login", response_model=Token)
async def login(
    form_data: UserLogin,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Authenticate a user and return access token
    
    Args:
        form_data: Login credentials
        response: FastAPI response object (for setting cookies)
        db: Database session
        
    Returns:
        Access token and user data
        
    Raises:
        HTTPException: If authentication fails
    """
    # Get user by username or email
    user = user_crud.get_by_username_or_email(db, form_data.username_or_email)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify password
    if not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Generate access token
    access_token = create_access_token(sub=str(user.id))
    
    # Generate refresh token (longer lived)
    refresh_token = create_access_token(
        sub=str(user.id),
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )
    
    # Set refresh token as HTTP-only cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,  # For local development; set True in production
        samesite="lax",  # CSRF protection
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,  # in seconds
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user
    }

@router.post("/refresh", response_model=Token)
async def refresh_token(
    response: Response,
    refresh_token: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    """
    Refresh access token using refresh token cookie
    
    Args:
        response: FastAPI response object
        refresh_token: Refresh token from cookie
        db: Database session
        
    Returns:
        New access token and user data
        
    Raises:
        HTTPException: If refresh token is invalid
    """
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing"
        )
    
    try:
        # Decode refresh token
        payload = decode_token(refresh_token)
        user_id = payload.get("sub")
        
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
            
        # Get user from database
        user = user_crud.get_by_id(db, int(user_id))
        
        if user is None or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        # Generate new access token
        access_token = create_access_token(sub=str(user.id))
        
        # Generate new refresh token (for token rotation)
        new_refresh_token = create_access_token(
            sub=str(user.id),
            expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        )
        
        # Set new refresh token cookie
        response.set_cookie(
            key="refresh_token",
            value=new_refresh_token,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user
        }
            
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

@router.post("/logout")
async def logout(response: Response):
    """
    Logout user by clearing refresh token cookie
    
    Args:
        response: FastAPI response object
        
    Returns:
        Success message
    """
    # Clear refresh token cookie
    response.delete_cookie(
        key="refresh_token",
        httponly=True,
        secure=False,
        samesite="lax"
    )
    
    return {"detail": "Successfully logged out"}

@router.get("/me", response_model=UserOut)
async def me(current_user: UserOut = Depends(get_current_user)):
    return current_user
