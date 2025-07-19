from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.models import User
from app.schemas import UserCreate
from app.services.auth import hash_password
from typing import Optional

def get_by_email(db: Session, email: str) -> Optional[User]:
    """
    Get a user by email
    
    Args:
        db: Database session
        email: User's email
        
    Returns:
        User object or None if not found
    """
    return db.query(User).filter(User.email == email).first()

def get_by_username(db: Session, username: str) -> Optional[User]:
    """
    Get a user by username
    
    Args:
        db: Database session
        username: User's username
        
    Returns:
        User object or None if not found
    """
    return db.query(User).filter(User.username == username).first()

def get_by_username_or_email(db: Session, username_or_email: str) -> Optional[User]:
    """
    Get a user by username or email
    
    Args:
        db: Database session
        username_or_email: User's username or email
        
    Returns:
        User object or None if not found
    """
    return db.query(User).filter(
        or_(User.username == username_or_email, User.email == username_or_email)
    ).first()

def get_by_id(db: Session, user_id: int) -> Optional[User]:
    """
    Get a user by ID
    
    Args:
        db: Database session
        user_id: User's ID
        
    Returns:
        User object or None if not found
    """
    return db.query(User).filter(User.id == user_id).first()

def create_user(db: Session, user_data: UserCreate) -> User:
    """
    Create a new user
    
    Args:
        db: Database session
        user_data: UserCreate schema with user data
        
    Returns:
        Created User object
        
    Raises:
        ValueError: If passwords don't match
    """
    # Validate passwords match
    if user_data.password != user_data.confirm_password:
        raise ValueError("Passwords do not match")
    
    # Create user with hashed password
    hashed_password = hash_password(user_data.password)
    
    # Create user object excluding confirm_password
    user_dict = user_data.dict(exclude={"confirm_password", "password"})
    db_user = User(**user_dict, password_hash=hashed_password)
    
    # Add and commit to DB
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return db_user
