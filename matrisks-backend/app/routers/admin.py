from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.schemas import UserOut
from app.crud import user as user_crud
from app.routers.auth import get_current_user

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
)

@router.get("/users", response_model=List[UserOut])
async def get_all_users(
    db: Session = Depends(get_db),
    current_user: UserOut = Depends(get_current_user)
):
    """
    Get all users (admin only)
    
    Args:
        db: Database session
        current_user: Current authenticated user
        
    Returns:
        List of all users
        
    Raises:
        HTTPException: If user is not an admin
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can access this resource"
        )
    
    users = user_crud.get_all_users(db)
    return users

@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: UserOut = Depends(get_current_user)
):
    """
    Delete a user by ID (admin only)
    
    Args:
        user_id: ID of the user to delete
        db: Database session
        current_user: Current authenticated user
        
    Raises:
        HTTPException: If user is not an admin or user not found
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can delete users"
        )
    
    user = user_crud.get_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user_crud.delete_user(db, user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
