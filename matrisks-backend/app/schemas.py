from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional
from datetime import datetime

class UserBase(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: str
    email: EmailStr
    gender: Optional[str] = None

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    confirm_password: str

    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v

class UserLogin(BaseModel):
    username_or_email: str
    password: str

class UserOut(UserBase):
    id: int
    is_active: bool
    is_superuser: bool | None = False
    is_admin: bool | None = False
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserOut

class TokenData(BaseModel):
    sub: Optional[str] = None
    exp: Optional[datetime] = None
