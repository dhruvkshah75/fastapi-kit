from pydantic import BaseModel, EmailStr, Field
from datetime import datetime 
from typing import Optional

# ===================== SCHEMAS RELATED TO USERS ==================================

# schema for the user creation
class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    class Config:
        from_attributes = True


# schema for the user login information
class UserLogin(BaseModel):
    identifier: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str

class Token_data(BaseModel):
    id: Optional[int] = None

# ============ API KEY SCHEMAS =================

# Used to display safe information about a key (NO secret value)
class ApiKeyInfo(BaseModel):
    id: int
    created_at: datetime
    expires_at: Optional[datetime] = None
    is_active: bool
    class Config:
        from_attributes = True

# Used ONLY for the response when a new key is created
class ApiKeyResponse(BaseModel):
    api_key: str
    expires_at: Optional[datetime] = None

class createAPIkey(BaseModel):
    days: Optional[int] = Field(
        30, 
        gt=0, 
        le=121,
        description="Number of days the key will be valid for. Must be a positive integer. Defaults to 30."
    )

