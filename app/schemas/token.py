from pydantic import BaseModel, EmailStr, validator
from datetime import datetime
from typing import Optional, List
import re
import uuid


# Authentication Schemas
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    email: Optional[str] = None  # Using email instead of username
    user_id: Optional[str] = None  # UUID as string


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class PasswordSubmitRequest(BaseModel):
    id: str
    new_password: str
