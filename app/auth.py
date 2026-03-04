from datetime import datetime, timedelta
from typing import Optional
import uuid

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError, jwt
import os

from app import crud

from .database import get_db
from app.models.user import User
from app.schemas import token

# JWT settings
SECRET_KEY = os.getenv("SECRET_KEY", "TEST")
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY", "TEST")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "525600"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "365"))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/token")

ONE_YEAR = timedelta(days=365)

def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
    type=None
):
    to_encode = data.copy()

    # Default to 12 months if not provided
    expire = datetime.utcnow() + (expires_delta or ONE_YEAR)

    to_encode.update({
        "exp": expire,
        "type": type
    })

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt



def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


from fastapi import Request


async def get_current_user(request: Request, db: Session = Depends(get_db)):

    auth_header = request.headers.get("authorization")

    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing token",
        )

    token = auth_header.replace("Bearer ", "")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = uuid.UUID(payload.get("sub"))
    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    user = crud.get_user(db, user_id=user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    # Since we don't have is_active column, just return the user
    # The property will always return True anyway
    return current_user


async def get_current_superuser(current_user: User = Depends(get_current_active_user)):
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return current_user
