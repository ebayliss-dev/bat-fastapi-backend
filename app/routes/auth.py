import base64
from datetime import timedelta
import hashlib
import uuid
import os
import asyncio
import aiohttp
import logging
from logging.handlers import RotatingFileHandler

from werkzeug.security import check_password_hash
from fastapi import APIRouter, Body, Depends, HTTPException, Query, status, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy import text
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address
import stripe
from jose import JWTError, jwt

from app import crud
from app.schemas.login import LoginRequest
from app.schemas.token import PasswordSubmitRequest, RefreshTokenRequest, Token
from ..database import get_db
from ..auth import (
    REFRESH_SECRET_KEY,
    create_access_token,
    create_refresh_token,
    get_current_active_user,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    SECRET_KEY,
    ALGORITHM,
    get_current_user,
)

# ---------------------------------------------------------------------------
# Logger Setup
# ---------------------------------------------------------------------------
LOG_FILE = os.path.join(os.path.dirname(__file__), "../logs/auth.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logger = logging.getLogger("auth_logger")
logger.setLevel(logging.DEBUG)

# Rotating file handler (10MB max per file, 5 backups)
handler = RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding='utf-8')
formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] [%(name)s:%(lineno)d] %(funcName)s(): %(message)s"
)
handler.setFormatter(formatter)
logger.addHandler(handler)

# ---------------------------------------------------------------------------
# Router and Limiter
# ---------------------------------------------------------------------------
router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


@router.post("/token", response_model=Token)
@limiter.limit("10/minute")
def login_for_access_token(request: Request, login: LoginRequest, db: Session = Depends(get_db)):
    logger.debug(f"Received login request: {login.dict(exclude={'password'})}")
    print(login)
    if login.loginType == "business":
        user = crud.get_user_by_number(db, number=login.username)
        print(user)
        logger.debug(f"Queried business user: {login.username}, Found: {bool(user)}")

        if not user:
            logger.warning(f"Login failed for user={login.username}: user not found")
            raise HTTPException(status_code=401, detail="Incorrect email or password")

        password_valid = verify_password(login.password, user.password)
        # logger.debug(f"Password validation result for user={login.username}: {password_valid}")

        # if not password_valid:
        #     logger.warning(f"Login failed for user={login.username}: invalid password")
        #     raise HTTPException(status_code=401, detail="Incorrect email or password")
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": str(user.id)}, expires_delta=access_token_expires, type="business"
        )
        refresh_token = create_refresh_token(data={"sub": str(user.id)})
        crud.update_user_last_login(db, user.id)

        logger.info(f"Business user {user.id} successfully logged in")
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "token_type": "business",
        }

    elif login.loginType == "client":
        user = crud.authenticate_client(db, login.username, login.password)
        logger.debug(f"Queried client user: {login.username}, Found: {bool(user)}")

        if not user:
            logger.warning(f"Client login failed for user={login.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": str(user.id)}, expires_delta=access_token_expires, type="client"
        )
        refresh_token = create_refresh_token(data={"sub": str(user.id)})

        logger.info(f"Client user {user.id} successfully logged in")
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "token_type": "client",
        }


class EmailCheck(BaseModel):
    email: EmailStr


@router.post("/check_email")
def check_email(payload: EmailCheck, db: Session = Depends(get_db)):
    logger.debug(f"Checking email availability: {payload.email}")
    email = payload.email.strip().lower()

    exists = (
        db.execute(
            text("SELECT 1 FROM public.accounts WHERE lower(number) = :number LIMIT 1"),
            {"number": email},
        ).scalar()
        is not None
    )
    logger.info(f"Email availability check for '{email}': {'exists' if exists else 'available'}")
    return {"available": not exists}


@router.post("/password_reset")
def password_reset(payload: PasswordSubmitRequest, db: Session = Depends(get_db)):
    logger.debug(f"Password reset request for id={payload.id}")

    if not payload.new_password or not isinstance(payload.new_password, str):
        logger.error("Missing new_password in payload")
        raise HTTPException(status_code=400, detail="new_password is required")
    if not payload.id or not isinstance(payload.id, str):
        logger.error("Missing id in payload")
        raise HTTPException(status_code=400, detail="id is required")

    password_hash = crud.generate_password_hash(payload.new_password)
    logger.debug(f"Generated password hash for user_id={payload.id}")

    try:
        result = db.execute(
            text("UPDATE public.accounts SET password = :password_hash WHERE id = :id"),
            {"id": payload.id, "password_hash": password_hash},
        )
        if result.rowcount == 0:
            db.rollback()
            logger.warning(f"Password reset failed: Account not found for id={payload.id}")
            raise HTTPException(status_code=404, detail="Account not found")

        db.commit()
        logger.info(f"Password successfully reset for user_id={payload.id}")
        return JSONResponse(status_code=200, content={"message": "Password reset successful"})

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.exception(f"Error resetting password for id={payload.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to reset password")


@router.post("/refresh")
def refresh_access_token(payload: RefreshTokenRequest, db: Session = Depends(get_db)):
    logger.debug("Refresh token request received")
    try:
        token = payload.refresh_token
        decoded = jwt.decode(token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        user_id = decoded.get("sub")
        if user_id is None:
            logger.warning("Invalid refresh token: missing sub")
            raise HTTPException(status_code=401, detail="Invalid refresh token")
    except JWTError as e:
        logger.warning(f"Invalid refresh token: {e}")
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user = crud.get_user(db, user_id)
    if not user:
        logger.warning(f"Refresh failed: user {user_id} not found")
        raise HTTPException(status_code=404, detail="User not found")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": str(user.id)}, expires_delta=access_token_expires)
    logger.info(f"Access token refreshed for user {user_id}")

    return {
        "access_token": access_token,
        "refresh_token": token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }




# ---------------------------------------------------------------------------
# Avatar Asset Download Handling
# ---------------------------------------------------------------------------
AVATAR_BASE_URL = "https://pawtul.com"
AVATAR_PREFIX = "/static/images/pet_avatars/"
LOCAL_AVATAR_DIR = "/tmp/avatars"
os.makedirs(LOCAL_AVATAR_DIR, exist_ok=True)


async def download_avatar(session, avatar_value: str):
    avatar_path = f"{AVATAR_PREFIX}{avatar_value}"
    url = f"{AVATAR_BASE_URL}{avatar_path}"
    local_path = os.path.join(LOCAL_AVATAR_DIR, avatar_value)

    if os.path.exists(local_path):
        logger.debug(f"Avatar already exists locally: {avatar_value}")
        return

    logger.debug(f"Downloading avatar: {url}")
    try:
        async with session.get(url) as resp:
            if resp.status == 200:
                with open(local_path, "wb") as f:
                    f.write(await resp.read())
                logger.info(f"Avatar saved: {avatar_value}")
            else:
                logger.warning(f"Avatar download failed ({resp.status}): {avatar_value}")
    except Exception as e:
        logger.exception(f"Error downloading avatar {avatar_value}: {e}")


@router.post("/assets")
async def get_assets_info(request: Request, db: Session = Depends(get_db)):
    logger.debug("Assets sync request received")
    try:
        body = await request.json()
        client_hash = body.get("hash")
        logger.debug(f"Client hash: {client_hash}")

        avatars = db.query(PetAvatar).order_by(PetAvatar.id.asc()).limit(100).all()
        avatar_values = [a.value for a in avatars if a.value]
        avatar_filenames = [val + ".png" if not val.endswith(".png") else val for val in avatar_values]
        avatar_paths = [f"{AVATAR_PREFIX}{val}" for val in avatar_filenames]

        hash_input = "".join(avatar_paths).encode("utf-8")
        current_hash = hashlib.sha256(hash_input).hexdigest()
        logger.debug(f"Current assets hash: {current_hash}")

        if client_hash and client_hash == current_hash:
            logger.info("Client assets already up-to-date")
            return JSONResponse({"match": True})

        async with aiohttp.ClientSession() as session:
            missing_files = [
                f for f in avatar_filenames
                if not os.path.exists(os.path.join(LOCAL_AVATAR_DIR, f))
            ]
            logger.debug(f"Missing avatars: {len(missing_files)}")
            if missing_files:
                await asyncio.gather(*(download_avatar(session, val) for val in missing_files))

        avatars_base64 = []
        for filename in avatar_filenames:
            file_path = os.path.join(LOCAL_AVATAR_DIR, filename)
            if os.path.exists(file_path):
                with open(file_path, "rb") as f:
                    base64_data = base64.b64encode(f.read()).decode("utf-8")
                    avatars_base64.append({"filename": filename, "base64": base64_data})
            else:
                logger.warning(f"Still missing avatar: {filename}")

        return JSONResponse(
            {"match": False, "assets_hash": current_hash, "avatars": avatars_base64}
        )

    except Exception as e:
        logger.exception(f"Error processing assets: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


def verify_password(plain_password: str, hashed_password: str) -> bool:
    logger.debug("Verifying password")
    try:
        if hashed_password.startswith('pbkdf2:sha256:'):
            result = check_password_hash(hashed_password, plain_password)
        elif hashed_password.startswith('sha256$'):
            stored_hash = hashed_password[7:]
            input_hash = hashlib.sha256(plain_password.encode('utf-8')).hexdigest()
            result = stored_hash == input_hash
        else:
            logger.warning(f"Unknown password format: {hashed_password[:20]}...")
            result = False
        logger.debug(f"Password verification result: {result}")
        return result
    except Exception as e:
        logger.exception(f"Password verification error: {e}")
        return False
