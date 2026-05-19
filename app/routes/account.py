from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional
from passlib.context import CryptContext

from app.database import get_db
from app.models.user import User
from app.auth import get_current_user

router = APIRouter(tags=["Account"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserUpdate(BaseModel):
    firstname: str
    surname: str
    number: str
    user_name: str
    image: Optional[str] = None
    password: Optional[str] = None


@router.get("/me")
async def get_me(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    user = db.query(User).filter(User.id == current_user.id).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "id": str(user.id),
        "firstname": user.firstname,
        "surname": user.surname,
        "number": user.number,
        "user_name": user.user_name,
        "credits": user.credits,
        "total_credits": user.total_credits,
        "bonus": user.bonus,
        "image": user.image,
        "created_on": user.created_on,
        "last_login": user.last_login,
    }


@router.put("/me")
async def update_me(
    payload: UserUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    user = db.query(User).filter(User.id == current_user.id).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    existing_number = (
        db.query(User)
        .filter(User.number == payload.number)
        .filter(User.id != user.id)
        .first()
    )

    if existing_number:
        raise HTTPException(
            status_code=400,
            detail="That mobile number is already in use",
        )

    user.firstname = payload.firstname.strip()
    user.surname = payload.surname.strip()
    user.number = payload.number.strip()
    user.user_name = payload.user_name.strip()
    user.image = payload.image

    if payload.password:
        if len(payload.password) < 6:
            raise HTTPException(
                status_code=400,
                detail="Password must be at least 6 characters",
            )

        user.password = pwd_context.hash(payload.password)

    db.commit()
    db.refresh(user)

    return {
        "message": "Profile updated",
        "user": {
            "id": str(user.id),
            "firstname": user.firstname,
            "surname": user.surname,
            "number": user.number,
            "user_name": user.user_name,
            "credits": user.credits,
            "total_credits": user.total_credits,
            "bonus": user.bonus,
            "image": user.image,
        },
    }