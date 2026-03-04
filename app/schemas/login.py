from pydantic import BaseModel, EmailStr, validator
from datetime import datetime
from typing import Optional, List
import re
import uuid


class LoginRequest(BaseModel):
    username: str  # or email, depending on your app
    password: str
    loginType: str
