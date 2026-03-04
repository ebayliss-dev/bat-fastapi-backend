from itsdangerous import URLSafeTimedSerializer
import os

SECRET = os.getenv("SECRET_KEY", "super-secret")
serializer = URLSafeTimedSerializer(SECRET)


def create_magic_token(mobile: str):
    return serializer.dumps(mobile, salt="magic-login")


def verify_magic_token(token: str, max_age=10000):
    return serializer.loads(token, salt="magic-login", max_age=max_age)