from passlib.hash import bcrypt
from jose import jwt
from datetime import datetime, timedelta
import random

def generate_student_code():
    return "STU" + str(random.randint(100000, 999999))

SECRET_KEY = "secret"

def create_access_token(user_id: int):
    payload = {"sub": str(user_id), "exp": datetime.utcnow() + timedelta(minutes=15)}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def create_refresh_token(user_id: int):
    payload = {"sub": str(user_id), "exp": datetime.utcnow() + timedelta(days=7)}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_password(plain_password, hashed_password):
    return bcrypt.verify(plain_password, hashed_password)
