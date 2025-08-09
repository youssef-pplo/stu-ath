from passlib.hash import bcrypt
from jose import jwt, JWTError
from datetime import datetime, timedelta
import random
import string

def generate_student_code():
    return "STU" + ''.join(random.choices(string.digits, k=6))

SECRET_KEY = "Ea$yB1o"  
ALGORITHM = "HS256"
def create_access_token(user_id: int):
    payload = {"sub": str(user_id), "exp": datetime.utcnow() + timedelta(minutes=15)}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def create_refresh_token(user_id: int):
    payload = {"sub": str(user_id), "exp": datetime.utcnow() + timedelta(days=7)}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)




def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None
