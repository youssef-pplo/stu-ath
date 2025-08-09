from pydantic import BaseModel
from typing import Optional

class RegisterRequest(BaseModel):
    name: str
    phone: str
    email: str
    parent_number: str   # rename from parent_phone
    city: str
    grade: str
    lang: str
    password: str
    confirm_password: str

class LoginRequest(BaseModel):
    identifier: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str

class StudentProfileResponse(BaseModel):
    student_code: Optional[str] = None
    name: str
    phone_number: str
    email: str
    username: Optional[str] = None
    parent_number: Optional[str] = None
    city: str
    lang: str
    grade: str
    password: str
