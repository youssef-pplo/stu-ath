from pydantic import BaseModel

class RegisterRequest(BaseModel):
    name: str
    phone: str
    email: str
    parent_phone: str
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
    student_code: str
    name: str
    phone_number: str
    email: str
    username: str
    parent_number: str
    city: str
    lang: str
    grade: str
    password: str 
