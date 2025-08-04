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
