from pydantic import BaseModel

class RegisterSchema(BaseModel):
    name: str
    phone: str
    parent_phone: str
    city: str
    grade: str
    lang: str
    password: str
    confirm_password: str

class LoginSchema(BaseModel):
    identifier: str
    password: str
