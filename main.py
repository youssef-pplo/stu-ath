from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from passlib.hash import bcrypt
from database import SessionLocal, engine, Base
from models import Student
from schemas import RegisterRequest, LoginRequest, TokenResponse
from utils import create_access_token, create_refresh_token, verify_password
import requests
from pydantic import BaseModel
from jose import JWTError, jwt
from typing import Optional

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

SECRET_KEY = "Ea$yB1o"
ALGORITHM = "HS256"

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*", "http://localhost:5173"],  # unchanged
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database session dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# External OTP PHP endpoints
OTP_SEND_URL = "https://easybio-drabdelrahman.com/otp-system/send_otp.php"
OTP_VERIFY_URL = "https://easybio-drabdelrahman.com/otp-system/verify-otp.php"
OTP_STATUS_URL = "https://easybio-drabdelrahman.com/otp-system/status.php"

@app.post("/register")
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(Student).filter((Student.phone == data.phone) | (Student.email == data.email)).first():
        raise HTTPException(status_code=400, detail="Phone or Email already exists")
    
    if data.password != data.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    hashed_password = bcrypt.hash(data.password)
    student = Student(**data.dict(exclude={"password", "confirm_password"}), password=hashed_password)
    db.add(student)
    db.commit()
    db.refresh(student)

    # Send OTP to email
    try:
        requests.post(OTP_SEND_URL, data={"email": data.email})
    except Exception as e:
        print("Failed to send OTP:", e)

    return {"message": "Registered successfully. Please verify your email."}

@app.post("/login", response_model=TokenResponse)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    student = db.query(Student).filter(
        (Student.phone == data.identifier) |
        (Student.email == data.identifier) |
        (Student.student_code == data.identifier)
    ).first()

    if not student or not verify_password(data.password, student.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Check if email is verified
    try:
        res = requests.post(OTP_STATUS_URL, data={"email": student.email})
        if res.status_code != 200 or res.json().get("verified") is not True:
            raise HTTPException(status_code=403, detail="Email not verified")
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to verify email")

    return {
        "access_token": create_access_token(student.id),
        "refresh_token": create_refresh_token(student.id)
    }

# Schema for refresh token request
class RefreshRequest(BaseModel):
    refresh_token: str

@app.post("/refresh", response_model=TokenResponse)
def refresh_token(data: RefreshRequest):
    # In production, validate refresh token properly
    return {
        "access_token": create_access_token(1),
        "refresh_token": create_refresh_token(1)
    }

# OAuth2 for JWT token extraction
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dependency: get current student
def get_current_student(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        student_id = payload.get("sub")
        if student_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        student_id = int(student_id)
    except (JWTError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token verification failed"
        )

    student = db.query(Student).filter(Student.id == student_id).first()
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    return student

# Schema for profile response
class StudentProfileResponse(BaseModel):
    student_code: Optional[str]
    name: Optional[str]
    phone_number: Optional[str]
    email: Optional[str]
    username: Optional[str]
    parent_number: Optional[str]
    city: Optional[str]
    lang: Optional[str]
    year_of_study: Optional[str]
    password: str

@app.get("/student/profile", response_model=StudentProfileResponse)
def get_student_profile(
    current_user: Student = Depends(get_current_student)
):
    return StudentProfileResponse(
        student_code=current_user.student_code,
        name=current_user.name,
        phone_number=getattr(current_user, "phone", None),
        email=current_user.email,
        username=current_user.username,
        parent_number=getattr(current_user, "parent_number", None),
        city=getattr(current_user, "city", None),
        lang=getattr(current_user, "lang", None),
        year_of_study=getattr(current_user, "year_of_study", None),
        password="****"
    )
