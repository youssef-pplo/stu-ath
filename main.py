from fastapi import FastAPI, HTTPException, Depends
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
from jose import jwt

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI()


SECRET_KEY = "Ea$yB1o"
ALGORITHM = "HS256"

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*", "http://localhost:5173"],
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
        if res.status_code != 200 or res.json().get("verified") != True:
            raise HTTPException(status_code=403, detail="Email not verified")
    except Exception as e:
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
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Dependency: get current student
def get_current_student(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        student_id: str = payload.get("sub")
        if student_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    student = db.query(Student).filter(Student.id == student_id).first()
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    return student
# Schema for profile response
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

@app.get("/profile")
def get_profile(current_student: Student = Depends(get_current_student)):
    return {
        "student_code": current_student.stu_code,
        "name": current_student.name,
        "phone_number": current_student.phone_number,
        "email": current_student.email,
        "username": current_student.username,
        "parent_number": current_student.parent_number,
        "city": current_student.city,
        "lang": current_student.lang,
        "year_of_study": current_student.year_of_study,
        "password": "****"
    }
