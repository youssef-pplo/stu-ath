from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from passlib.hash import bcrypt
from database import SessionLocal, engine, Base
from models import Student
from schemas import RegisterRequest, LoginRequest, TokenResponse
from utils import create_access_token, create_refresh_token, verify_password
import requests

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

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

    try:
        requests.post(OTP_SEND_URL, data={"email": data.email}, timeout=5)
    except requests.RequestException:
        pass  # Don't block registration on email failure

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
        res = requests.post(OTP_STATUS_URL, data={"email": student.email}, timeout=5)
        try:
            otp_status = res.json()
        except ValueError:
            raise HTTPException(status_code=500, detail="OTP service returned invalid response")

        if not otp_status.get("verified"):
            raise HTTPException(status_code=403, detail="Email not verified")
    except requests.RequestException:
        raise HTTPException(status_code=500, detail="Failed to contact OTP service")

    return {
        "access_token": create_access_token(student.id),
        "refresh_token": create_refresh_token(student.id)
    }

@app.post("/refresh", response_model=TokenResponse)
def refresh_token(refresh_token: str):
    # Dummy logic for refresh (in real case, validate JWT)
    return {
        "access_token": create_access_token(1),
        "refresh_token": create_refresh_token(1)
    }
