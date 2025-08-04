from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import engine, Base, SessionLocal
from models import Student
from schemas import RegisterSchema, LoginSchema
from auth import hash_password, verify_password, create_access_token, create_refresh_token
from utils import generate_student_code
import requests

app = FastAPI()

origins = ["*"]  # Allow all origins for dev; restrict in prod

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/register")
def register(data: RegisterSchema, db: Session = Depends(get_db)):
    if data.password != data.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    existing = db.query(Student).filter((Student.phone == data.phone) | (Student.email == data.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Phone or email already registered")

    student_code = generate_student_code()

    new_student = Student(
        name=data.name,
        phone=data.phone,
        parent_phone=data.parent_phone,
        email=data.email,
        city=data.city,
        grade=data.grade,
        lang=data.lang,
        password=hash_password(data.password),
        student_code=student_code
    )

    db.add(new_student)
    db.commit()
    db.refresh(new_student)

    # Send OTP via PHP
    php_url = "https://easybio-drabdelrahman.com/otp-api/send-otp.php"
    resp = requests.post(php_url, data={"email": new_student.email})
    if resp.status_code != 200:
        raise HTTPException(500, "Failed to send OTP")

    return {"message": "Registered successfully. OTP sent to email."}


@app.post("/otp/verify")
async def otp_verify(request: Request):
    data = await request.json()
    email = data.get("email")
    otp = data.get("otp")
    resp = requests.post("https://easybio-drabdelrahman.com/otp-api/verify-otp.php", data={"email": email, "otp": otp})
    if resp.status_code == 200 and resp.json().get("verified"):
        return {"status": "verified"}
    raise HTTPException(400, "Invalid OTP")


@app.get("/otp/status")
def otp_status(email: str):
    resp = requests.get("https://easybio-drabdelrahman.com/otp-api/status.php", params={"email": email})
    return resp.json()


@app.post("/login")
def login(data: LoginSchema, db: Session = Depends(get_db)):
    student = db.query(Student).filter(
        (Student.phone == data.identifier) |
        (Student.email == data.identifier) |
        (Student.student_code == data.identifier)
    ).first()

    if not student or not verify_password(data.password, student.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # Check OTP status if login via email
    if "@" in data.identifier:
        resp = requests.get("https://easybio-drabdelrahman.com/otp-api/status.php", params={"email": data.identifier})
        if not resp.json().get("verified"):
            raise HTTPException(status_code=403, detail="Email not verified")

    access_token = create_access_token({"sub": student.phone})
    refresh_token = create_refresh_token({"sub": student.phone})

    return {
        "token": access_token,
        "refresh_token": refresh_token,
        "student": {
            "name": student.name,
            "student_code": student.student_code,
            "phone": student.phone,
            "lang": student.lang
        }
    }


@app.post("/token/refresh")
async def refresh_token(request: Request):
    data = await request.json()
    refresh_token = data.get("refresh_token")
    if not refresh_token:
        raise HTTPException(400, "Refresh token required")
    # Normally you'd verify refresh token here and issue a new access token
    # For simplicity, we’ll just create a new token
    payload = {"sub": "user"}  # TODO: Decode refresh token securely
    return {"access_token": create_access_token(payload)}
