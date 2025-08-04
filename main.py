
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import engine, Base, SessionLocal
from models import Student
from schemas import RegisterSchema, LoginSchema
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token
)
from utils import generate_student_code

app = FastAPI()

origins = ["http://localhost:5173", "https://easybio2025.netlify.app"]  
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
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

    existing = db.query(Student).filter(Student.phone == data.phone).first()
    if existing:
        raise HTTPException(status_code=400, detail="Phone already registered")

    student_code = generate_student_code()

    new_student = Student(
        name=data.name,
        phone=data.phone,
        parent_phone=data.parent_phone,
        city=data.city,
        grade=data.grade,
        lang=data.lang,
        password=hash_password(data.password),
        student_code=student_code
    )

    db.add(new_student)
    db.commit()
    db.refresh(new_student)

    access_token = create_access_token({"sub": new_student.phone})
    refresh_token = create_refresh_token({"sub": new_student.phone})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "student": {
            "name": new_student.name,
            "student_code": new_student.student_code,
            "phone": new_student.phone,
            "lang": new_student.lang
        }
    }

@app.post("/login")
def login(data: LoginSchema, db: Session = Depends(get_db)):
    student = db.query(Student).filter(
        (Student.phone == data.identifier) |
        (Student.student_code == data.identifier)
    ).first()

    if not student or not verify_password(data.password, student.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token = create_access_token({"sub": student.phone})
    refresh_token = create_refresh_token({"sub": student.phone})

    return {
        "access_token": access_token,
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
    body = await request.json()
    refresh_token = body.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=400, detail="Refresh token is required")

    sub = decode_token(refresh_token)
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    new_access_token = create_access_token({"sub": sub})
    return { "access_token": new_access_token }
