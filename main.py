
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import engine, Base, SessionLocal
from models import Student
from schemas import RegisterSchema, LoginSchema
from auth import hash_password, verify_password, create_access_token, create_refresh_token, decode_token
import requests

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

# === Register Endpoint ===
@app.post("/register")
def register(data: RegisterSchema, db: Session = Depends(get_db)):
    if data.password != data.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    if db.query(Student).filter((Student.phone == data.phone) | (Student.email == data.email)).first():
        raise HTTPException(status_code=400, detail="Phone or email already registered")

    from utils import generate_student_code
    student_code = generate_student_code()

    new_student = Student(
        name=data.name,
        phone=data.phone,
        email=data.email,
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

    # Send OTP
    try:
        requests.post(
            "https://easybio-drabdelrahman.com/otp-system/send_otp.php",
            data={"email": new_student.email}
        )
    except:
        pass

    return {"message": "Student registered. OTP sent to email.", "student_code": new_student.student_code}

# === Login Endpoint ===
@app.post("/login")
def login(data: LoginSchema, db: Session = Depends(get_db)):
    student = db.query(Student).filter(
        (Student.phone == data.identifier) |
        (Student.email == data.identifier) |
        (Student.student_code == data.identifier)
    ).first()

    if not student or not verify_password(data.password, student.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # Check verification
    try:
        resp = requests.get(f"https://easybio-drabdelrahman.com/otp-system/check_status.php?email={student.email}")
        if resp.json().get("verified") is not True:
            raise HTTPException(status_code=403, detail="Email not verified")
    except:
        raise HTTPException(status_code=500, detail="Verification server error")

    access_token = create_access_token({"sub": student.phone})
    refresh_token = create_refresh_token({"sub": student.phone})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "student": {
            "name": student.name,
            "student_code": student.student_code,
            "phone": student.phone,
            "email": student.email,
            "lang": student.lang
        }
    }

# === Refresh Token Endpoint ===
@app.post("/token/refresh")
def refresh_token(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing refresh token")

    refresh_token = auth_header.split(" ")[1]
    try:
        payload = decode_token(refresh_token)
        phone = payload.get("sub")
        new_token = create_access_token({"sub": phone})
        return {"access_token": new_token}
    except:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
