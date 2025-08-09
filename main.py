from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from passlib.hash import bcrypt
from database import SessionLocal, engine, Base
from models import Student
from schemas import RegisterRequest, LoginRequest, TokenResponse
from utils import create_access_token, create_refresh_token, verify_password
from pydantic import BaseModel
from jose import JWTError, jwt
from typing import Optional
import requests

# -------------------------
# Configuration / Constants
# -------------------------
SECRET_KEY = "Ea$yB1o"    # <-- keep this value and make sure utils uses the same secret!
ALGORITHM = "HS256"

# External OTP PHP endpoints (used on register and login verification)
OTP_SEND_URL = "https://easybio-drabdelrahman.com/otp-system/send_otp.php"
OTP_STATUS_URL = "https://easybio-drabdelrahman.com/otp-system/status.php"
# -------------------------

# Create DB tables (no-op if already created)
Base.metadata.create_all(bind=engine)

app = FastAPI()

# CORS — preserved exactly as requested
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# DB session dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# OAuth2 scheme for extracting tokens from Authorization header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# -------------------------
# Helper: decode token safely
# -------------------------
def decode_token_or_none(token: str):
    """
    Decode JWT and return payload dict, or None on failure.
    Uses SECRET_KEY and ALGORITHM defined above.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

# -------------------------
# Register endpoint
# -------------------------
@app.post("/register")
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    # check uniqueness
    existing = db.query(Student).filter((Student.phone == data.phone) | (Student.email == data.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Phone or Email already exists")

    if data.password != data.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    # hash password
    hashed_password = bcrypt.hash(data.password)

    # create student
    student = Student(**data.dict(exclude={"password", "confirm_password"}), password=hashed_password)
    db.add(student)
    db.commit()
    db.refresh(student)

    # send OTP (don't block registration on email failure)
    try:
        requests.post(OTP_SEND_URL, data={"email": data.email}, timeout=5)
    except Exception as e:
        # log but don't fail registration
        print("OTP send failed:", e)

    # Issue tokens (make sure create_access_token uses same SECRET_KEY/ALGORITHM)
    access_token = create_access_token(student.id)
    refresh_token = create_refresh_token(student.id)

    return {
        "message": "Registered successfully. Please verify your email.",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "student": {
            "id": student.id,
            "student_code": getattr(student, "student_code", None),
            "name": student.name,
            "phone": student.phone,
            "email": student.email,
            "lang": getattr(student, "lang", None)
        }
    }

# -------------------------
# Login endpoint
# -------------------------
@app.post("/login", response_model=TokenResponse)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    # find by phone, email, or student_code
    student = db.query(Student).filter(
        (Student.phone == data.identifier) |
        (Student.email == data.identifier) |
        (Student.student_code == data.identifier)
    ).first()

    if not student or not verify_password(data.password, student.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Check email verified via OTP service (if email present)
    if student.email:
        try:
            resp = requests.post(OTP_STATUS_URL, data={"email": student.email}, timeout=5)
            # ensure JSON parseable
            try:
                status_json = resp.json()
            except ValueError:
                raise HTTPException(status_code=500, detail="OTP service returned invalid response")
            if not status_json.get("verified", False):
                raise HTTPException(status_code=403, detail="Email not verified")
        except HTTPException:
            # re-raise OTP related HTTPExceptions
            raise
        except Exception:
            raise HTTPException(status_code=500, detail="Failed to verify email")

    # issue tokens
    access_token = create_access_token(student.id)
    refresh_token = create_refresh_token(student.id)

    return {"access_token": access_token, "refresh_token": refresh_token}

# -------------------------
# Refresh endpoint
# -------------------------
class RefreshRequest(BaseModel):
    refresh_token: str

@app.post("/token/refresh")
def refresh_token(data: RefreshRequest):
    """
    Accepts JSON body { "refresh_token": "<token>" }.
    Validates & decodes the refresh token, issues a new access token.
    """
    token = data.refresh_token
    payload = decode_token_or_none(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    sub = payload.get("sub")
    if sub is None:
        raise HTTPException(status_code=401, detail="Invalid refresh token payload")

    # convert sub to int when possible (your tokens use student.id)
    try:
        student_id = int(sub)
    except Exception:
        student_id = sub

    # You may want to check a revocation DB here — omitted for brevity
    new_access = create_access_token(student_id)
    new_refresh = create_refresh_token(student_id)  # rotate refresh token if desired

    return {"access_token": new_access, "refresh_token": new_refresh}

# -------------------------
# Dependency: current student
# -------------------------
def get_current_student(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> Student:
    """
    Validates Authorization Bearer token and returns Student object.
    Raises 401 if token invalid, 404 if student not found.
    """
    payload = decode_token_or_none(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    sub = payload.get("sub")
    if sub is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    # convert to int if possible
    try:
        student_id = int(sub)
    except Exception:
        student_id = sub

    student = db.query(Student).filter(Student.id == student_id).first()
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    return student

# -------------------------
# Student profile endpoint
# -------------------------
class StudentProfileResponse(BaseModel):
    student_code: Optional[str]
    name: Optional[str]
    phone: Optional[str]
    email: Optional[str]
    username: Optional[str]
    parent_number: Optional[str]
    city: Optional[str]
    lang: Optional[str]
    grade: Optional[str]
    password: str

@app.get("/student/profile", response_model=StudentProfileResponse)
def get_student_profile(current_student: Student = Depends(get_current_student)):
    """
    Returns the authenticated student's profile. Missing fields become null.
    The password is masked.
    """
    return StudentProfileResponse(
        student_code=getattr(current_student, "student_code", None),
        name=getattr(current_student, "name", None),
        phone=getattr(current_student, "phone", None),
        email=getattr(current_student, "email", None),
        username=getattr(current_student, "username", None),
        parent_number=getattr(current_student, "parent_number", None),
        city=getattr(current_student, "city", None),
        lang=getattr(current_student, "lang", None),
        grade=getattr(current_student, "grade", None) or getattr(current_student, "year_of_study", None),
        password="****"
    )

# -------------------------
# Health / debug route
# -------------------------
@app.get("/")
def root():
    return {"status": "ok"}
