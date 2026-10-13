import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(os.getenv("SSI_DATABASE", BASE_DIR / "student_analytics.db"))
TOKEN_SECRET = os.getenv("SSI_TOKEN_SECRET")
if not TOKEN_SECRET:
    TOKEN_SECRET = secrets.token_urlsafe(48)
    print("WARNING: SSI_TOKEN_SECRET is unset; sessions will expire when the server restarts.")

app = FastAPI(title="KPMG Student Analytics API", version="1.0.0")
bearer = HTTPBearer(auto_error=False)

STUDENTS = [
    {"id": "S101", "name": "Aarav", "section": "A", "cgpa": 9.2, "marks": 88, "attendance": 94, "backlogs": 0},
    {"id": "S102", "name": "Diya", "section": "A", "cgpa": 8.7, "marks": 82, "attendance": 86, "backlogs": 0},
    {"id": "S103", "name": "Rahul", "section": "A", "cgpa": 7.5, "marks": 70, "attendance": 72, "backlogs": 1},
    {"id": "S104", "name": "Priya", "section": "B", "cgpa": 9.5, "marks": 93, "attendance": 96, "backlogs": 0},
    {"id": "S105", "name": "Kiran", "section": "B", "cgpa": 7.9, "marks": 76, "attendance": 79, "backlogs": 0},
    {"id": "S106", "name": "Ananya", "section": "B", "cgpa": 8.9, "marks": 84, "attendance": 88, "backlogs": 0},
]


def connect_db():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def database():
    connection = connect_db()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database():
    with database() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                email TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('student', 'teacher', 'management')),
                student_id TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY,
                student_id TEXT NOT NULL,
                student_name TEXT NOT NULL,
                section TEXT NOT NULL,
                subject TEXT NOT NULL,
                date TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('Present', 'Absent')),
                submitted_by TEXT NOT NULL,
                submitted_at TEXT NOT NULL,
                UNIQUE(student_id, date, subject)
            );
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL REFERENCES accounts(email),
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
                message TEXT NOT NULL,
                date TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS assessments (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                deadline TEXT NOT NULL,
                questions TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY,
                assessment_id TEXT NOT NULL REFERENCES assessments(id),
                title TEXT NOT NULL,
                email TEXT NOT NULL REFERENCES accounts(email),
                student_name TEXT NOT NULL,
                student_id TEXT NOT NULL,
                answers TEXT NOT NULL,
                score INTEGER NOT NULL,
                total INTEGER NOT NULL,
                submitted_at TEXT NOT NULL,
                UNIQUE(assessment_id, email)
            );
            """
        )


@app.on_event("startup")
def startup():
    initialize_database()


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"{salt.hex()}:{derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, expected_hex = stored_hash.split(":", 1)
        actual = hash_password(password, bytes.fromhex(salt_hex)).split(":", 1)[1]
        return hmac.compare_digest(actual, expected_hex)
    except (ValueError, TypeError):
        return False


def create_token(email: str) -> str:
    expires = int(time.time()) + 60 * 60 * 12
    payload = json.dumps({"sub": email, "exp": expires}, separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    signature = hmac.new(TOKEN_SECRET.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
):
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    try:
        encoded, signature = credentials.credentials.split(".", 1)
        expected = hmac.new(TOKEN_SECRET.encode(), encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("Invalid signature")
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if payload["exp"] <= time.time():
            raise ValueError("Expired token")
        with database() as db:
            user = db.execute(
                "SELECT email, name, role, student_id AS studentId FROM accounts WHERE email = ?",
                (payload["sub"],),
            ).fetchone()
        if user is None:
            raise ValueError("Unknown account")
        return dict(user)
    except (ValueError, KeyError, json.JSONDecodeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired session")


def require_roles(*roles: str):
    def check_role(user=Depends(get_current_user)):
        if user["role"] not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return check_role


def public_account(row):
    return {
        "email": row["email"],
        "name": row["name"],
        "role": row["role"],
        "studentId": row["student_id"],
    }


class RegisterRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: str = Field(min_length=3, max_length=254)
    role: Literal["student", "teacher", "management"]
    studentId: str = ""
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: str
    password: str


class AttendanceEntry(BaseModel):
    studentId: str
    status: Literal["Present", "Absent"]


class AttendanceRequest(BaseModel):
    section: Literal["A", "B"]
    date: str
    subject: str = Field(min_length=1, max_length=100)
    records: list[AttendanceEntry] = Field(min_length=1, max_length=100)


class FeedbackRequest(BaseModel):
    category: str = Field(min_length=1, max_length=100)
    rating: int = Field(ge=1, le=5)
    message: str = Field(min_length=1, max_length=5000)


class AssessmentQuestion(BaseModel):
    question: str = Field(min_length=1, max_length=1000)
    options: list[str] = Field(min_length=2, max_length=20)
    answer: str


class AssessmentRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=5000)
    deadline: str
    questions: list[AssessmentQuestion] = Field(min_length=1, max_length=50)


class SubmissionRequest(BaseModel):
    answers: list[str]


@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
def register(request: RegisterRequest):
    email = request.email.strip().lower()
    name = request.name.strip()
    if not name or "@" not in email:
        raise HTTPException(status_code=400, detail="Enter a valid name and email")
    student_id = request.studentId.strip().upper() if request.role == "student" else ""
    if request.role == "student" and student_id not in {student["id"] for student in STUDENTS}:
        raise HTTPException(status_code=400, detail="Use a sample student ID from S101 to S106")
    try:
        with database() as db:
            db.execute(
                "INSERT INTO accounts(email, name, role, student_id, password_hash) VALUES (?, ?, ?, ?, ?)",
                (email, name, request.role, student_id, hash_password(request.password)),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="This email is already registered")
    return {"message": "Registration successful"}


@app.post("/api/auth/login")
def login(request: LoginRequest):
    email = request.email.strip().lower()
    with database() as db:
        account = db.execute("SELECT * FROM accounts WHERE email = ?", (email,)).fetchone()
    if account is None or not verify_password(request.password, account["password_hash"]):
        raise HTTPException(status_code=401, detail="Email or password is incorrect")
    return {"token": create_token(email), "user": public_account(account)}


@app.get("/api/me")
def me(user=Depends(get_current_user)):
    return user


@app.get("/api/students")
def list_students(_user=Depends(require_roles("teacher", "management"))):
    return STUDENTS


@app.get("/api/attendance")
def list_attendance(user=Depends(get_current_user)):
    with database() as db:
        if user["role"] == "student":
            rows = db.execute(
                "SELECT * FROM attendance WHERE student_id = ? ORDER BY id",
                (user["studentId"],),
            ).fetchall()
        else:
            rows = db.execute("SELECT * FROM attendance ORDER BY id").fetchall()
    return [
        {
            "studentId": row["student_id"],
            "studentName": row["student_name"],
            "section": row["section"],
            "subject": row["subject"],
            "date": row["date"],
            "status": row["status"],
            "submittedBy": row["submitted_by"],
            "submittedAt": row["submitted_at"],
        }
        for row in rows
    ]


@app.post("/api/attendance")
def save_attendance(request: AttendanceRequest, user=Depends(require_roles("teacher", "management"))):
    try:
        datetime.strptime(request.date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=400, detail="Date must use YYYY-MM-DD format")
    roster = [student for student in STUDENTS if student["section"] == request.section]
    by_id = {entry.studentId: entry for entry in request.records}
    if len(request.records) != len(roster) or set(by_id) != {student["id"] for student in roster}:
        raise HTTPException(status_code=400, detail="Mark each student in the selected section exactly once")
    submitted_at = datetime.now(timezone.utc).isoformat()
    with database() as db:
        for student in roster:
            db.execute(
                """
                INSERT INTO attendance(student_id, student_name, section, subject, date, status, submitted_by, submitted_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(student_id, date, subject) DO UPDATE SET
                    student_name=excluded.student_name,
                    section=excluded.section,
                    status=excluded.status,
                    submitted_by=excluded.submitted_by,
                    submitted_at=excluded.submitted_at
                """,
                (
                    student["id"], student["name"], request.section, request.subject,
                    request.date, by_id[student["id"]].status, user["name"], submitted_at,
                ),
            )
    return {"message": "Attendance saved", "count": len(roster)}


@app.get("/api/feedback")
def list_feedback(user=Depends(get_current_user)):
    with database() as db:
        if user["role"] == "student":
            rows = db.execute("SELECT * FROM feedback WHERE email = ? ORDER BY id", (user["email"],)).fetchall()
        else:
            rows = db.execute("SELECT * FROM feedback ORDER BY id").fetchall()
    return [dict(row) for row in rows]


@app.post("/api/feedback", status_code=status.HTTP_201_CREATED)
def submit_feedback(request: FeedbackRequest, user=Depends(get_current_user)):
    message = request.message.strip()
    if not message:
        raise HTTPException(status_code=400, detail="Feedback message cannot be empty")
    with database() as db:
        cursor = db.execute(
            "INSERT INTO feedback(email, name, category, rating, message, date) VALUES (?, ?, ?, ?, ?, ?)",
            (user["email"], user["name"], request.category.strip(), request.rating, message, datetime.now().date().isoformat()),
        )
        row = db.execute("SELECT * FROM feedback WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return dict(row)


def assessment_dict(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "description": row["description"],
        "deadline": row["deadline"],
        "questions": json.loads(row["questions"]),
        "createdBy": row["created_by"],
        "createdAt": row["created_at"],
    }


def is_past_deadline(deadline: str) -> bool:
    parsed = datetime.fromisoformat(deadline.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    return datetime.now().astimezone() > parsed.astimezone()


@app.get("/api/assessments")
def list_assessments(user=Depends(get_current_user)):
    with database() as db:
        assessments = db.execute("SELECT * FROM assessments ORDER BY created_at").fetchall()
        if user["role"] in {"management", "teacher"}:
            submissions = db.execute("SELECT * FROM submissions ORDER BY id").fetchall()
        elif user["role"] == "student":
            submissions = db.execute(
                "SELECT * FROM submissions WHERE email = ? ORDER BY id", (user["email"],)
            ).fetchall()
        else:
            submissions = []
    public_assessments = [assessment_dict(row) for row in assessments]
    for assessment in public_assessments:
        for question in assessment["questions"]:
            question.pop("answer", None)
    return {
        "assessments": public_assessments,
        "submissions": [
            {
                "assessmentId": row["assessment_id"],
                "title": row["title"],
                "email": row["email"],
                "studentName": row["student_name"],
                "studentId": row["student_id"],
                "answers": json.loads(row["answers"]),
                "score": row["score"],
                "total": row["total"],
                "submittedAt": row["submitted_at"],
            }
            for row in submissions
        ],
    }


@app.post("/api/assessments", status_code=status.HTTP_201_CREATED)
def create_assessment(request: AssessmentRequest, user=Depends(require_roles("management"))):
    try:
        if is_past_deadline(request.deadline):
            raise HTTPException(status_code=400, detail="Choose a future submission deadline")
    except ValueError:
        raise HTTPException(status_code=400, detail="Deadline must be a valid ISO date and time")
    title = request.title.strip()
    description = request.description.strip()
    if not title or not description:
        raise HTTPException(status_code=400, detail="Assessment title and description cannot be empty")
    questions = [question.dict() for question in request.questions]
    for index, question in enumerate(questions, start=1):
        question["question"] = question["question"].strip()
        question["options"] = [option.strip() for option in question["options"]]
        question["answer"] = question["answer"].strip()
        options = question["options"]
        if not question["question"]:
            raise HTTPException(status_code=400, detail=f"Question {index} cannot be empty")
        if any(not option.strip() for option in options) or len(set(options)) != len(options):
            raise HTTPException(status_code=400, detail=f"Question {index} has empty or duplicate options")
        if question["answer"] not in options:
            raise HTTPException(status_code=400, detail=f"Question {index} answer must match one of its options")
    assessment_id = "A" + secrets.token_hex(8)
    created_at = datetime.now(timezone.utc).isoformat()
    with database() as db:
        db.execute(
            "INSERT INTO assessments(id, title, description, deadline, questions, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                assessment_id, title, description,
                request.deadline, json.dumps(questions), user["name"], created_at,
            ),
        )
        row = db.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,)).fetchone()
    return assessment_dict(row)


@app.post("/api/assessments/{assessment_id}/submissions", status_code=status.HTTP_201_CREATED)
def submit_assessment(assessment_id: str, request: SubmissionRequest, user=Depends(require_roles("student"))):
    with database() as db:
        assessment = db.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,)).fetchone()
        if assessment is None:
            raise HTTPException(status_code=404, detail="Assessment not found")
        questions = json.loads(assessment["questions"])
        if len(request.answers) != len(questions):
            raise HTTPException(status_code=400, detail="Provide one answer for every question")
        if is_past_deadline(assessment["deadline"]):
            raise HTTPException(status_code=400, detail="The submission deadline has passed")
        student_id = user["studentId"]
        if not student_id:
            raise HTTPException(status_code=400, detail="Student account is not linked to a student record")
        score = sum(answer == question["answer"] for answer, question in zip(request.answers, questions))
        submitted_at = datetime.now(timezone.utc).isoformat()
        try:
            db.execute(
                """
                INSERT INTO submissions(assessment_id, title, email, student_name, student_id, answers, score, total, submitted_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assessment_id, assessment["title"], user["email"], user["name"], student_id,
                    json.dumps(request.answers), score, len(questions), submitted_at,
                ),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="You have already submitted this assessment")
    return {"assessmentId": assessment_id, "score": score, "total": len(questions), "submittedAt": submitted_at}


@app.get("/")
def index():
    return FileResponse(BASE_DIR / "inedx.html")
