"""SecuriX Auth Service — FastAPI + PostgreSQL.

Endpoints:
  POST /api/auth/register  {name, email, password, role?} -> creates user in Postgres
  POST /api/auth/login     {email, password}              -> verifies against Postgres
  GET  /api/auth/me        (Bearer <jwt>)                 -> returns current user

Passwords are bcrypt-hashed. Auth tokens are HS256 JWTs.
No static / hardcoded users — everything lives in the app_users table.
"""
import logging
import os
import re
import sys
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
import psycopg2
import psycopg2.extras
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env"))
    load_dotenv()
except ImportError:
    pass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("auth-service")

app = FastAPI(title="CYBERLENS Auth Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:venkat%402007VK@localhost:5432/securix_db",
)
JWT_SECRET = os.getenv("JWT_SECRET", "securix-dev-secret-change-me")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", "24"))

VALID_ROLES = {"analyst", "cfo", "auditor", "admin"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS app_users (
    id            SERIAL PRIMARY KEY,
    name          VARCHAR(128) NOT NULL,
    email         VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(32)  NOT NULL DEFAULT 'analyst',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def get_conn():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True
    return conn


def ensure_schema():
    try:
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(CREATE_TABLE_SQL)
        finally:
            conn.close()
    except Exception as e:
        logger.warning("ensure_schema failed (DB may not be up yet): %s", e)


ensure_schema()


def normalize_email(email: str) -> str:
    return email.strip().lower()


def make_token(user_id: int, email: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired. Please login again.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid session token.")


def public_user(row: dict) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
        "role": row["role"],
        "created_at": str(row.get("created_at")),
    }


class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)
    role: str = "analyst"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


@app.get("/health")
def health():
    return {"status": "ok", "service": "auth-service"}


@app.post("/api/auth/register")
def register(req: RegisterRequest):
    name = req.name.strip()
    email = normalize_email(str(req.email))
    role = (req.role or "analyst").strip().lower()
    if role not in VALID_ROLES:
        role = "analyst"
    if not EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Invalid email address.")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")

    password_hash = bcrypt.hashpw(req.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    ensure_schema()
    try:
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT id FROM app_users WHERE LOWER(email)=LOWER(%s)", (email,))
                if cur.fetchone():
                    raise HTTPException(status_code=409, detail="Email already registered. Please login.")
                cur.execute(
                    "INSERT INTO app_users (name, email, password_hash, role) VALUES (%s,%s,%s,%s) RETURNING id, name, email, role, created_at",
                    (name, email, password_hash, role),
                )
                row = cur.fetchone()
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception as e:
        logger.error("register DB error: %s", e)
        raise HTTPException(status_code=500, detail="Database error. Is Postgres running?")

    user = public_user(dict(row))
    return {"success": True, "user": user, "token": make_token(user["id"], user["email"], user["role"])}


@app.post("/api/auth/login")
def login(req: LoginRequest):
    email = normalize_email(str(req.email))
    ensure_schema()
    try:
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM app_users WHERE LOWER(email)=LOWER(%s)", (email,))
                row = cur.fetchone()
        finally:
            conn.close()
    except Exception as e:
        logger.error("login DB error: %s", e)
        raise HTTPException(status_code=500, detail="Database error. Is Postgres running?")

    if not row:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    row = dict(row)
    if not bcrypt.checkpw(req.password.encode("utf-8"), row["password_hash"].encode("utf-8")):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    user = public_user(row)
    return {"success": True, "user": user, "token": make_token(user["id"], user["email"], user["role"])}


@app.get("/api/auth/me")
def me(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization Bearer header.")
    claims = decode_token(authorization.replace("Bearer ", "", 1).strip())
    ensure_schema()
    try:
        conn = get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT id, name, email, role, created_at FROM app_users WHERE id=%s", (claims.get("sub"),))
                row = cur.fetchone()
        finally:
            conn.close()
    except Exception as e:
        logger.error("me DB error: %s", e)
        raise HTTPException(status_code=500, detail="Database error.")
    if not row:
        raise HTTPException(status_code=401, detail="User not found.")
    return {"success": True, "user": public_user(dict(row))}


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8019"))
    uvicorn.run(app, host="0.0.0.0", port=port)
