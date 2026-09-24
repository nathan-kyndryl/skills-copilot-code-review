"""
Authentication endpoints for the High School Management System API
"""

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request, Response
from typing import Any, Dict

from ..database import teacher_sessions_collection, teachers_collection, verify_password

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

SESSION_COOKIE_NAME = "teacher_session"
SESSION_DURATION = timedelta(hours=8)
SESSION_TTL_SECONDS = int(SESSION_DURATION.total_seconds())


def _serialize_teacher(teacher: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "username": teacher["username"],
        "display_name": teacher["display_name"],
        "role": teacher["role"]
    }


def _session_expiration() -> datetime:
    return datetime.now(timezone.utc) + SESSION_DURATION


def require_teacher_session(request: Request) -> Dict[str, Any]:
    """Return the signed-in teacher for the current session."""
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_token:
        raise HTTPException(
            status_code=401, detail="Authentication required for this action")

    session = teacher_sessions_collection.find_one({
        "_id": session_token,
        "expires_at": {"$gt": datetime.now(timezone.utc)}
    })
    if not session:
        raise HTTPException(
            status_code=401, detail="Invalid teacher credentials")

    teacher_username = session["teacher_username"]
    teacher = teachers_collection.find_one({"_id": teacher_username})
    if not teacher or teacher.get("role") not in {"teacher", "admin"}:
        teacher_sessions_collection.delete_one({"_id": session_token})
        raise HTTPException(
            status_code=401, detail="Invalid teacher credentials")

    return teacher


@router.post("/login")
def login(username: str, password: str, response: Response) -> Dict[str, Any]:
    """Login a teacher account"""
    # Find the teacher in the database
    teacher = teachers_collection.find_one({"_id": username})

    # Verify password using Argon2 verifier from database.py
    if not teacher or not verify_password(teacher.get("password", ""), password):
        raise HTTPException(
            status_code=401, detail="Invalid username or password")

    session_token = secrets.token_urlsafe(32)
    teacher_sessions_collection.replace_one(
        {"_id": session_token},
        {
            "_id": session_token,
            "teacher_username": teacher["username"],
            "expires_at": _session_expiration()
        },
        upsert=True
    )
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        httponly=True,
        max_age=SESSION_TTL_SECONDS,
        samesite="lax"
    )

    # Return teacher information (excluding password)
    return _serialize_teacher(teacher)


@router.post("/logout")
def logout(request: Request, response: Response) -> Dict[str, str]:
    """Logout the current teacher session"""
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if session_token:
        teacher_sessions_collection.delete_one({"_id": session_token})

    response.delete_cookie(key=SESSION_COOKIE_NAME)
    return {"message": "Logged out"}


@router.get("/check-session")
def check_session(request: Request) -> Dict[str, Any]:
    """Check if the current teacher session is valid"""
    return _serialize_teacher(require_teacher_session(request))
