"""
Authentication endpoints for the High School Management System API
"""

import secrets

from fastapi import APIRouter, HTTPException, Request, Response
from typing import Dict, Any

from ..database import teachers_collection, verify_password

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

SESSION_COOKIE_NAME = "teacher_session"
active_sessions: Dict[str, str] = {}


def _serialize_teacher(teacher: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "username": teacher["username"],
        "display_name": teacher["display_name"],
        "role": teacher["role"]
    }


def require_teacher_session(request: Request) -> Dict[str, Any]:
    """Return the signed-in teacher for the current session."""
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_token:
        raise HTTPException(
            status_code=401, detail="Authentication required for this action")

    teacher_username = active_sessions.get(session_token)
    if not teacher_username:
        raise HTTPException(
            status_code=401, detail="Invalid teacher credentials")

    teacher = teachers_collection.find_one({"_id": teacher_username})
    if not teacher or teacher.get("role") not in {"teacher", "admin"}:
        active_sessions.pop(session_token, None)
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
    active_sessions[session_token] = teacher["username"]
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        httponly=True,
        samesite="lax"
    )

    # Return teacher information (excluding password)
    return _serialize_teacher(teacher)


@router.post("/logout")
def logout(request: Request, response: Response) -> Dict[str, str]:
    """Logout the current teacher session"""
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if session_token:
        active_sessions.pop(session_token, None)

    response.delete_cookie(key=SESSION_COOKIE_NAME)
    return {"message": "Logged out"}


@router.get("/check-session")
def check_session(request: Request) -> Dict[str, Any]:
    """Check if the current teacher session is valid"""
    return _serialize_teacher(require_teacher_session(request))
