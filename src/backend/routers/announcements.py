"""
Announcement endpoints for the High School Management System API
"""

import uuid
from datetime import date

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

from ..database import announcements_collection, teachers_collection

router = APIRouter(
    prefix="/announcements",
    tags=["announcements"]
)


class AnnouncementInput(BaseModel):
    message: str = Field(..., min_length=1, max_length=500)
    start_date: Optional[str] = None
    expiration_date: str


def _require_teacher(teacher_username: Optional[str]) -> None:
    """Raise if the given username does not belong to a signed-in teacher."""
    if not teacher_username:
        raise HTTPException(
            status_code=401, detail="Authentication required for this action")

    if not teachers_collection.find_one({"_id": teacher_username}):
        raise HTTPException(
            status_code=401, detail="Invalid teacher credentials")


def _validate_dates(start_date: Optional[str], expiration_date: str) -> None:
    """Validate the date fields and ensure expiration is after start."""
    try:
        parsed_expiration = date.fromisoformat(expiration_date)
    except ValueError:
        raise HTTPException(
            status_code=400, detail="Expiration date must be in YYYY-MM-DD format")

    if start_date:
        try:
            parsed_start = date.fromisoformat(start_date)
        except ValueError:
            raise HTTPException(
                status_code=400, detail="Start date must be in YYYY-MM-DD format")

        if parsed_start > parsed_expiration:
            raise HTTPException(
                status_code=400, detail="Start date must be before the expiration date")


def _serialize(announcement: Dict[str, Any]) -> Dict[str, Any]:
    announcement = dict(announcement)
    announcement["id"] = announcement.pop("_id")
    return announcement


@router.get("/active", response_model=List[Dict[str, Any]])
def get_active_announcements() -> List[Dict[str, Any]]:
    """Get all announcements that are currently active (public endpoint)"""
    today = date.today().isoformat()

    query = {
        "expiration_date": {"$gte": today},
        "$or": [{"start_date": None}, {"start_date": {"$lte": today}}]
    }

    return [_serialize(a) for a in announcements_collection.find(query)]


@router.get("", response_model=List[Dict[str, Any]])
@router.get("/", response_model=List[Dict[str, Any]])
def get_all_announcements(teacher_username: Optional[str] = Query(None)) -> List[Dict[str, Any]]:
    """Get all announcements regardless of status - requires teacher authentication"""
    _require_teacher(teacher_username)

    announcements = announcements_collection.find().sort("expiration_date", 1)
    return [_serialize(a) for a in announcements]


@router.post("", response_model=Dict[str, Any])
@router.post("/", response_model=Dict[str, Any])
def create_announcement(
    announcement: AnnouncementInput,
    teacher_username: Optional[str] = Query(None)
) -> Dict[str, Any]:
    """Create a new announcement - requires teacher authentication"""
    _require_teacher(teacher_username)
    _validate_dates(announcement.start_date, announcement.expiration_date)

    new_announcement = {
        "_id": str(uuid.uuid4()),
        "message": announcement.message,
        "start_date": announcement.start_date,
        "expiration_date": announcement.expiration_date,
        "created_by": teacher_username
    }
    announcements_collection.insert_one(new_announcement)

    return _serialize(new_announcement)


@router.put("/{announcement_id}", response_model=Dict[str, Any])
def update_announcement(
    announcement_id: str,
    announcement: AnnouncementInput,
    teacher_username: Optional[str] = Query(None)
) -> Dict[str, Any]:
    """Update an existing announcement - requires teacher authentication"""
    _require_teacher(teacher_username)
    _validate_dates(announcement.start_date, announcement.expiration_date)

    existing = announcements_collection.find_one({"_id": announcement_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Announcement not found")

    updated_fields = {
        "message": announcement.message,
        "start_date": announcement.start_date,
        "expiration_date": announcement.expiration_date
    }
    announcements_collection.update_one(
        {"_id": announcement_id}, {"$set": updated_fields})

    return _serialize({**existing, **updated_fields})


@router.delete("/{announcement_id}")
def delete_announcement(
    announcement_id: str,
    teacher_username: Optional[str] = Query(None)
) -> Dict[str, str]:
    """Delete an announcement - requires teacher authentication"""
    _require_teacher(teacher_username)

    result = announcements_collection.delete_one({"_id": announcement_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Announcement not found")

    return {"message": "Announcement deleted"}
