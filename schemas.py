"""
Database Schemas for Personal Finance Manager

Each Pydantic model represents a MongoDB collection. The collection name is the
lowercased class name (e.g., User -> "user", Transaction -> "transaction").
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal
from datetime import datetime


class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email address")
    hashed_password: str = Field(..., description="BCrypt hashed password")
    photo_url: Optional[str] = Field(None, description="Avatar URL")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class Transaction(BaseModel):
    user_id: str = Field(..., description="Owner user id (string ObjectId)")
    type: Literal["income", "expense"] = Field(..., description="Transaction type")
    amount: float = Field(..., gt=0, description="Positive amount")
    category: str = Field(..., description="Category name")
    date: datetime = Field(..., description="Transaction date")
    note: Optional[str] = Field(None, description="Optional note")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class Goal(BaseModel):
    user_id: str = Field(..., description="Owner user id (string ObjectId)")
    name: str = Field(..., description="Goal name, e.g., 'Trip to Japan'")
    target_amount: float = Field(..., gt=0, description="Target amount to reach")
    current_amount: float = Field(0, ge=0, description="Accumulated amount")
    deadline: Optional[datetime] = Field(None, description="Optional deadline")
    achieved: bool = Field(False, description="Whether goal is achieved")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class Notification(BaseModel):
    user_id: str
    message: str
    type: Literal["info", "warning", "success"] = "info"
    read: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
