"""
Database Schemas for Project Management Tool

Each Pydantic model below maps to a MongoDB collection. The collection name is the
lowercased class name (e.g., User -> "user").
"""
from typing import List, Optional
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime

# Auth/User
class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email address")
    password_hash: str = Field(..., description="BCrypt hash of the password")
    avatar_url: Optional[str] = Field(None, description="Profile image URL")
    is_active: bool = Field(True)

# Projects
class Project(BaseModel):
    name: str = Field(..., description="Project name")
    description: Optional[str] = Field(None)
    owner_id: str = Field(..., description="User _id of the owner as string")
    members: List[str] = Field(default_factory=list, description="List of user _id strings")
    labels: List[str] = Field(default_factory=list)

# Tasks
class Task(BaseModel):
    project_id: str = Field(..., description="Related project _id as string")
    title: str = Field(...)
    description: Optional[str] = Field(None)
    status: str = Field("todo", description="todo | in_progress | done")
    assignees: List[str] = Field(default_factory=list, description="User _id strings")
    due_date: Optional[datetime] = None
    labels: List[str] = Field(default_factory=list)
    position: float = Field(0, description="Ordering value for board columns")

# Comments
class Comment(BaseModel):
    task_id: str = Field(..., description="Related task _id as string")
    author_id: str = Field(..., description="User _id as string")
    content: str = Field(...)

# Lightweight request models (no password_hash exposure)
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None

class TaskCreate(BaseModel):
    project_id: str
    title: str
    description: Optional[str] = None
    assignee_emails: List[EmailStr] = Field(default_factory=list)

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    assignees: Optional[List[str]] = None
    labels: Optional[List[str]] = None
    position: Optional[float] = None

class CommentCreate(BaseModel):
    task_id: str
    content: str
