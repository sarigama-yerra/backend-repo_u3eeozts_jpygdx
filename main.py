import os
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import (
    User, Project, Task, Comment,
    RegisterRequest, LoginRequest,
    ProjectCreate, TaskCreate, TaskUpdate, CommentCreate,
)

# Auth setup
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
auth_scheme = HTTPBearer()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helpers
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


def create_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": int(datetime.now(timezone.utc).timestamp()) + 60 * 60 * 24 * 7,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)) -> dict:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db["user"].find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Utility conversions

def to_str_id(doc: dict) -> dict:
    doc = dict(doc)
    doc["_id"] = str(doc["_id"]) if "_id" in doc else None
    # Remove sensitive fields
    if "password_hash" in doc:
        doc.pop("password_hash")
    return doc


@app.get("/")
def read_root():
    return {"message": "Project Management API"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:80]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


# Auth routes
@app.post("/auth/register", response_model=TokenResponse)
def register(data: RegisterRequest):
    existing = db["user"].find_one({"email": data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    password_hash = pwd_context.hash(data.password)
    user = User(name=data.name, email=data.email, password_hash=password_hash)
    user_id = create_document("user", user)
    token = create_token(user_id)
    return TokenResponse(access_token=token)


@app.post("/auth/login", response_model=TokenResponse)
def login(data: LoginRequest):
    user = db["user"].find_one({"email": data.email})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if not pwd_context.verify(data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = create_token(str(user["_id"]))
    return TokenResponse(access_token=token)


# Current user info
@app.get("/me")
def me(current=Depends(get_current_user)):
    return to_str_id(current)


# Project routes
@app.post("/projects")
def create_project(payload: ProjectCreate, current=Depends(get_current_user)):
    project = Project(
        name=payload.name,
        description=payload.description,
        owner_id=str(current["_id"]),
        members=[str(current["_id"])],
    )
    project_id = create_document("project", project)
    proj = db["project"].find_one({"_id": ObjectId(project_id)})
    return to_str_id(proj)


@app.get("/projects")
def list_projects(current=Depends(get_current_user)):
    user_id = str(current["_id"])
    projects = list(db["project"].find({"members": user_id}))
    return [to_str_id(p) for p in projects]


@app.post("/projects/{project_id}/invite")
def invite_member(project_id: str, email: EmailStr, current=Depends(get_current_user)):
    project = db["project"].find_one({"_id": ObjectId(project_id)})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if str(current["_id"]) != project.get("owner_id"):
        raise HTTPException(status_code=403, detail="Only owner can invite")
    user = db["user"].find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user_id = str(user["_id"])
    if user_id not in project.get("members", []):
        db["project"].update_one({"_id": ObjectId(project_id)}, {"$addToSet": {"members": user_id}})
    project = db["project"].find_one({"_id": ObjectId(project_id)})
    return to_str_id(project)


# Task routes
@app.post("/tasks")
def create_task(payload: TaskCreate, current=Depends(get_current_user)):
    project = db["project"].find_one({"_id": ObjectId(payload.project_id)})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if str(current["_id"]) not in project.get("members", []):
        raise HTTPException(status_code=403, detail="Not a project member")
    assignee_ids: List[str] = []
    for email in payload.assignee_emails:
        user = db["user"].find_one({"email": str(email)})
        if user:
            assignee_ids.append(str(user["_id"]))
    # position: set to now timestamp for ordering in column
    position = datetime.now(timezone.utc).timestamp()
    task = Task(
        project_id=payload.project_id,
        title=payload.title,
        description=payload.description,
        assignees=assignee_ids,
        position=position,
    )
    task_id = create_document("task", task)
    task_doc = db["task"].find_one({"_id": ObjectId(task_id)})
    broadcast_task_update(task_doc)
    return to_str_id(task_doc)


@app.get("/projects/{project_id}/tasks")
def list_tasks(project_id: str, current=Depends(get_current_user)):
    project = db["project"].find_one({"_id": ObjectId(project_id)})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if str(current["_id"]) not in project.get("members", []):
        raise HTTPException(status_code=403, detail="Not a project member")
    tasks = list(db["task"].find({"project_id": project_id}))
    return [to_str_id(t) for t in tasks]


@app.patch("/tasks/{task_id}")
def update_task(task_id: str, payload: TaskUpdate, current=Depends(get_current_user)):
    task = db["task"].find_one({"_id": ObjectId(task_id)})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    project = db["project"].find_one({"_id": ObjectId(task["project_id"])})
    if not project or str(current["_id"]) not in project.get("members", []):
        raise HTTPException(status_code=403, detail="Not authorized")
    update_data = {k: v for k, v in payload.model_dump(exclude_none=True).items()}
    update_data["updated_at"] = datetime.now(timezone.utc)
    db["task"].update_one({"_id": ObjectId(task_id)}, {"$set": update_data})
    task = db["task"].find_one({"_id": ObjectId(task_id)})
    broadcast_task_update(task)
    return to_str_id(task)


# Comments
@app.post("/tasks/{task_id}/comments")
def add_comment(task_id: str, payload: CommentCreate, current=Depends(get_current_user)):
    task = db["task"].find_one({"_id": ObjectId(task_id)})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    project = db["project"].find_one({"_id": ObjectId(task["project_id"])})
    if not project or str(current["_id"]) not in project.get("members", []):
        raise HTTPException(status_code=403, detail="Not authorized")
    comment = Comment(task_id=task_id, author_id=str(current["_id"]), content=payload.content)
    comment_id = create_document("comment", comment)
    c = db["comment"].find_one({"_id": ObjectId(comment_id)})
    broadcast_comment_update(c)
    return to_str_id(c)


@app.get("/tasks/{task_id}/comments")
def list_comments(task_id: str, current=Depends(get_current_user)):
    task = db["task"].find_one({"_id": ObjectId(task_id)})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    project = db["project"].find_one({"_id": ObjectId(task["project_id"])})
    if not project or str(current["_id"]) not in project.get("members", []):
        raise HTTPException(status_code=403, detail="Not authorized")
    comments = list(db["comment"].find({"task_id": task_id}).sort("created_at"))
    return [to_str_id(c) for c in comments]


# Simple notifications: store basic notification docs
class Notification(BaseModel):
    user_id: str
    type: str
    message: str
    read: bool = False


def create_notification(user_id: str, type_: str, message: str):
    n = Notification(user_id=user_id, type=type_, message=message)
    create_document("notification", n)


# Broadcast center for WebSockets per project
class ConnectionManager:
    def __init__(self):
        self.project_connections: dict[str, list[WebSocket]] = {}

    async def connect(self, project_id: str, websocket: WebSocket):
        await websocket.accept()
        self.project_connections.setdefault(project_id, []).append(websocket)

    def disconnect(self, project_id: str, websocket: WebSocket):
        conns = self.project_connections.get(project_id, [])
        if websocket in conns:
            conns.remove(websocket)

    async def broadcast(self, project_id: str, message: dict):
        for ws in list(self.project_connections.get(project_id, [])):
            try:
                await ws.send_json(message)
            except Exception:
                self.disconnect(project_id, ws)


manager = ConnectionManager()


def broadcast_task_update(task_doc: dict):
    try:
        import anyio

        async def _send():
            await manager.broadcast(task_doc["project_id"], {"type": "task:update", "data": to_str_id(task_doc)})
        anyio.run(_send)
    except Exception:
        pass


def broadcast_comment_update(comment_doc: dict):
    try:
        import anyio

        # find task to get project
        task = db["task"].find_one({"_id": ObjectId(comment_doc["task_id"])}) if ObjectId.is_valid(comment_doc["task_id"]) else None
        project_id = task["project_id"] if task else None

        async def _send():
            await manager.broadcast(project_id, {"type": "comment:new", "data": to_str_id(comment_doc)})
        anyio.run(_send)
    except Exception:
        pass


@app.websocket("/ws/projects/{project_id}")
async def project_ws(websocket: WebSocket, project_id: str):
    await manager.connect(project_id, websocket)
    try:
        while True:
            # Echo pings or simple keep-alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(project_id, websocket)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
