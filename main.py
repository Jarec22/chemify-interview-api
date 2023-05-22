from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Table, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from passlib.context import CryptContext
import datetime
import uvicorn
import jwt

app = FastAPI()

SQLALCHEMY_DATABASE_URL = "sqlite:///./tasks.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    description = Column(String(255), nullable=False)
    status = Column(String(10), nullable=False)

    def json_repr(self):
        return {
            "user_id": self.user_id,
            "description": self.description,
            "status": self.status,
            "task_id": self.id,
        }


class User(Base):
    __table__ = Table(
        "users",
        Base.metadata,
        Column("id", Integer, primary_key=True, index=True),
        Column("username", String(50), unique=True, nullable=False),
        Column("email", String(50), unique=True, nullable=False),
        Column("password_hash", String(100), nullable=False),
    )


class DeletedTask(Base):
    __tablename__ = "deleted_tasks"

    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(Integer, ForeignKey("tasks.id"), nullable=False)
    user_id = Column(Integer, nullable=False)
    description = Column(String(255), nullable=False)
    status = Column(String(10), nullable=False)

    task = relationship("Task")


class TaskCreate(BaseModel):
    user_id: int
    description: str
    status: str = "Pending"


class TaskUpdate(BaseModel):
    user_id: int
    description: str
    status: str


class UserCreate(BaseModel):
    username: str
    email: str
    password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
JWT_SECRET_KEY = "pingpong"
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_TIME = 3600

Base.metadata.create_all(bind=engine)


def decode_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.DecodeError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user_id(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("user_id")
        return user_id
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.post("/users/", status_code=201)
def create_user(user: UserCreate, db=Depends(get_db)):
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username, email=user.email, password_hash=hashed_password
    )
    db.add(db_user)
    db.commit()
    return {"message": "User created successfully"}


@app.post("/token/")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)):
    db_user = db.query(User).filter_by(username=form_data.username).first()
    if not db_user or not verify_password(form_data.password, db_user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid username or password")

    # Generate access token
    access_token_expires = datetime.timedelta(seconds=JWT_EXPIRATION_TIME)
    access_token_payload = {
        "user_id": db_user.id,
        "exp": datetime.datetime.utcnow() + access_token_expires,
    }
    access_token = jwt.encode(
        access_token_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM
    )

    response = {
        "message": "Login successful",
        "token": access_token,
        "user_id": db_user.id,
    }

    return response


@app.post("/tasks/", status_code=201)
def create_task(task: TaskCreate, db=Depends(get_db)):
    new_task = Task(**task.dict())
    db.add(new_task)
    db.commit()
    db.refresh(new_task)
    return {"message": "Task created successfully", "task": new_task.json_repr()}


@app.get("/tasks/{task_id}")
def get_task(
    task_id: int,
    db=Depends(get_db),
    current_user_id: int = Depends(get_current_user_id),
):
    task = db.query(Task).get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.user_id != current_user_id:
        raise HTTPException(
            status_code=403, detail="Not authorized to access this task"
        )
    return task


@app.put("/tasks/{task_id}")
def update_task(
    task_id: int,
    task: TaskUpdate,
    db=Depends(get_db),
    current_user_id: int = Depends(get_current_user_id),
):
    existing_task = db.query(Task).get(task_id)
    if not existing_task:
        raise HTTPException(status_code=404, detail="Task not found")
    if existing_task.user_id != current_user_id:
        raise HTTPException(
            status_code=403, detail="Not authorized to access this task"
        )
    if task.status.lower() not in ["pending", "doing", "blocked", "done"]:
        raise HTTPException(status_code=400, detail="Invalid status value")

    existing_task.user_id = task.user_id
    existing_task.description = task.description
    existing_task.status = task.status

    db.commit()
    return {"message": "Task updated successfully", "task": task}


@app.delete("/tasks/{task_id}")
def delete_task(
    task_id: int,
    db=Depends(get_db),
    current_user_id: int = Depends(get_current_user_id),
):
    task = db.query(Task).get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.user_id != current_user_id:
        raise HTTPException(
            status_code=403, detail="Not authorized to delete this task"
        )

    deleted_task = DeletedTask(
        task_id=task.id,
        user_id=task.user_id,
        description=task.description,
        status=task.status,
    )
    db.add(deleted_task)

    db.delete(task)
    db.commit()

    return {"message": "Task deleted successfully"}


@app.get("/tasks/user/", status_code=200)
def get_tasks(token: str = Depends(oauth2_scheme), db=Depends(get_db)):
    payload = decode_token(token)
    user_id = payload.get("user_id")

    tasks = db.query(Task).filter_by(user_id=user_id).all()
    return {"tasks": tasks}


@app.get("/deleted/user/", status_code=200)
def get_tasks(token: str = Depends(oauth2_scheme), db=Depends(get_db)):
    payload = decode_token(token)
    user_id = payload.get("user_id")

    tasks = db.query(DeletedTask).filter_by(user_id=user_id).all()
    return {"tasks": tasks}


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, workers=4)
