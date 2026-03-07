import os
import re
import shutil
import asyncio
import logging
import bcrypt
import hashlib
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict
from fastapi import FastAPI, File, UploadFile, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text, Boolean, desc, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from uuid import uuid4

# Configuração de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# === Configurações ===
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"  # Troque em produção!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/login")

# === Banco de Dados SQLite ===
SQLALCHEMY_DATABASE_URL = "sqlite:///./got_app.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# === Modelos ===
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    bio = Column(Text, default="")
    avatar_url = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender")
    received_messages = relationship("Message", foreign_keys="Message.recipient_id", back_populates="recipient")
    posts = relationship("Post", back_populates="user", cascade="all, delete-orphan")
    reels = relationship("Reel", back_populates="user", cascade="all, delete-orphan")
    followers = relationship("Follow", foreign_keys="Follow.followed_id", back_populates="followed", cascade="all, delete-orphan")
    following = relationship("Follow", foreign_keys="Follow.follower_id", back_populates="follower", cascade="all, delete-orphan")

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    recipient_id = Column(Integer, ForeignKey("users.id"))
    content = Column(Text, nullable=True)
    message_type = Column(String, default='text')
    file_url = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    is_read = Column(Boolean, default=False)

    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    recipient = relationship("User", foreign_keys=[recipient_id], back_populates="received_messages")

class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    image_url = Column(String, nullable=True)          # nullable para posts de texto
    text_content = Column(Text, nullable=True)         # conteúdo de texto
    caption = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="posts")

class Reel(Base):
    __tablename__ = "reels"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    youtube_id = Column(String, nullable=False)
    caption = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="reels")

class Follow(Base):
    __tablename__ = "follows"
    id = Column(Integer, primary_key=True, index=True)
    follower_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    followed_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    follower = relationship("User", foreign_keys=[follower_id], back_populates="following")
    followed = relationship("User", foreign_keys=[followed_id], back_populates="followers")

    __table_args__ = (UniqueConstraint('follower_id', 'followed_id', name='unique_follow'),)

# Cria as tabelas
Base.metadata.create_all(bind=engine)

# === Funções de hash ===
def get_password_hash(password: str) -> str:
    password_sha256 = hashlib.sha256(password.encode()).digest()
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_sha256, salt)
    return hashed.decode()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    password_sha256 = hashlib.sha256(plain_password.encode()).digest()
    return bcrypt.checkpw(password_sha256, hashed_password.encode())

# === Extração de YouTube ID ===
def extract_youtube_id(url: str) -> Optional[str]:
    patterns = [
        r'youtube\.com/watch\?v=([a-zA-Z0-9_-]{11})',
        r'youtu\.be/([a-zA-Z0-9_-]{11})',
        r'youtube\.com/shorts/([a-zA-Z0-9_-]{11})',
        r'youtube\.com/embed/([a-zA-Z0-9_-]{11})',
    ]
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    return None

# === Schemas ===
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    name: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    name: str
    bio: str = ""
    avatar_url: str = ""
    followers_count: int = 0
    following_count: int = 0
    posts_count: int = 0

class UserProfileUpdate(BaseModel):
    name: Optional[str] = None
    bio: Optional[str] = None

class MessageSend(BaseModel):
    recipient_id: int
    content: Optional[str] = None
    message_type: str = 'text'
    file_url: Optional[str] = None

class MessageOut(BaseModel):
    id: int
    sender_id: int
    recipient_id: int
    content: Optional[str]
    message_type: str
    file_url: Optional[str]
    timestamp: datetime
    is_read: bool

class ConversationOut(BaseModel):
    user_id: int
    name: str
    avatar_url: str = ""
    last_message: Optional[str] = None
    last_message_time: Optional[datetime] = None
    unread_count: int = 0
    i_follow_them: bool = False
    they_follow_me: bool = False
    is_mutual: bool = False
    remaining_messages: Optional[int] = None

class Token(BaseModel):
    access_token: str
    token_type: str

class PostCreate(BaseModel):
    caption: Optional[str] = None

class TextPostCreate(BaseModel):
    text: str
    caption: Optional[str] = None

class PostOut(BaseModel):
    id: int
    user_id: int
    image_url: Optional[str]
    text_content: Optional[str]
    caption: Optional[str]
    created_at: datetime
    post_type: str = "image"   # "image" ou "text"
    user_name: Optional[str] = None
    user_avatar: Optional[str] = None

class ReelCreate(BaseModel):
    youtube_url: str
    caption: Optional[str] = None

class ReelOut(BaseModel):
    id: int
    user_id: int
    youtube_id: str
    caption: Optional[str]
    created_at: datetime
    user_name: Optional[str] = None
    user_avatar: Optional[str] = None

class FollowOut(BaseModel):
    follower_id: int
    followed_id: int
    created_at: datetime

# === Dependências ===
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def authenticate_user(db: Session, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user

# === WebSocket Connection Manager ===
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[int, Dict] = {}
        self.call_sessions: Dict[int, int] = {}

    async def connect(self, websocket: WebSocket, user_id: int, user_name: str):
        await websocket.accept()
        self.active_connections[user_id] = {"ws": websocket, "name": user_name}
        logger.info(f"Usuário {user_id} ({user_name}) conectado via WebSocket")

    def disconnect(self, user_id: int):
        if user_id in self.active_connections:
            del self.active_connections[user_id]
            if user_id in self.call_sessions:
                other = self.call_sessions.pop(user_id)
                if other in self.call_sessions:
                    del self.call_sessions[other]
                if other in self.active_connections:
                    asyncio.create_task(self.send_personal_message({"type": "call_end", "from": user_id}, other))
            logger.info(f"Usuário {user_id} desconectado")

    async def send_personal_message(self, message: dict, user_id: int):
        if user_id in self.active_connections:
            try:
                await self.active_connections[user_id]["ws"].send_json(message)
                logger.info(f"Mensagem enviada para usuário {user_id}")
            except Exception as e:
                logger.error(f"Erro ao enviar mensagem para {user_id}: {e}")

    async def broadcast_to_followers(self, user_id: int, message: dict, db: Session):
        followers = db.query(Follow).filter(Follow.followed_id == user_id).all()
        for follow in followers:
            follower_id = follow.follower_id
            if follower_id in self.active_connections:
                await self.send_personal_message(message, follower_id)

    def get_user_name(self, user_id: int) -> Optional[str]:
        if user_id in self.active_connections:
            return self.active_connections[user_id]["name"]
        return None

manager = ConnectionManager()

# === App FastAPI ===
app = FastAPI(title="Got App API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pastas
os.makedirs("uploads", exist_ok=True)
os.makedirs("uploads/audio", exist_ok=True)
os.makedirs("uploads/posts", exist_ok=True)
os.makedirs("static", exist_ok=True)

app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")
app.mount("/static", StaticFiles(directory="static"), name="static")

# === WebSocket ===
@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int, token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        token_user_id = payload.get("sub")
        if token_user_id is None or int(token_user_id) != user_id:
            logger.warning(f"Token user {token_user_id} não corresponde ao user_id {user_id}")
            await websocket.close(code=1008)
            return
    except (JWTError, ValueError) as e:
        logger.error(f"Erro na validação do token: {e}")
        await websocket.close(code=1008)
        return

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        await websocket.close(code=1008)
        return

    await manager.connect(websocket, user_id, user.name)
    try:
        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type")
            target = data.get("target")

            if msg_type == "call_offer":
                if target not in manager.active_connections:
                    await manager.send_personal_message({"type": "call_offline"}, user_id)
                    continue
                if target in manager.call_sessions:
                    await manager.send_personal_message({"type": "call_busy"}, user_id)
                    continue
                manager.call_sessions[user_id] = target
                manager.call_sessions[target] = user_id
                await manager.send_personal_message({
                    "type": "call_offer",
                    "from": user_id,
                    "fromName": user.name,
                    "offer": data["offer"],
                    "hasVideo": data.get("hasVideo", False),
                    "hasAudio": data.get("hasAudio", True)
                }, target)

            elif msg_type == "call_answer":
                if target in manager.active_connections:
                    await manager.send_personal_message({
                        "type": "call_answer",
                        "from": user_id,
                        "answer": data["answer"]
                    }, target)

            elif msg_type == "ice_candidate":
                if target in manager.active_connections:
                    await manager.send_personal_message({
                        "type": "ice_candidate",
                        "from": user_id,
                        "candidate": data["candidate"]
                    }, target)

            elif msg_type == "call_end":
                if user_id in manager.call_sessions:
                    other = manager.call_sessions.pop(user_id)
                    if other in manager.call_sessions:
                        del manager.call_sessions[other]
                    if other in manager.active_connections:
                        await manager.send_personal_message({"type": "call_end", "from": user_id}, other)

            elif msg_type == "call_reject":
                if target in manager.active_connections:
                    await manager.send_personal_message({"type": "call_reject", "from": user_id}, target)
                if user_id in manager.call_sessions:
                    other = manager.call_sessions.pop(user_id)
                    if other in manager.call_sessions:
                        del manager.call_sessions[other]

            elif msg_type == "call_accept":
                if target in manager.active_connections:
                    await manager.send_personal_message({
                        "type": "call_accept",
                        "from": user_id,
                        "hasVideo": data.get("hasVideo", False)
                    }, target)

            else:
                logger.warning(f"Tipo de mensagem desconhecido: {msg_type}")

    except WebSocketDisconnect:
        manager.disconnect(user_id)
    except Exception as e:
        logger.error(f"Erro no WebSocket: {e}")
        manager.disconnect(user_id)

# === Endpoints HTTP ===

@app.post("/users/register", response_model=UserOut)
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if ' ' in user.username:
        raise HTTPException(status_code=400, detail="Username cannot contain spaces")
    hashed_password = get_password_hash(user.password)
    new_user = User(
        username=user.username,
        email=user.email,
        name=user.name,
        hashed_password=hashed_password
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return UserOut(
        id=new_user.id,
        username=new_user.username,
        email=new_user.email,
        name=new_user.name,
        bio=new_user.bio,
        avatar_url=new_user.avatar_url,
        followers_count=0,
        following_count=0,
        posts_count=0
    )

@app.post("/users/login", response_model=Token)
def login(user_data: UserLogin, db: Session = Depends(get_db)):
    user = authenticate_user(db, user_data.email, user_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserOut)
def read_users_me(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    followers_count = db.query(Follow).filter(Follow.followed_id == current_user.id).count()
    following_count = db.query(Follow).filter(Follow.follower_id == current_user.id).count()
    posts_count = db.query(Post).filter(Post.user_id == current_user.id).count()
    return UserOut(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        name=current_user.name,
        bio=current_user.bio,
        avatar_url=current_user.avatar_url,
        followers_count=followers_count,
        following_count=following_count,
        posts_count=posts_count
    )

@app.put("/users/me", response_model=UserOut)
def update_profile(profile: UserProfileUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if profile.name is not None:
        current_user.name = profile.name
    if profile.bio is not None:
        current_user.bio = profile.bio
    db.commit()
    db.refresh(current_user)
    followers_count = db.query(Follow).filter(Follow.followed_id == current_user.id).count()
    following_count = db.query(Follow).filter(Follow.follower_id == current_user.id).count()
    posts_count = db.query(Post).filter(Post.user_id == current_user.id).count()
    return UserOut(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        name=current_user.name,
        bio=current_user.bio,
        avatar_url=current_user.avatar_url,
        followers_count=followers_count,
        following_count=following_count,
        posts_count=posts_count
    )

@app.post("/users/me/avatar", response_model=UserOut)
async def upload_avatar(file: UploadFile = File(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    ext = os.path.splitext(file.filename)[1]
    filename = f"avatar_{current_user.id}_{uuid4().hex}{ext}"
    file_path = os.path.join("uploads", filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    avatar_url = f"/uploads/{filename}"
    current_user.avatar_url = avatar_url
    db.commit()
    db.refresh(current_user)
    followers_count = db.query(Follow).filter(Follow.followed_id == current_user.id).count()
    following_count = db.query(Follow).filter(Follow.follower_id == current_user.id).count()
    posts_count = db.query(Post).filter(Post.user_id == current_user.id).count()
    return UserOut(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        name=current_user.name,
        bio=current_user.bio,
        avatar_url=current_user.avatar_url,
        followers_count=followers_count,
        following_count=following_count,
        posts_count=posts_count
    )

@app.get("/users/search", response_model=List[UserOut])
def search_users(q: str = "", current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = db.query(User).filter(User.id != current_user.id)
    if q:
        query = query.filter(
            (User.username.ilike(f"%{q}%")) | (User.name.ilike(f"%{q}%"))
        )
    users = query.limit(20).all()
    result = []
    for u in users:
        followers_count = db.query(Follow).filter(Follow.followed_id == u.id).count()
        following_count = db.query(Follow).filter(Follow.follower_id == u.id).count()
        posts_count = db.query(Post).filter(Post.user_id == u.id).count()
        result.append(UserOut(
            id=u.id,
            username=u.username,
            email=u.email,
            name=u.name,
            bio=u.bio,
            avatar_url=u.avatar_url,
            followers_count=followers_count,
            following_count=following_count,
            posts_count=posts_count
        ))
    return result

@app.get("/users/{user_id}", response_model=UserOut)
def get_user(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    followers_count = db.query(Follow).filter(Follow.followed_id == user_id).count()
    following_count = db.query(Follow).filter(Follow.follower_id == user_id).count()
    posts_count = db.query(Post).filter(Post.user_id == user_id).count()
    return UserOut(
        id=user.id,
        username=user.username,
        email=user.email,
        name=user.name,
        bio=user.bio,
        avatar_url=user.avatar_url,
        followers_count=followers_count,
        following_count=following_count,
        posts_count=posts_count
    )

# === Endpoints de relacionamento ===

@app.get("/users/{user_id}/followers", response_model=List[UserOut])
def get_followers(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    followers = db.query(Follow).filter(Follow.followed_id == user_id).all()
    result = []
    for follow in followers:
        u = follow.follower
        followers_count = db.query(Follow).filter(Follow.followed_id == u.id).count()
        following_count = db.query(Follow).filter(Follow.follower_id == u.id).count()
        posts_count = db.query(Post).filter(Post.user_id == u.id).count()
        result.append(UserOut(
            id=u.id,
            username=u.username,
            email=u.email,
            name=u.name,
            bio=u.bio,
            avatar_url=u.avatar_url,
            followers_count=followers_count,
            following_count=following_count,
            posts_count=posts_count
        ))
    return result

@app.get("/users/{user_id}/following", response_model=List[UserOut])
def get_following(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    following = db.query(Follow).filter(Follow.follower_id == user_id).all()
    result = []
    for follow in following:
        u = follow.followed
        followers_count = db.query(Follow).filter(Follow.followed_id == u.id).count()
        following_count = db.query(Follow).filter(Follow.follower_id == u.id).count()
        posts_count = db.query(Post).filter(Post.user_id == u.id).count()
        result.append(UserOut(
            id=u.id,
            username=u.username,
            email=u.email,
            name=u.name,
            bio=u.bio,
            avatar_url=u.avatar_url,
            followers_count=followers_count,
            following_count=following_count,
            posts_count=posts_count
        ))
    return result

@app.post("/follow/{user_id}")
async def follow_user(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot follow yourself")
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    existing = db.query(Follow).filter(
        Follow.follower_id == current_user.id,
        Follow.followed_id == user_id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Already following")
    follow = Follow(follower_id=current_user.id, followed_id=user_id)
    db.add(follow)
    db.commit()

    await manager.send_personal_message({
        "type": "followed",
        "follower_id": current_user.id,
        "follower_name": current_user.name
    }, user_id)

    await manager.send_personal_message({
        "type": "follow_update",
        "target_id": user_id,
        "follower_id": current_user.id,
        "action": "followed"
    }, current_user.id)

    return {"status": "followed"}

@app.delete("/follow/{user_id}")
async def unfollow_user(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    follow = db.query(Follow).filter(
        Follow.follower_id == current_user.id,
        Follow.followed_id == user_id
    ).first()
    if not follow:
        raise HTTPException(status_code=404, detail="Not following")
    db.delete(follow)
    db.commit()

    await manager.send_personal_message({
        "type": "unfollowed",
        "follower_id": current_user.id,
        "follower_name": current_user.name
    }, user_id)

    await manager.send_personal_message({
        "type": "follow_update",
        "target_id": user_id,
        "follower_id": current_user.id,
        "action": "unfollowed"
    }, current_user.id)

    return {"status": "unfollowed"}

@app.get("/follow/status/{user_id}")
def follow_status(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    following = db.query(Follow).filter(
        Follow.follower_id == current_user.id,
        Follow.followed_id == user_id
    ).first() is not None
    return {"following": following}

# === Endpoints de Conversas e Mensagens ===

@app.get("/conversations/", response_model=List[ConversationOut])
def get_conversations(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    other_users = db.query(User).filter(User.id != current_user.id).all()
    conversations = []
    for other in other_users:
        i_follow_them = db.query(Follow).filter(
            Follow.follower_id == current_user.id,
            Follow.followed_id == other.id
        ).first() is not None
        they_follow_me = db.query(Follow).filter(
            Follow.follower_id == other.id,
            Follow.followed_id == current_user.id
        ).first() is not None
        is_mutual = i_follow_them and they_follow_me

        remaining = None
        if not they_follow_me:
            msg_count = db.query(Message).filter(
                Message.sender_id == current_user.id,
                Message.recipient_id == other.id
            ).count()
            remaining = max(0, 3 - msg_count)

        last_msg = db.query(Message).filter(
            ((Message.sender_id == current_user.id) & (Message.recipient_id == other.id)) |
            ((Message.sender_id == other.id) & (Message.recipient_id == current_user.id))
        ).order_by(desc(Message.timestamp)).first()
        unread = db.query(Message).filter(
            Message.sender_id == other.id,
            Message.recipient_id == current_user.id,
            Message.is_read == False
        ).count()
        last_msg_display = None
        if last_msg:
            if last_msg.message_type == 'audio':
                last_msg_display = '🎤 Áudio'
            else:
                last_msg_display = last_msg.content

        if i_follow_them or they_follow_me:
            conversations.append({
                "user_id": other.id,
                "name": other.name,
                "avatar_url": other.avatar_url,
                "last_message": last_msg_display,
                "last_message_time": last_msg.timestamp if last_msg else None,
                "unread_count": unread,
                "i_follow_them": i_follow_them,
                "they_follow_me": they_follow_me,
                "is_mutual": is_mutual,
                "remaining_messages": remaining
            })
    return conversations

@app.get("/messages/{user_id}", response_model=List[MessageOut])
def get_messages(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    other = db.query(User).filter(User.id == user_id).first()
    if not other:
        raise HTTPException(status_code=404, detail="User not found")
    messages = db.query(Message).filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp).all()
    db.query(Message).filter(
        Message.sender_id == user_id,
        Message.recipient_id == current_user.id,
        Message.is_read == False
    ).update({"is_read": True})
    db.commit()
    return messages

@app.post("/messages/audio")
async def upload_audio(file: UploadFile = File(...), current_user: User = Depends(get_current_user)):
    ext = os.path.splitext(file.filename)[1]
    if not ext:
        ext = '.webm'
    filename = f"audio_{current_user.id}_{uuid4().hex}{ext}"
    file_path = os.path.join("uploads", "audio", filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    file_url = f"/uploads/audio/{filename}"
    return {"file_url": file_url}

@app.post("/messages/", response_model=MessageOut)
async def send_message(message: MessageSend, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    recipient = db.query(User).filter(User.id == message.recipient_id).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    recipient_follows_sender = db.query(Follow).filter(
        Follow.follower_id == recipient.id,
        Follow.followed_id == current_user.id
    ).first() is not None

    if not recipient_follows_sender:
        msg_count = db.query(Message).filter(
            Message.sender_id == current_user.id,
            Message.recipient_id == recipient.id
        ).count()
        if msg_count >= 3:
            raise HTTPException(status_code=403, detail="Você só pode enviar 3 mensagens para este usuário até ele te seguir.")

    new_msg = Message(
        sender_id=current_user.id,
        recipient_id=message.recipient_id,
        content=message.content,
        message_type=message.message_type,
        file_url=message.file_url
    )
    db.add(new_msg)
    db.commit()
    db.refresh(new_msg)

    msg_data = {
        "id": new_msg.id,
        "sender_id": new_msg.sender_id,
        "recipient_id": new_msg.recipient_id,
        "content": new_msg.content,
        "message_type": new_msg.message_type,
        "file_url": new_msg.file_url,
        "timestamp": new_msg.timestamp.isoformat(),
        "is_read": new_msg.is_read
    }

    if not recipient_follows_sender:
        msg_data["from_non_follower"] = True

    await manager.send_personal_message(msg_data, message.recipient_id)

    return new_msg

# === Endpoints de Posts ===

@app.post("/posts", response_model=PostOut)
async def create_post(
    caption: str = "",
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ext = os.path.splitext(file.filename)[1]
    filename = f"post_{current_user.id}_{uuid4().hex}{ext}"
    file_path = os.path.join("uploads", "posts", filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    image_url = f"/uploads/posts/{filename}"

    post = Post(user_id=current_user.id, image_url=image_url, caption=caption, post_type="image")
    db.add(post)
    db.commit()
    db.refresh(post)
    return PostOut(
        id=post.id,
        user_id=post.user_id,
        image_url=post.image_url,
        text_content=post.text_content,
        caption=post.caption,
        created_at=post.created_at,
        post_type="image",
        user_name=current_user.name,
        user_avatar=current_user.avatar_url
    )

@app.post("/posts/text", response_model=PostOut)
def create_text_post(
    body: TextPostCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not body.text or not body.text.strip():
        raise HTTPException(status_code=400, detail="O texto não pode estar vazio.")
    post = Post(
        user_id=current_user.id,
        text_content=body.text.strip(),
        caption=body.caption or "",
        image_url=None
    )
    db.add(post)
    db.commit()
    db.refresh(post)
    return PostOut(
        id=post.id,
        user_id=post.user_id,
        image_url=post.image_url,
        text_content=post.text_content,
        caption=post.caption,
        created_at=post.created_at,
        post_type="text",
        user_name=current_user.name,
        user_avatar=current_user.avatar_url
    )

@app.get("/users/{user_id}/posts", response_model=List[PostOut])
def get_user_posts(user_id: int, db: Session = Depends(get_db)):
    posts = db.query(Post).filter(Post.user_id == user_id).order_by(desc(Post.created_at)).all()
    result = []
    for p in posts:
        user = db.query(User).filter(User.id == p.user_id).first()
        result.append(PostOut(
            id=p.id,
            user_id=p.user_id,
            image_url=p.image_url,
            text_content=p.text_content,
            caption=p.caption,
            created_at=p.created_at,
            post_type="text" if p.text_content and not p.image_url else "image",
            user_name=user.name if user else "",
            user_avatar=user.avatar_url if user else ""
        ))
    return result

# === Feed com algoritmo de recomendação ===

@app.get("/feed", response_model=List[PostOut])
def get_feed(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # IDs dos usuários que o usuário atual segue
    following_ids = [
        f.followed_id for f in
        db.query(Follow).filter(Follow.follower_id == current_user.id).all()
    ]

    # Posts de seguidos (ordem cronológica decrescente)
    followed_posts = (
        db.query(Post)
        .filter(Post.user_id.in_(following_ids))
        .order_by(desc(Post.created_at))
        .limit(50)
        .all()
    ) if following_ids else []

    # Posts de não seguidos (excluindo o próprio usuário)
    excluded_ids = following_ids + [current_user.id]
    other_posts = (
        db.query(Post)
        .filter(~Post.user_id.in_(excluded_ids))
        .order_by(desc(Post.created_at))
        .limit(50)
        .all()
    )

    # Junta e limita a 50
    all_posts = (followed_posts + other_posts)[:50]

    result = []
    for p in all_posts:
        user = db.query(User).filter(User.id == p.user_id).first()
        result.append(PostOut(
            id=p.id,
            user_id=p.user_id,
            image_url=p.image_url,
            text_content=p.text_content,
            caption=p.caption,
            created_at=p.created_at,
            post_type="text" if p.text_content and not p.image_url else "image",
            user_name=user.name if user else "",
            user_avatar=user.avatar_url if user else ""
        ))
    return result

# === Endpoints de Reels ===

@app.post("/reels", response_model=ReelOut)
def create_reel(
    body: ReelCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    yt_id = extract_youtube_id(body.youtube_url)
    if not yt_id:
        raise HTTPException(status_code=400, detail="URL do YouTube inválida. Use youtube.com/watch?v=, youtu.be/ ou youtube.com/shorts/")

    reel = Reel(
        user_id=current_user.id,
        youtube_id=yt_id,
        caption=body.caption or ""
    )
    db.add(reel)
    db.commit()
    db.refresh(reel)
    return ReelOut(
        id=reel.id,
        user_id=reel.user_id,
        youtube_id=reel.youtube_id,
        caption=reel.caption,
        created_at=reel.created_at,
        user_name=current_user.name,
        user_avatar=current_user.avatar_url
    )

@app.get("/reels", response_model=List[ReelOut])
def get_reels(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # IDs dos usuários que o usuário atual segue
    following_ids = [
        f.followed_id for f in
        db.query(Follow).filter(Follow.follower_id == current_user.id).all()
    ]

    # Reels de seguidos (ordem cronológica decrescente)
    followed_reels = (
        db.query(Reel)
        .filter(Reel.user_id.in_(following_ids))
        .order_by(desc(Reel.created_at))
        .limit(50)
        .all()
    ) if following_ids else []

    # Reels de não seguidos (excluindo o próprio usuário)
    excluded_ids = following_ids + [current_user.id]
    other_reels = (
        db.query(Reel)
        .filter(~Reel.user_id.in_(excluded_ids))
        .order_by(desc(Reel.created_at))
        .limit(50)
        .all()
    )

    all_reels = (followed_reels + other_reels)[:50]

    result = []
    for r in all_reels:
        user = db.query(User).filter(User.id == r.user_id).first()
        result.append(ReelOut(
            id=r.id,
            user_id=r.user_id,
            youtube_id=r.youtube_id,
            caption=r.caption,
            created_at=r.created_at,
            user_name=user.name if user else "",
            user_avatar=user.avatar_url if user else ""
        ))
    return result

@app.get("/")
def root():
    return FileResponse("static/index.html")

