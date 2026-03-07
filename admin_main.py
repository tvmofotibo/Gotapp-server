"""
admin_main.py — Servidor de administração STANDALONE do got app
Roda independente do main.py, na porta 8001.

Uso:
    uvicorn admin_main:app --host 0.0.0.0 --port 8001 --reload

Acesse em: http://localhost:8001/admin
Apenas o usuário @hydra consegue fazer login.

Compartilha o mesmo banco de dados (got_app.db) que o main.py,
mas é um processo FastAPI completamente separado.
"""

import os
import hashlib
import bcrypt
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles

from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime,
    ForeignKey, Text, Boolean, desc, UniqueConstraint
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship

# === Configurações (mesmas do main.py) =======================================
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM  = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 horas

ADMIN_USERNAME = "hydra"  # único usuário autorizado

# === Banco de dados (mesmo arquivo do main.py) ================================
SQLALCHEMY_DATABASE_URL = "sqlite:///./got_app.db"
engine       = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base         = declarative_base()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# === Modelos ORM (espelham as tabelas do main.py — NÃO recriam) ==============
class User(Base):
    __tablename__ = "users"
    id              = Column(Integer, primary_key=True, index=True)
    username        = Column(String, unique=True, index=True, nullable=False)
    email           = Column(String, unique=True, index=True, nullable=False)
    name            = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    bio             = Column(Text, default="")
    avatar_url      = Column(String, default="")
    created_at      = Column(DateTime, default=datetime.utcnow)
    posts             = relationship("Post",    back_populates="user", cascade="all, delete-orphan")
    reels             = relationship("Reel",    back_populates="user", cascade="all, delete-orphan")
    followers         = relationship("Follow",  foreign_keys="Follow.followed_id",  back_populates="followed",  cascade="all, delete-orphan")
    following         = relationship("Follow",  foreign_keys="Follow.follower_id",   back_populates="follower",  cascade="all, delete-orphan")
    sent_messages     = relationship("Message", foreign_keys="Message.sender_id",    back_populates="sender")
    received_messages = relationship("Message", foreign_keys="Message.recipient_id", back_populates="recipient")

class Message(Base):
    __tablename__ = "messages"
    id           = Column(Integer, primary_key=True, index=True)
    sender_id    = Column(Integer, ForeignKey("users.id"))
    recipient_id = Column(Integer, ForeignKey("users.id"))
    content      = Column(Text, nullable=True)
    message_type = Column(String, default="text")
    file_url     = Column(String, nullable=True)
    timestamp    = Column(DateTime, default=datetime.utcnow)
    is_read      = Column(Boolean, default=False)
    sender    = relationship("User", foreign_keys=[sender_id],    back_populates="sent_messages")
    recipient = relationship("User", foreign_keys=[recipient_id], back_populates="received_messages")

class Post(Base):
    __tablename__ = "posts"
    id           = Column(Integer, primary_key=True, index=True)
    user_id      = Column(Integer, ForeignKey("users.id"), nullable=False)
    image_url    = Column(String,  nullable=True)
    text_content = Column(Text,    nullable=True)
    caption      = Column(Text,    default="")
    created_at   = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="posts")

class Reel(Base):
    __tablename__ = "reels"
    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False)
    youtube_id = Column(String,  nullable=False)
    caption    = Column(Text,    default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="reels")

class Follow(Base):
    __tablename__ = "follows"
    id          = Column(Integer, primary_key=True, index=True)
    follower_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    followed_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at  = Column(DateTime, default=datetime.utcnow)
    follower = relationship("User", foreign_keys=[follower_id], back_populates="following")
    followed = relationship("User", foreign_keys=[followed_id], back_populates="followers")
    __table_args__ = (UniqueConstraint("follower_id", "followed_id", name="unique_follow"),)

# NÃO chama create_all — as tabelas já existem no banco criado pelo main.py

# === Auth =====================================================================
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/admin/api/login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain: str, hashed: str) -> bool:
    pw_sha = hashlib.sha256(plain.encode()).digest()
    return bcrypt.checkpw(pw_sha, hashed.encode())

def get_password_hash(plain: str) -> str:
    pw_sha = hashlib.sha256(plain.encode()).digest()
    return bcrypt.hashpw(pw_sha, bcrypt.gensalt()).decode()

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    to_encode["exp"] = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_admin(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        raw = payload.get("sub")
        if raw is None:
            raise exc
        # sub pode vir como int ou string dependendo de quem gerou o token
        user_id = int(raw)
    except (JWTError, ValueError, TypeError):
        raise exc
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise exc
    if user.username.lower() != ADMIN_USERNAME:
        raise HTTPException(status_code=403, detail="Acesso negado. Apenas @hydra.")
    return user

# === App =====================================================================
app = FastAPI(title="got app · Admin", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# === Schemas =================================================================
class LoginBody(BaseModel):
    email: str
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str

class AdminStats(BaseModel):
    total_users: int; total_posts: int; total_reels: int
    total_messages: int; total_follows: int
    new_users_today: int; new_posts_today: int

class AdminUserOut(BaseModel):
    id: int; username: str; name: str; email: str; bio: str
    avatar_url: str; created_at: datetime
    posts_count: int; reels_count: int; followers_count: int
    following_count: int; messages_sent: int

class AdminUserEdit(BaseModel):
    username:     Optional[str] = None
    name:         Optional[str] = None
    email:        Optional[str] = None
    bio:          Optional[str] = None
    new_password: Optional[str] = None

class AdminPostOut(BaseModel):
    id: int; user_id: int; username: str; post_type: str
    image_url: Optional[str]; text_content: Optional[str]
    caption: Optional[str]; created_at: datetime

class AdminPostEdit(BaseModel):
    caption:      Optional[str] = None
    text_content: Optional[str] = None

class AdminReelOut(BaseModel):
    id: int; user_id: int; username: str
    youtube_id: str; caption: Optional[str]; created_at: datetime

class AdminReelEdit(BaseModel):
    youtube_id: Optional[str] = None
    caption:    Optional[str] = None

class AdminMessageOut(BaseModel):
    id: int; sender_id: int; sender_username: str
    recipient_id: int; recipient_username: str
    content: Optional[str]; message_type: str
    timestamp: datetime; is_read: bool

class AdminMessageEdit(BaseModel):
    content: Optional[str] = None

# === Helpers =================================================================
def _user_out(u, db):
    return AdminUserOut(
        id=u.id, username=u.username, name=u.name, email=u.email,
        bio=u.bio or "", avatar_url=u.avatar_url or "", created_at=u.created_at,
        posts_count     = db.query(Post).filter(Post.user_id == u.id).count(),
        reels_count     = db.query(Reel).filter(Reel.user_id == u.id).count(),
        followers_count = db.query(Follow).filter(Follow.followed_id == u.id).count(),
        following_count = db.query(Follow).filter(Follow.follower_id == u.id).count(),
        messages_sent   = db.query(Message).filter(Message.sender_id == u.id).count(),
    )

def _post_out(p, db):
    o = db.query(User).filter(User.id == p.user_id).first()
    return AdminPostOut(
        id=p.id, user_id=p.user_id, username=o.username if o else "?",
        post_type="text" if p.text_content and not p.image_url else "image",
        image_url=p.image_url, text_content=p.text_content,
        caption=p.caption, created_at=p.created_at,
    )

def _reel_out(r, db):
    o = db.query(User).filter(User.id == r.user_id).first()
    return AdminReelOut(id=r.id, user_id=r.user_id, username=o.username if o else "?",
        youtube_id=r.youtube_id, caption=r.caption, created_at=r.created_at)

def _msg_out(m, db):
    s = db.query(User).filter(User.id == m.sender_id).first()
    r = db.query(User).filter(User.id == m.recipient_id).first()
    return AdminMessageOut(
        id=m.id, sender_id=m.sender_id, sender_username=s.username if s else "?",
        recipient_id=m.recipient_id, recipient_username=r.username if r else "?",
        content=m.content, message_type=m.message_type,
        timestamp=m.timestamp, is_read=m.is_read,
    )

# === Rotas ===================================================================

# Painel HTML — servido a partir de static/admin.html
@app.get("/admin", response_class=HTMLResponse)
@app.get("/",      response_class=HTMLResponse)
async def serve_panel():
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "admin.html")
    if os.path.exists(html_path):
        return FileResponse(html_path)
    return HTMLResponse(
        "<h2>admin.html não encontrado.</h2><p>Coloque admin.html em static/admin.html</p>",
        status_code=404
    )

# Login
@app.post("/admin/api/login", response_model=TokenOut)
def admin_login(body: LoginBody, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(401, "E-mail ou senha incorretos")
    if user.username.lower() != ADMIN_USERNAME:
        raise HTTPException(403, "Acesso negado. Apenas @hydra pode acessar o painel.")
    return TokenOut(access_token=create_access_token({"sub": user.id}), token_type="bearer")

# Me (usado pelo frontend para verificar o usuário logado)
@app.get("/users/me")
async def admin_me(admin: User = Depends(get_current_admin)):
    return {"id": admin.id, "username": admin.username, "name": admin.name, "email": admin.email}

# Stats
@app.get("/admin/api/stats", response_model=AdminStats)
def admin_stats(_: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    return AdminStats(
        total_users     = db.query(User).count(),
        total_posts     = db.query(Post).count(),
        total_reels     = db.query(Reel).count(),
        total_messages  = db.query(Message).count(),
        total_follows   = db.query(Follow).count(),
        new_users_today = db.query(User).filter(User.created_at >= today).count(),
        new_posts_today = db.query(Post).filter(Post.created_at >= today).count(),
    )

# Users — listar
@app.get("/admin/api/users", response_model=List[AdminUserOut])
def admin_list_users(
    q: str = "", skip: int = 0, limit: int = 500,
    _: User = Depends(get_current_admin), db: Session = Depends(get_db)
):
    qry = db.query(User)
    if q:
        qry = qry.filter(
            User.username.ilike(f"%{q}%") |
            User.name.ilike(f"%{q}%") |
            User.email.ilike(f"%{q}%")
        )
    return [_user_out(u, db) for u in qry.order_by(desc(User.created_at)).offset(skip).limit(limit).all()]

# Users — editar (nome, username, email, bio, senha)
@app.patch("/admin/api/users/{uid}", response_model=AdminUserOut)
def admin_edit_user(
    uid: int, body: AdminUserEdit,
    _: User = Depends(get_current_admin), db: Session = Depends(get_db)
):
    u = db.query(User).filter(User.id == uid).first()
    if not u:
        raise HTTPException(404, "Usuário não encontrado")

    if body.username is not None:
        uname = body.username.strip().lower()
        if not uname:
            raise HTTPException(400, "Username não pode ser vazio")
        if uname != u.username and db.query(User).filter(User.username == uname, User.id != uid).first():
            raise HTTPException(400, f"@{uname} já está em uso")
        u.username = uname

    if body.name is not None:
        n = body.name.strip()
        if not n:
            raise HTTPException(400, "Nome não pode ser vazio")
        u.name = n

    if body.email is not None:
        em = body.email.strip().lower()
        if em != u.email and db.query(User).filter(User.email == em, User.id != uid).first():
            raise HTTPException(400, "E-mail já está em uso por outro usuário")
        u.email = em

    if body.bio is not None:
        u.bio = body.bio

    if body.new_password:
        if len(body.new_password) < 6:
            raise HTTPException(400, "Senha muito curta (mínimo 6 caracteres)")
        u.hashed_password = get_password_hash(body.new_password)

    db.commit()
    db.refresh(u)
    return _user_out(u, db)

# Users — deletar
@app.delete("/admin/api/users/{uid}")
def admin_delete_user(
    uid: int,
    admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    u = db.query(User).filter(User.id == uid).first()
    if not u:
        raise HTTPException(404, "Usuário não encontrado")
    if u.username.lower() == ADMIN_USERNAME:
        raise HTTPException(400, "Não é possível deletar o admin (@hydra)")
    db.query(Message).filter(
        (Message.sender_id == uid) | (Message.recipient_id == uid)
    ).delete(synchronize_session=False)
    db.query(Follow).filter(
        (Follow.follower_id == uid) | (Follow.followed_id == uid)
    ).delete(synchronize_session=False)
    if u.avatar_url:
        p = u.avatar_url.lstrip("/")
        if os.path.exists(p):
            os.remove(p)
    db.delete(u)
    db.commit()
    return {"status": "ok", "message": f"@{u.username} deletado com sucesso"}

# Posts — listar
@app.get("/admin/api/posts", response_model=List[AdminPostOut])
def admin_list_posts(
    skip: int = 0, limit: int = 500,
    _: User = Depends(get_current_admin), db: Session = Depends(get_db)
):
    return [_post_out(p, db) for p in db.query(Post).order_by(desc(Post.created_at)).offset(skip).limit(limit).all()]

# Posts — editar
@app.patch("/admin/api/posts/{pid}", response_model=AdminPostOut)
def admin_edit_post(
    pid: int, body: AdminPostEdit,
    _: User = Depends(get_current_admin), db: Session = Depends(get_db)
):
    p = db.query(Post).filter(Post.id == pid).first()
    if not p:
        raise HTTPException(404, "Post não encontrado")
    if body.caption is not None:
        p.caption = body.caption
    if body.text_content is not None:
        p.text_content = body.text_content
    db.commit()
    db.refresh(p)
    return _post_out(p, db)

# Posts — deletar
@app.delete("/admin/api/posts/{pid}")
def admin_delete_post(
    pid: int,
    _: User = Depends(get_current_admin), db: Session = Depends(get_db)
):
    p = db.query(Post).filter(Post.id == pid).first()
    if not p:
        raise HTTPException(404, "Post não encontrado")
    if p.image_url:
        path = p.image_url.lstrip("/")
        if os.path.exists(path):
            os.remove(path)
    db.delete(p)
    db.commit()
    return {"status": "ok"}

# Reels — listar
@app.get("/admin/api/reels", response_model=List[AdminReelOut])
def admin_list_reels(
    skip: int = 0, limit: int = 500,
    _: User = Depends(get_current_admin), db: Session = Depends(get_db)
):
    return [_reel_out(r, db) for r in db.query(Reel).order_by(desc(Reel.created_at)).offset(skip).limit(limit).all()]

# Reels — editar
@app.patch("/admin/api/reels/{rid}", response_model=AdminReelOut)
def admin_edit_reel(
    rid: int, body: AdminReelEdit,
    _: User = Depends(get_current_admin), db: Session = Depends(get_db)
):
    r = db.query(Reel).filter(Reel.id == rid).first()
    if not r:
        raise HTTPException(404, "Reel não encontrado")
    if body.youtube_id is not None:
        yt = body.youtube_id.strip()
        if not yt:
            raise HTTPException(400, "youtube_id não pode ser vazio")
        r.youtube_id = yt
    if body.caption is not None:
        r.caption = body.caption
    db.commit()
    db.refresh(r)
    return _reel_out(r, db)

# Reels — deletar
@app.delete("/admin/api/reels/{rid}")
def admin_delete_reel(
    rid: int,
    _: User = Depends(get_current_admin), db: Session = Depends(get_db)
):
    r = db.query(Reel).filter(Reel.id == rid).first()
    if not r:
        raise HTTPException(404, "Reel não encontrado")
    db.delete(r)
    db.commit()
    return {"status": "ok"}

# Messages — listar
@app.get("/admin/api/messages", response_model=List[AdminMessageOut])
def admin_list_messages(
    skip: int = 0, limit: int = 500,
    _: User = Depends(get_current_admin), db: Session = Depends(get_db)
):
    return [_msg_out(m, db) for m in db.query(Message).order_by(desc(Message.timestamp)).offset(skip).limit(limit).all()]

# Messages — editar
@app.patch("/admin/api/messages/{mid}", response_model=AdminMessageOut)
def admin_edit_message(
    mid: int, body: AdminMessageEdit,
    _: User = Depends(get_current_admin), db: Session = Depends(get_db)
):
    m = db.query(Message).filter(Message.id == mid).first()
    if not m:
        raise HTTPException(404, "Mensagem não encontrada")
    if body.content is not None:
        m.content = body.content
    db.commit()
    db.refresh(m)
    return _msg_out(m, db)

# Messages — deletar
@app.delete("/admin/api/messages/{mid}")
def admin_delete_message(
    mid: int,
    _: User = Depends(get_current_admin), db: Session = Depends(get_db)
):
    m = db.query(Message).filter(Message.id == mid).first()
    if not m:
        raise HTTPException(404, "Mensagem não encontrada")
    db.delete(m)
    db.commit()
    return {"status": "ok"}

