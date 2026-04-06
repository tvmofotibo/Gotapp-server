"""
admin.py — Painel Administrativo do Got App
Rode com: python admin.py
Acesse:   http://localhost:8001/admin
"""

import os
import json
import secrets
import hashlib
import bcrypt
from datetime import datetime
from fastapi import FastAPI, HTTPException, Depends, Request, Cookie
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text, Boolean, UniqueConstraint, desc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship

# ── Banco de dados (mesmo do app principal) ──────────────────
SQLALCHEMY_DATABASE_URL = "sqlite:///./got_app.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

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
    posts = relationship("Post", back_populates="user", cascade="all, delete-orphan")
    reels = relationship("Reel", back_populates="user", cascade="all, delete-orphan")
    followers = relationship("Follow", foreign_keys="Follow.followed_id", back_populates="followed", cascade="all, delete-orphan")
    following = relationship("Follow", foreign_keys="Follow.follower_id", back_populates="follower", cascade="all, delete-orphan")
    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender")
    received_messages = relationship("Message", foreign_keys="Message.recipient_id", back_populates="recipient")
    push_subscriptions = relationship("PushSubscription", back_populates="user", cascade="all, delete-orphan")

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
    image_url = Column(String, nullable=True)
    text_content = Column(Text, nullable=True)
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

class PushSubscription(Base):
    __tablename__ = "push_subscriptions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    endpoint = Column(Text, nullable=False, unique=True)
    p256dh = Column(Text, nullable=False)
    auth = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="push_subscriptions")

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_password_hash(password: str) -> str:
    password_sha256 = hashlib.sha256(password.encode()).digest()
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password_sha256, salt).decode()

# ── Auth ─────────────────────────────────────────────────────
ADMIN_USERNAME = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASS", "admin123")
_sessions: dict = {}

def _make_token() -> str:
    return secrets.token_hex(32)

def _check_session(admin_token: Optional[str] = Cookie(default=None)) -> bool:
    if not admin_token or admin_token not in _sessions:
        raise HTTPException(status_code=401, detail="Não autenticado")
    return True

# ── Schemas ──────────────────────────────────────────────────
class LoginForm(BaseModel):
    username: str
    password: str

class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    new_password: Optional[str] = None

class UserCreate(BaseModel):
    username: str
    email: str
    name: str
    password: str

class PostUpdate(BaseModel):
    caption: Optional[str] = None
    text_content: Optional[str] = None

class ReelUpdate(BaseModel):
    caption: Optional[str] = None
    youtube_id: Optional[str] = None

class MessageUpdate(BaseModel):
    content: Optional[str] = None

# ── App ───────────────────────────────────────────────────────
admin = FastAPI(title="Got App — Admin Panel")
admin.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ═══════════════════════════════════════════════════════════════
# LOGIN PAGE
# ═══════════════════════════════════════════════════════════════
LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>got app · admin</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@700;800&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600&display=swap" rel="stylesheet">
<style>
:root{--ink:#07070a;--v:#7c5cfc;--v2:#a78bfa;--vg:linear-gradient(135deg,#6d28d9,#7c5cfc 45%,#a78bfa);--glow:rgba(124,92,252,.22);--bdr:rgba(255,255,255,.06);--bdrv:rgba(124,92,252,.28);--t0:#f0f0f5;--t2:#737388;--t3:#3a3a4a;}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--ink);color:var(--t0);font-family:'DM Sans',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;-webkit-font-smoothing:antialiased}
.orbs{position:fixed;inset:0;pointer-events:none;overflow:hidden}
.orb{position:absolute;border-radius:50%;filter:blur(80px);animation:oF 8s ease-in-out infinite}
.o1{width:320px;height:320px;background:rgba(109,40,217,.28);top:-80px;right:-60px}
.o2{width:220px;height:220px;background:rgba(167,139,250,.14);bottom:-40px;left:-40px;animation-delay:-3s}
.o3{width:150px;height:150px;background:rgba(124,92,252,.16);top:45%;left:35%;animation-delay:-5s}
@keyframes oF{0%,100%{transform:translate(0,0) scale(1)}33%{transform:translate(18px,-28px) scale(1.07)}66%{transform:translate(-14px,18px) scale(.95)}}
.card{position:relative;z-index:1;background:rgba(15,15,20,.88);backdrop-filter:blur(28px);border:1.5px solid var(--bdrv);border-radius:24px;padding:44px 32px 38px;width:90%;max-width:360px;display:flex;flex-direction:column;gap:16px;box-shadow:0 28px 70px rgba(0,0,0,.55),inset 0 1px 0 rgba(255,255,255,.06);animation:cI .45s cubic-bezier(.34,1.56,.64,1)}
@keyframes cI{from{opacity:0;transform:translateY(32px) scale(.93)}to{opacity:1;transform:none}}
.brand{text-align:center;margin-bottom:4px}
.brand-name{font-family:'Sora',sans-serif;font-size:3rem;font-weight:800;letter-spacing:-3px;background:var(--vg);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;line-height:1}
.brand-sub{color:var(--t2);font-size:.8rem;margin-top:6px}
.badge{display:inline-block;background:rgba(124,92,252,.15);border:1px solid var(--bdrv);color:var(--v2);font-size:.67rem;padding:3px 10px;border-radius:99px;margin-top:8px;letter-spacing:1.5px;text-transform:uppercase}
.field{position:relative}
.fi{position:absolute;left:15px;top:50%;transform:translateY(-50%);color:var(--t3);pointer-events:none;transition:color .2s;display:flex;align-items:center}
.field:focus-within .fi{color:var(--v2)}
.field input{padding-left:44px}
input{width:100%;background:rgba(255,255,255,.04);border:1.5px solid var(--bdr);border-radius:99px;padding:13px 18px;font-size:.92rem;color:var(--t0);outline:none;transition:border-color .2s,box-shadow .2s,background .2s;font-family:'DM Sans',sans-serif}
input:focus{border-color:var(--v2);background:rgba(124,92,252,.06);box-shadow:0 0 0 4px var(--glow)}
input::placeholder{color:var(--t3)}
.btn{width:100%;padding:14px;border-radius:99px;font-size:.93rem;font-weight:600;cursor:pointer;border:none;font-family:'DM Sans',sans-serif;background:var(--vg);color:#fff;box-shadow:0 5px 20px rgba(124,92,252,.4);transition:all .22s;display:flex;align-items:center;justify-content:center;gap:8px}
.btn:hover{transform:translateY(-2px);box-shadow:0 8px 28px rgba(124,92,252,.55)}
.btn:active{transform:scale(.96)}
.btn:disabled{opacity:.45;cursor:not-allowed;transform:none}
.err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#ef4444;border-radius:12px;padding:11px 14px;font-size:.83rem;display:none}
.err.show{display:block}
.spin{width:16px;height:16px;border:2.5px solid rgba(255,255,255,.2);border-top-color:#fff;border-radius:50%;animation:spin .6s linear infinite;display:inline-block}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="orbs"><div class="orb o1"></div><div class="orb o2"></div><div class="orb o3"></div></div>
<div class="card">
  <div class="brand">
    <div class="brand-name">got app</div>
    <div class="brand-sub">Conecte-se com quem importa</div>
    <div class="badge">admin panel</div>
  </div>
  <div class="err" id="err">Usuário ou senha incorretos.</div>
  <div class="field">
    <span class="fi"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>
    <input type="text" id="u" placeholder="Usuário" autocomplete="username"/>
  </div>
  <div class="field">
    <span class="fi"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg></span>
    <input type="password" id="p" placeholder="Senha" onkeydown="if(event.key==='Enter')login()"/>
  </div>
  <button class="btn" id="btn" onclick="login()">Entrar no painel</button>
</div>
<script>
async function login(){
  const btn=document.getElementById('btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span>';
  document.getElementById('err').classList.remove('show');
  const r=await fetch('/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});
  if(r.ok){window.location.href='/admin';}
  else{document.getElementById('err').classList.add('show');btn.disabled=false;btn.textContent='Entrar no painel';}
}
document.getElementById('u').focus();
</script>
</body>
</html>"""

# ═══════════════════════════════════════════════════════════════
# ADMIN PANEL HTML
# ═══════════════════════════════════════════════════════════════
ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>got app · admin</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@400;600;700;800&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600&display=swap" rel="stylesheet">
<style>
:root{
  --ink:#07070a;--ink1:#0f0f14;--ink2:#17171f;--ink3:#1f1f2a;--ink4:#272733;
  --t0:#f0f0f5;--t1:#c8c8d8;--t2:#737388;--t3:#3a3a4a;
  --v:#7c5cfc;--v2:#a78bfa;
  --vg:linear-gradient(135deg,#6d28d9,#7c5cfc 45%,#a78bfa);
  --glow:rgba(124,92,252,.2);--glow2:rgba(124,92,252,.07);
  --bdr:rgba(255,255,255,.06);--bdrv:rgba(124,92,252,.25);
  --danger:#ef4444;--warn:#f59e0b;--success:#22c55e;--info:#06b6d4;
  --ease:cubic-bezier(.4,0,.2,1);--spring:cubic-bezier(.34,1.56,.64,1);
  --sb:240px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:var(--ink);color:var(--t0);font-family:'DM Sans',sans-serif;font-size:14px;-webkit-font-smoothing:antialiased}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-thumb{background:var(--ink4);border-radius:4px}

.layout{display:flex;height:100vh;overflow:hidden}

/* SIDEBAR */
.sb{width:var(--sb);min-width:var(--sb);background:rgba(15,15,20,.97);backdrop-filter:blur(20px);border-right:1px solid var(--bdr);display:flex;flex-direction:column;overflow-y:auto;overflow-x:hidden}
.sb-logo{padding:22px 20px 18px;border-bottom:1px solid var(--bdr)}
.sb-name{font-family:'Sora',sans-serif;font-size:1.7rem;font-weight:800;letter-spacing:-2px;background:var(--vg);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;line-height:1}
.sb-badge{display:inline-block;background:rgba(124,92,252,.14);border:1px solid var(--bdrv);color:var(--v2);font-size:.6rem;padding:2px 9px;border-radius:99px;margin-top:5px;letter-spacing:1.5px;text-transform:uppercase}
.sb-sec{padding:14px 20px 5px;font-size:.62rem;letter-spacing:2.5px;text-transform:uppercase;color:var(--t3)}
.ni{display:flex;align-items:center;gap:10px;padding:10px 20px;cursor:pointer;color:var(--t2);transition:all .16s var(--ease);border-left:2.5px solid transparent;font-size:.87rem;font-weight:500;white-space:nowrap}
.ni:hover{color:var(--t1);background:var(--glow2)}
.ni.active{color:var(--v2);border-left-color:var(--v);background:var(--glow2)}
.ni svg{flex-shrink:0;opacity:.65;transition:opacity .16s}
.ni.active svg,.ni:hover svg{opacity:1}
.ni-badge{background:var(--vg);color:#fff;font-size:.6rem;font-weight:700;min-width:18px;height:18px;border-radius:99px;display:inline-flex;align-items:center;justify-content:center;padding:0 4px;margin-left:auto}
.sb-foot{margin-top:auto;padding:14px 20px;border-top:1px solid var(--bdr)}
.sb-meta{font-size:.72rem;color:var(--t3);line-height:1.8}
.sb-meta strong{color:var(--t2)}

/* MAIN */
.main{flex:1;overflow:hidden;display:flex;flex-direction:column}
.top{height:54px;padding:0 24px;background:rgba(15,15,20,.92);backdrop-filter:blur(20px);border-bottom:1px solid var(--bdr);display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.top-l{display:flex;align-items:center;gap:10px}
.top-title{font-family:'Sora',sans-serif;font-size:1rem;font-weight:700;letter-spacing:-.3px}
.top-sub{font-size:.72rem;color:var(--t3);margin-top:1px}
.top-r{display:flex;align-items:center;gap:8px}
.content{flex:1;overflow-y:auto;padding:22px 24px 32px}

/* STAT GRID */
.sg{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:22px}
.sc{background:var(--ink2);border:1.5px solid var(--bdr);border-radius:20px;padding:18px 16px;transition:border-color .2s,transform .2s var(--spring);position:relative;overflow:hidden}
.sc:hover{border-color:var(--bdrv);transform:translateY(-2px)}
.sc::before{content:'';position:absolute;top:-28px;right:-28px;width:80px;height:80px;border-radius:50%;background:var(--vg);opacity:.07}
.sc-ic{font-size:1.2rem;margin-bottom:10px}
.sc-val{font-family:'Sora',sans-serif;font-size:2rem;font-weight:800;line-height:1}
.sc-lbl{font-size:.7rem;color:var(--t2);margin-top:4px;letter-spacing:.5px;text-transform:uppercase}

/* PANEL */
.panel{background:var(--ink2);border:1.5px solid var(--bdr);border-radius:20px;overflow:hidden;margin-bottom:16px}
.ph{padding:13px 18px;border-bottom:1px solid var(--bdr);display:flex;align-items:center;justify-content:space-between;font-family:'Sora',sans-serif;font-size:.9rem;font-weight:700}
.ph-r{display:flex;align-items:center;gap:8px}

/* TABLE */
.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.82rem}
thead th{padding:10px 14px;text-align:left;font-size:.65rem;letter-spacing:1.5px;text-transform:uppercase;color:var(--t3);border-bottom:1px solid var(--bdr);background:rgba(0,0,0,.15);white-space:nowrap;font-family:'Sora',sans-serif}
tbody tr{border-bottom:1px solid rgba(255,255,255,.025);transition:background .1s}
tbody tr:hover{background:var(--glow2)}
tbody tr:last-child{border-bottom:none}
td{padding:10px 14px;vertical-align:middle}
.tid{color:var(--v2);font-weight:700;font-size:.74rem;font-family:'Sora',sans-serif}
.tmono{color:var(--t2);font-size:.78rem}
.ttr{max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* AVATAR */
.av{width:30px;height:30px;border-radius:50%;object-fit:cover;border:2px solid var(--bdrv);background:var(--ink3)}
.avph{width:30px;height:30px;border-radius:50%;background:var(--vg);display:inline-flex;align-items:center;justify-content:center;font-weight:700;font-size:.75rem;color:#fff;flex-shrink:0}

/* BADGES */
.bdg{display:inline-flex;align-items:center;padding:2px 8px;border-radius:99px;font-size:.67rem;font-weight:600}
.bv{background:rgba(124,92,252,.14);color:var(--v2);border:1px solid var(--bdrv)}
.bg{background:rgba(34,197,94,.1);color:var(--success);border:1px solid rgba(34,197,94,.22)}
.br{background:rgba(239,68,68,.1);color:var(--danger);border:1px solid rgba(239,68,68,.22)}
.by{background:rgba(245,158,11,.1);color:var(--warn);border:1px solid rgba(245,158,11,.22)}
.bb{background:rgba(6,182,212,.1);color:var(--info);border:1px solid rgba(6,182,212,.22)}

/* BUTTONS */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:8px 16px;border-radius:99px;border:none;cursor:pointer;font-family:'DM Sans',sans-serif;font-size:.82rem;font-weight:600;transition:all .16s var(--ease);white-space:nowrap}
.btn:active{transform:scale(.94)!important}
.btn:disabled{opacity:.4;cursor:not-allowed;transform:none!important}
.bp{background:var(--vg);color:#fff;box-shadow:0 4px 16px rgba(124,92,252,.3)}
.bp:hover{transform:translateY(-1px);box-shadow:0 6px 22px rgba(124,92,252,.48)}
.bs{background:rgba(255,255,255,.06);color:var(--t1);border:1.5px solid var(--bdr)}
.bs:hover{border-color:var(--bdrv);color:var(--v2)}
.bd{background:rgba(239,68,68,.09);color:var(--danger);border:1.5px solid rgba(239,68,68,.2)}
.bd:hover{background:rgba(239,68,68,.16)}
.btn-sm{padding:6px 13px;font-size:.78rem}
.btn-xs{padding:4px 10px;font-size:.72rem}
.btn-ic{width:29px;height:29px;padding:0;border-radius:8px;flex-shrink:0}

/* SEARCH */
.srch{padding:13px 18px 10px;display:flex;gap:10px;align-items:center}
.sb-box{flex:1;display:flex;align-items:center;gap:8px;background:rgba(255,255,255,.04);border:1.5px solid var(--bdr);border-radius:99px;padding:0 14px;transition:border-color .2s,box-shadow .2s}
.sb-box:focus-within{border-color:var(--v2);box-shadow:0 0 0 3px var(--glow)}
.sb-box svg{color:var(--t3);flex-shrink:0;transition:color .2s}
.sb-box:focus-within svg{color:var(--v2)}
.sb-box input{background:transparent;border:none;outline:none;padding:10px 0;color:var(--t0);font-family:'DM Sans',sans-serif;font-size:.85rem;width:100%}
.sb-box input::placeholder{color:var(--t3)}

/* MODAL */
.mov{display:none;position:fixed;inset:0;background:rgba(0,0,0,.72);backdrop-filter:blur(14px);z-index:1000;align-items:center;justify-content:center}
.mov.show{display:flex}
.mbox{background:var(--ink2);border:1.5px solid var(--bdrv);border-radius:20px;width:520px;max-width:95vw;max-height:90vh;overflow-y:auto;box-shadow:0 30px 80px rgba(0,0,0,.55);animation:mI .22s var(--spring)}
@keyframes mI{from{opacity:0;transform:scale(.9) translateY(16px)}to{opacity:1;transform:none}}
.mh{padding:20px 22px;border-bottom:1px solid var(--bdr);display:flex;align-items:center;justify-content:space-between}
.mh h2{font-family:'Sora',sans-serif;font-size:1rem;font-weight:700}
.mb{padding:20px 22px;display:flex;flex-direction:column;gap:14px}
.mf{padding:14px 22px;border-top:1px solid var(--bdr);display:flex;gap:10px;justify-content:flex-end}

/* FORMS */
.fg{display:flex;flex-direction:column;gap:6px}
.fl{font-size:.68rem;letter-spacing:1.5px;text-transform:uppercase;color:var(--t2)}
.fgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.fi,.fta,.fsel{background:rgba(255,255,255,.04);border:1.5px solid var(--bdr);border-radius:13px;padding:10px 13px;color:var(--t0);font-family:'DM Sans',sans-serif;font-size:.88rem;outline:none;transition:border-color .2s,box-shadow .2s,background .2s;width:100%}
.fi:focus,.fta:focus{border-color:var(--v2);background:var(--glow2);box-shadow:0 0 0 3px var(--glow)}
.fi::placeholder,.fta::placeholder{color:var(--t3)}
.fta{resize:vertical;min-height:80px;line-height:1.55;border-radius:12px}

/* TOAST */
#toasts{position:fixed;bottom:20px;right:20px;z-index:2000;display:flex;flex-direction:column;gap:8px;pointer-events:none}
.toast{background:var(--ink3);border:1.5px solid var(--bdr);border-radius:13px;padding:11px 15px;font-size:.82rem;display:flex;align-items:center;gap:9px;box-shadow:0 10px 30px rgba(0,0,0,.4);min-width:220px;max-width:340px;animation:tI .25s var(--spring) both;pointer-events:auto;transition:opacity .22s,transform .22s}
.toast.ok{border-color:rgba(34,197,94,.3);background:rgba(34,197,94,.07);color:var(--success)}
.toast.err{border-color:rgba(239,68,68,.3);background:rgba(239,68,68,.07);color:var(--danger)}
.toast.inf{border-color:var(--bdrv);background:var(--glow2);color:var(--v2)}
@keyframes tI{from{opacity:0;transform:translateX(24px) scale(.9)}to{opacity:1;transform:none}}

/* EMPTY */
.empty{display:flex;flex-direction:column;align-items:center;gap:12px;padding:48px 20px;color:var(--t3)}
.empty svg{opacity:.28}
.empty p{font-size:.84rem;text-align:center;line-height:1.7}

.spin{width:14px;height:14px;border:2px solid rgba(255,255,255,.15);border-top-color:#fff;border-radius:50%;animation:spin .6s linear infinite;display:inline-block}
@keyframes spin{to{transform:rotate(360deg)}}

.page{display:none}
.page.active{display:block;animation:pI .2s var(--ease)}
@keyframes pI{from{opacity:0;transform:translateY(7px)}to{opacity:1;transform:none}}

@media(max-width:860px){
  .sb{width:58px;min-width:58px}
  .sb-logo,.sb-badge,.sb-sec,.sb-foot{display:none}
  .ni span,.ni-badge{display:none}
  .ni{padding:13px;justify-content:center}
  .sg{grid-template-columns:repeat(2,1fr)}
}
</style>
</head>
<body>
<div class="layout">

<!-- SIDEBAR -->
<aside class="sb">
  <div class="sb-logo">
    <div class="sb-name">got app</div>
    <div class="sb-badge">admin</div>
  </div>
  <div class="sb-sec">Visão Geral</div>
  <div class="ni active" onclick="goPage('dashboard')" id="nav-dashboard">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
    <span>Dashboard</span>
  </div>
  <div class="sb-sec">Conteúdo</div>
  <div class="ni" onclick="goPage('users')" id="nav-users">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>
    <span>Usuários</span><span class="ni-badge" id="nb-users">0</span>
  </div>
  <div class="ni" onclick="goPage('posts')" id="nav-posts">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
    <span>Posts</span><span class="ni-badge" id="nb-posts">0</span>
  </div>
  <div class="ni" onclick="goPage('reels')" id="nav-reels">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="6" width="15" height="12" rx="2"/><path d="M17 10l5-3v10l-5-3V10z"/></svg>
    <span>Reels</span><span class="ni-badge" id="nb-reels">0</span>
  </div>
  <div class="sb-sec">Social</div>
  <div class="ni" onclick="goPage('messages')" id="nav-messages">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/></svg>
    <span>Mensagens</span><span class="ni-badge" id="nb-msgs">0</span>
  </div>
  <div class="ni" onclick="goPage('follows')" id="nav-follows">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
    <span>Follows</span>
  </div>
  <div class="sb-sec">Sistema</div>
  <div class="ni" onclick="goPage('push')" id="nav-push">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></svg>
    <span>Push Subs</span>
  </div>
  <div class="sb-foot">
    <div class="sb-meta"><strong>admin</strong><br>got app panel</div>
    <button class="btn bs btn-sm" style="margin-top:10px;width:100%" onclick="logout()">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      <span>Sair</span>
    </button>
  </div>
</aside>

<!-- MAIN -->
<div class="main">
  <div class="top">
    <div class="top-l">
      <div>
        <div class="top-title" id="top-title">Dashboard</div>
        <div class="top-sub" id="top-sub">Visão geral do sistema</div>
      </div>
    </div>
    <div class="top-r">
      <button class="btn bs btn-sm" onclick="refreshCur()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>
        Atualizar
      </button>
      <button class="btn bp btn-sm" id="top-action" style="display:none" onclick="topAction()">+ Novo</button>
    </div>
  </div>

  <div class="content">

    <!-- DASHBOARD -->
    <div id="page-dashboard" class="page active">
      <div class="sg">
        <div class="sc"><div class="sc-ic">👥</div><div class="sc-val" id="sv-users">—</div><div class="sc-lbl">Usuários</div></div>
        <div class="sc"><div class="sc-ic">🖼️</div><div class="sc-val" id="sv-posts">—</div><div class="sc-lbl">Posts</div></div>
        <div class="sc"><div class="sc-ic">▶️</div><div class="sc-val" id="sv-reels">—</div><div class="sc-lbl">Reels</div></div>
        <div class="sc"><div class="sc-ic">💬</div><div class="sc-val" id="sv-msgs">—</div><div class="sc-lbl">Mensagens</div></div>
        <div class="sc"><div class="sc-ic">🔗</div><div class="sc-val" id="sv-follows">—</div><div class="sc-lbl">Follows</div></div>
        <div class="sc"><div class="sc-ic">🔔</div><div class="sc-val" id="sv-push">—</div><div class="sc-lbl">Push Subs</div></div>
        <div class="sc"><div class="sc-ic">📩</div><div class="sc-val" id="sv-unread">—</div><div class="sc-lbl">Não lidas</div></div>
        <div class="sc"><div class="sc-ic">🤝</div><div class="sc-val" id="sv-mutual">—</div><div class="sc-lbl">Mútuos</div></div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
        <div class="panel"><div class="ph">Últimos Usuários</div>
          <table id="dt-users"><thead><tr><th>ID</th><th>Nome</th><th>@Username</th><th>Posts</th></tr></thead><tbody></tbody></table>
        </div>
        <div class="panel"><div class="ph">Últimas Mensagens</div>
          <table id="dt-msgs"><thead><tr><th>De</th><th>Para</th><th>Conteúdo</th><th>Tipo</th></tr></thead><tbody></tbody></table>
        </div>
      </div>
    </div>

    <!-- USERS -->
    <div id="page-users" class="page">
      <div class="panel">
        <div class="ph">Usuários <div class="ph-r"><button class="btn bp btn-sm" onclick="openNewUser()">+ Novo Usuário</button></div></div>
        <div class="srch"><div class="sb-box"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg><input type="text" placeholder="Buscar nome, email, username…" id="u-srch" oninput="filterUsers()"/></div></div>
        <div class="tw"><table id="tbl-users"><thead><tr><th>ID</th><th>Av.</th><th>Nome</th><th>Username</th><th>Email</th><th>Bio</th><th>Cadastro</th><th>Seguidores</th><th>Posts</th><th>Ações</th></tr></thead><tbody></tbody></table></div>
      </div>
    </div>

    <!-- POSTS -->
    <div id="page-posts" class="page">
      <div class="panel">
        <div class="ph">Posts</div>
        <div class="srch"><div class="sb-box"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg><input type="text" placeholder="Buscar autor, caption…" id="p-srch" oninput="filterPosts()"/></div></div>
        <div class="tw"><table id="tbl-posts"><thead><tr><th>ID</th><th>Autor</th><th>Tipo</th><th>Caption</th><th>Texto</th><th>Imagem</th><th>Criado</th><th>Ações</th></tr></thead><tbody></tbody></table></div>
      </div>
    </div>

    <!-- REELS -->
    <div id="page-reels" class="page">
      <div class="panel">
        <div class="ph">Reels</div>
        <div class="tw"><table id="tbl-reels"><thead><tr><th>ID</th><th>Autor</th><th>YouTube ID</th><th>Caption</th><th>Criado</th><th>Ações</th></tr></thead><tbody></tbody></table></div>
      </div>
    </div>

    <!-- MESSAGES -->
    <div id="page-messages" class="page">
      <div class="panel">
        <div class="ph">Mensagens <div class="ph-r"><label style="display:flex;align-items:center;gap:6px;font-size:.78rem;color:var(--t2);cursor:pointer;font-weight:400"><input type="checkbox" id="unread-only" onchange="filterMsgs()" style="accent-color:var(--v)"/> Não lidas</label></div></div>
        <div class="srch"><div class="sb-box"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg><input type="text" placeholder="Buscar conteúdo, remetente…" id="m-srch" oninput="filterMsgs()"/></div></div>
        <div class="tw"><table id="tbl-msgs"><thead><tr><th>ID</th><th>De</th><th>Para</th><th>Conteúdo</th><th>Tipo</th><th>Lida</th><th>Hora</th><th>Ações</th></tr></thead><tbody></tbody></table></div>
      </div>
    </div>

    <!-- FOLLOWS -->
    <div id="page-follows" class="page">
      <div class="panel">
        <div class="ph">Follows</div>
        <div class="tw"><table id="tbl-follows"><thead><tr><th>ID</th><th>Seguidor</th><th>Seguindo</th><th>Mútuo</th><th>Data</th><th>Ações</th></tr></thead><tbody></tbody></table></div>
      </div>
    </div>

    <!-- PUSH -->
    <div id="page-push" class="page">
      <div class="panel">
        <div class="ph">Push Subscriptions</div>
        <div class="tw"><table id="tbl-push"><thead><tr><th>ID</th><th>Usuário</th><th>Endpoint</th><th>Criado</th><th>Ações</th></tr></thead><tbody></tbody></table></div>
      </div>
    </div>

  </div>
</div>
</div>

<div id="toasts"></div>

<!-- MODAL USUÁRIO -->
<div class="mov" id="modal-user">
  <div class="mbox">
    <div class="mh"><h2 id="mu-title">Novo Usuário</h2><button class="btn bs btn-ic" onclick="closeModal('modal-user')">✕</button></div>
    <div class="mb">
      <input type="hidden" id="eu-id"/>
      <div class="fgrid">
        <div class="fg"><label class="fl">Username *</label><input class="fi" id="eu-user" placeholder="sem espaços"/></div>
        <div class="fg"><label class="fl">Nome completo *</label><input class="fi" id="eu-name" placeholder="Nome"/></div>
      </div>
      <div class="fg"><label class="fl">Email *</label><input class="fi" id="eu-email" type="email" placeholder="email@exemplo.com"/></div>
      <div class="fg"><label class="fl">Bio</label><textarea class="fta" id="eu-bio" placeholder="Biografia"></textarea></div>
      <div class="fg"><label class="fl">URL Avatar</label><input class="fi" id="eu-avatar" placeholder="/uploads/avatar_1_abc.jpg"/></div>
      <div class="fg"><label class="fl" id="eu-pwlbl">Senha *</label><input class="fi" id="eu-pw" type="password" placeholder="••••••••"/></div>
    </div>
    <div class="mf"><button class="btn bs" onclick="closeModal('modal-user')">Cancelar</button><button class="btn bp" onclick="saveUser()">Salvar</button></div>
  </div>
</div>

<!-- MODAL POST -->
<div class="mov" id="modal-post">
  <div class="mbox">
    <div class="mh"><h2>Editar Post <span style="color:var(--t3)" id="ep-lbl"></span></h2><button class="btn bs btn-ic" onclick="closeModal('modal-post')">✕</button></div>
    <div class="mb">
      <input type="hidden" id="ep-id"/>
      <div class="fg"><label class="fl">Caption</label><textarea class="fta" id="ep-caption" placeholder="Legenda"></textarea></div>
      <div class="fg"><label class="fl">Texto do post</label><textarea class="fta" id="ep-text" placeholder="Conteúdo do post" style="min-height:100px"></textarea></div>
    </div>
    <div class="mf"><button class="btn bs" onclick="closeModal('modal-post')">Cancelar</button><button class="btn bp" onclick="savePost()">Salvar</button></div>
  </div>
</div>

<!-- MODAL REEL -->
<div class="mov" id="modal-reel">
  <div class="mbox">
    <div class="mh"><h2>Editar Reel <span style="color:var(--t3)" id="er-lbl"></span></h2><button class="btn bs btn-ic" onclick="closeModal('modal-reel')">✕</button></div>
    <div class="mb">
      <input type="hidden" id="er-id"/>
      <div class="fg"><label class="fl">YouTube ID</label><input class="fi" id="er-ytid" placeholder="dQw4w9WgXcQ"/></div>
      <div class="fg"><label class="fl">Caption</label><textarea class="fta" id="er-caption" placeholder="Legenda do reel"></textarea></div>
    </div>
    <div class="mf"><button class="btn bs" onclick="closeModal('modal-reel')">Cancelar</button><button class="btn bp" onclick="saveReel()">Salvar</button></div>
  </div>
</div>

<!-- MODAL MENSAGEM -->
<div class="mov" id="modal-msg">
  <div class="mbox">
    <div class="mh"><h2>Editar Mensagem <span style="color:var(--t3)" id="em-lbl"></span></h2><button class="btn bs btn-ic" onclick="closeModal('modal-msg')">✕</button></div>
    <div class="mb">
      <input type="hidden" id="em-id"/>
      <div class="fg"><label class="fl">Conteúdo</label><textarea class="fta" id="em-content" style="min-height:110px"></textarea></div>
    </div>
    <div class="mf"><button class="btn bs" onclick="closeModal('modal-msg')">Cancelar</button><button class="btn bp" onclick="saveMsg()">Salvar</button></div>
  </div>
</div>

<!-- MODAL CONFIRMAR -->
<div class="mov" id="modal-confirm">
  <div class="mbox" style="max-width:380px">
    <div class="mh"><h2 id="cf-title">Confirmar</h2><button class="btn bs btn-ic" onclick="closeModal('modal-confirm')">✕</button></div>
    <div class="mb" style="text-align:center">
      <div style="font-size:2.2rem;margin-bottom:8px" id="cf-ic">⚠️</div>
      <div style="font-size:.87rem;color:var(--t2);line-height:1.68" id="cf-msg"></div>
    </div>
    <div class="mf"><button class="btn bs" onclick="closeModal('modal-confirm')">Cancelar</button><button class="btn bd" id="cf-ok">Excluir</button></div>
  </div>
</div>

<script>
'use strict';
let aUsers=[],aPosts=[],aMsgs=[],aReels=[],aFollows=[],aPush=[];
let curPage='dashboard';

// Utils
const esc=s=>String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const fmt=d=>{if(!d)return'—';const dt=new Date(d);return dt.toLocaleDateString('pt-BR',{day:'2-digit',month:'2-digit',year:'2-digit'})+' '+dt.toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'})};
const avUrl=(n,s=30)=>`https://ui-avatars.com/api/?name=${encodeURIComponent(n||'?')}&background=6d28d9&color=fff&size=${s}&bold=true`;

function toast(msg,type='inf'){
  const c=document.getElementById('toasts'),d=document.createElement('div');
  d.className=`toast ${type}`;
  const i={ok:'✓',err:'✕',inf:'◈'};
  d.innerHTML=`<span>${i[type]||'◈'}</span><span>${msg}</span>`;
  c.appendChild(d);
  setTimeout(()=>{d.style.opacity='0';d.style.transform='translateX(20px)';setTimeout(()=>d.remove(),220)},3200);
}

async function api(method,path,body){
  const o={method,headers:{'Content-Type':'application/json'},credentials:'same-origin'};
  if(body)o.body=JSON.stringify(body);
  const r=await fetch(path,o);
  if(r.status===401){window.location.href='/admin/login';return}
  if(!r.ok){const e=await r.json().catch(()=>({detail:'Erro'}));throw new Error(e.detail||'Erro')}
  return r.json().catch(()=>null);
}

function openModal(id){document.getElementById(id).classList.add('show')}
function closeModal(id){document.getElementById(id).classList.remove('show')}
document.querySelectorAll('.mov').forEach(o=>o.addEventListener('click',e=>{if(e.target===o)o.classList.remove('show')}));

function confirmDlg(title,msg,icon='⚠️'){
  return new Promise(res=>{
    document.getElementById('cf-title').textContent=title;
    document.getElementById('cf-msg').textContent=msg;
    document.getElementById('cf-ic').textContent=icon;
    const ok=document.getElementById('cf-ok');
    const cancel=document.getElementById('modal-confirm').querySelector('.btn.bs');
    ok.onclick=()=>{closeModal('modal-confirm');res(true)};
    cancel.onclick=()=>{closeModal('modal-confirm');res(false)};
    openModal('modal-confirm');
  });
}

const PAGE_META={
  dashboard:{t:'Dashboard',s:'Visão geral do sistema',a:null},
  users:{t:'Usuários',s:'Gerenciar contas',a:'openNewUser'},
  posts:{t:'Posts',s:'Gerenciar publicações',a:null},
  reels:{t:'Reels',s:'Gerenciar vídeos',a:null},
  messages:{t:'Mensagens',s:'Histórico de conversas',a:null},
  follows:{t:'Follows',s:'Relacionamentos',a:null},
  push:{t:'Push Subscriptions',s:'Notificações push',a:null},
};
const LOADERS={users:loadUsers,posts:loadPosts,reels:loadReels,messages:loadMsgs,follows:loadFollows,push:loadPush};

function goPage(p){
  document.querySelectorAll('.ni').forEach(e=>e.classList.remove('active'));
  document.getElementById('nav-'+p).classList.add('active');
  document.querySelectorAll('.page').forEach(e=>e.classList.remove('active'));
  document.getElementById('page-'+p).classList.add('active');
  const m=PAGE_META[p]||{};
  document.getElementById('top-title').textContent=m.t||p;
  document.getElementById('top-sub').textContent=m.s||'';
  const ab=document.getElementById('top-action');
  if(m.a){ab.style.display='';ab.dataset.act=m.a}else ab.style.display='none';
  curPage=p;
  if(LOADERS[p])LOADERS[p]();
}
function topAction(){const a=document.getElementById('top-action').dataset.act;if(a&&window[a])window[a]()}
function refreshCur(){if(curPage==='dashboard')loadStats();else if(LOADERS[curPage])LOADERS[curPage]()}
function logout(){fetch('/admin/logout',{method:'POST',credentials:'same-origin'}).finally(()=>{window.location.href='/admin/login'})}

// STATS
async function loadStats(){
  try{
    const s=await api('GET','/admin/stats');
    const map={users:'users',posts:'posts',reels:'reels',msgs:'messages',follows:'follows',push:'push_subs',unread:'unread_messages',mutual:'mutual_follows'};
    Object.entries(map).forEach(([k,v])=>{const el=document.getElementById('sv-'+k);if(el)el.textContent=s[v]??'—'});
    document.getElementById('nb-users').textContent=s.users||0;
    document.getElementById('nb-posts').textContent=s.posts||0;
    document.getElementById('nb-reels').textContent=s.reels||0;
    document.getElementById('nb-msgs').textContent=s.messages||0;
    loadDashTbls();
  }catch(e){toast('Erro stats: '+e.message,'err')}
}
async function loadDashTbls(){
  try{
    const users=await api('GET','/admin/users?limit=6&order=desc');
    const tb=document.querySelector('#dt-users tbody');tb.innerHTML='';
    users.forEach(u=>{const tr=document.createElement('tr');tr.innerHTML=`<td class="tid">#${u.id}</td><td>${esc(u.name)}</td><td class="tmono">@${esc(u.username)}</td><td>${u.posts_count}</td>`;tb.appendChild(tr)});
  }catch{}
  try{
    const msgs=await api('GET','/admin/messages?limit=6&order=desc');
    const tb=document.querySelector('#dt-msgs tbody');tb.innerHTML='';
    msgs.forEach(m=>{const tr=document.createElement('tr');tr.innerHTML=`<td>${esc(m.sender_name)}</td><td>${esc(m.recipient_name)}</td><td class="ttr">${esc(m.content||'—')}</td><td><span class="bdg ${m.message_type==='audio'?'by':'bv'}">${m.message_type}</span></td>`;tb.appendChild(tr)});
  }catch{}
}

// USERS
async function loadUsers(){
  try{aUsers=await api('GET','/admin/users');renderUsers(aUsers)}catch(e){toast('Erro: '+e.message,'err')}
}
function renderUsers(users){
  const tb=document.querySelector('#tbl-users tbody');
  if(!users.length){tb.innerHTML=`<tr><td colspan="10"><div class="empty"><svg width="38" height="38" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/></svg><p>Nenhum usuário</p></div></td></tr>`;return}
  tb.innerHTML='';
  users.forEach(u=>{
    const src=u.avatar_url?u.avatar_url:null;
    const avEl=src?`<img class="av" src="${esc(src)}" onerror="this.src='${avUrl(u.name)}'" alt="av"/>`:
      `<div class="avph">${(u.name||'?')[0].toUpperCase()}</div>`;
    const tr=document.createElement('tr');
    tr.innerHTML=`
      <td class="tid">#${u.id}</td>
      <td>${avEl}</td>
      <td><strong>${esc(u.name)}</strong></td>
      <td class="tmono">@${esc(u.username)}</td>
      <td class="tmono">${esc(u.email)}</td>
      <td class="ttr tmono">${esc(u.bio)}</td>
      <td class="tmono">${fmt(u.created_at)}</td>
      <td>${u.followers_count||0}</td>
      <td>${u.posts_count||0}</td>
      <td><div style="display:flex;gap:4px">
        <button class="btn bs btn-xs btn-ic" title="Editar" onclick='openEditUser(${JSON.stringify(u)})'>✎</button>
        <button class="btn bd btn-xs btn-ic" title="Excluir" onclick="delUser(${u.id},'${esc(u.name)}')">✕</button>
      </div></td>`;
    tb.appendChild(tr);
  });
}
function filterUsers(){
  const q=document.getElementById('u-srch').value.toLowerCase();
  renderUsers(aUsers.filter(u=>(u.name||'').toLowerCase().includes(q)||(u.username||'').toLowerCase().includes(q)||(u.email||'').toLowerCase().includes(q)));
}
function openNewUser(){
  document.getElementById('mu-title').textContent='Novo Usuário';
  document.getElementById('eu-id').value='';
  document.getElementById('eu-pwlbl').textContent='Senha *';
  ['eu-user','eu-name','eu-email','eu-bio','eu-avatar','eu-pw'].forEach(id=>document.getElementById(id).value='');
  openModal('modal-user');
}
function openEditUser(u){
  document.getElementById('mu-title').textContent='Editar — '+u.name;
  document.getElementById('eu-id').value=u.id;
  document.getElementById('eu-user').value=u.username||'';
  document.getElementById('eu-name').value=u.name||'';
  document.getElementById('eu-email').value=u.email||'';
  document.getElementById('eu-bio').value=u.bio||'';
  document.getElementById('eu-avatar').value=u.avatar_url||'';
  document.getElementById('eu-pw').value='';
  document.getElementById('eu-pwlbl').textContent='Nova senha (deixe em branco para manter)';
  openModal('modal-user');
}
async function saveUser(){
  const id=document.getElementById('eu-id').value;
  const body={username:document.getElementById('eu-user').value.trim(),name:document.getElementById('eu-name').value.trim(),email:document.getElementById('eu-email').value.trim(),bio:document.getElementById('eu-bio').value.trim(),avatar_url:document.getElementById('eu-avatar').value.trim()};
  const pw=document.getElementById('eu-pw').value;
  if(pw)body.new_password=pw;
  if(!body.username||!body.name||!body.email){toast('Preencha os campos obrigatórios','err');return}
  if(!id&&!pw){toast('Senha obrigatória para novo usuário','err');return}
  try{
    if(id)await api('PUT',`/admin/users/${id}`,body);
    else await api('POST','/admin/users',{...body,password:pw});
    toast(id?'Usuário atualizado!':'Usuário criado!','ok');
    closeModal('modal-user');loadUsers();loadStats();
  }catch(e){toast('Erro: '+e.message,'err')}
}
async function delUser(id,name){
  const ok=await confirmDlg('Excluir usuário',`Excluir "${name}"? Todos os dados associados serão removidos permanentemente.`,'🗑️');
  if(!ok)return;
  try{await api('DELETE',`/admin/users/${id}`);toast('Usuário excluído','ok');loadUsers();loadStats()}catch(e){toast('Erro: '+e.message,'err')}
}

// POSTS
async function loadPosts(){
  try{aPosts=await api('GET','/admin/posts');renderPosts(aPosts)}catch(e){toast('Erro: '+e.message,'err')}
}
function renderPosts(posts){
  const tb=document.querySelector('#tbl-posts tbody');
  if(!posts.length){tb.innerHTML=`<tr><td colspan="8"><div class="empty"><p>Nenhum post</p></div></td></tr>`;return}
  tb.innerHTML='';
  posts.forEach(p=>{
    const tr=document.createElement('tr');
    const tipo=p.post_type==='text'?`<span class="bdg bv">texto</span>`:`<span class="bdg bb">imagem</span>`;
    tr.innerHTML=`
      <td class="tid">#${p.id}</td>
      <td>${esc(p.user_name)}</td>
      <td>${tipo}</td>
      <td class="ttr">${esc(p.caption)}</td>
      <td class="ttr tmono">${esc(p.text_content)}</td>
      <td>${p.image_url?`<a href="${esc(p.image_url)}" target="_blank" style="color:var(--v2);font-size:.75rem">ver ↗</a>`:'-'}</td>
      <td class="tmono">${fmt(p.created_at)}</td>
      <td><div style="display:flex;gap:4px">
        <button class="btn bs btn-xs btn-ic" onclick='openEditPost(${JSON.stringify(p)})'>✎</button>
        <button class="btn bd btn-xs btn-ic" onclick="delPost(${p.id})">✕</button>
      </div></td>`;
    tb.appendChild(tr);
  });
}
function filterPosts(){
  const q=document.getElementById('p-srch').value.toLowerCase();
  renderPosts(aPosts.filter(p=>(p.user_name||'').toLowerCase().includes(q)||(p.caption||'').toLowerCase().includes(q)||(p.text_content||'').toLowerCase().includes(q)));
}
function openEditPost(p){
  document.getElementById('ep-id').value=p.id;
  document.getElementById('ep-lbl').textContent=`#${p.id}`;
  document.getElementById('ep-caption').value=p.caption||'';
  document.getElementById('ep-text').value=p.text_content||'';
  openModal('modal-post');
}
async function savePost(){
  const id=document.getElementById('ep-id').value;
  try{
    await api('PUT',`/admin/posts/${id}`,{caption:document.getElementById('ep-caption').value,text_content:document.getElementById('ep-text').value});
    toast('Post atualizado!','ok');closeModal('modal-post');loadPosts();
  }catch(e){toast('Erro: '+e.message,'err')}
}
async function delPost(id){
  const ok=await confirmDlg('Excluir post',`Excluir post #${id}?`,'🗑️');
  if(!ok)return;
  try{await api('DELETE',`/admin/posts/${id}`);toast('Post excluído','ok');loadPosts();loadStats()}catch(e){toast('Erro: '+e.message,'err')}
}

// REELS
async function loadReels(){
  try{aReels=await api('GET','/admin/reels');renderReels(aReels)}catch(e){toast('Erro: '+e.message,'err')}
}
function renderReels(reels){
  const tb=document.querySelector('#tbl-reels tbody');
  if(!reels.length){tb.innerHTML=`<tr><td colspan="6"><div class="empty"><p>Nenhum reel</p></div></td></tr>`;return}
  tb.innerHTML='';
  reels.forEach(r=>{
    const tr=document.createElement('tr');
    tr.innerHTML=`
      <td class="tid">#${r.id}</td>
      <td>${esc(r.user_name)}</td>
      <td><a href="https://youtube.com/watch?v=${esc(r.youtube_id)}" target="_blank" style="color:var(--v2)">${esc(r.youtube_id)} ↗</a></td>
      <td class="ttr">${esc(r.caption)}</td>
      <td class="tmono">${fmt(r.created_at)}</td>
      <td><div style="display:flex;gap:4px">
        <button class="btn bs btn-xs btn-ic" onclick='openEditReel(${JSON.stringify(r)})'>✎</button>
        <button class="btn bd btn-xs btn-ic" onclick="delReel(${r.id})">✕</button>
      </div></td>`;
    tb.appendChild(tr);
  });
}
function openEditReel(r){
  document.getElementById('er-id').value=r.id;
  document.getElementById('er-lbl').textContent=`#${r.id}`;
  document.getElementById('er-ytid').value=r.youtube_id||'';
  document.getElementById('er-caption').value=r.caption||'';
  openModal('modal-reel');
}
async function saveReel(){
  const id=document.getElementById('er-id').value;
  try{
    await api('PUT',`/admin/reels/${id}`,{youtube_id:document.getElementById('er-ytid').value.trim(),caption:document.getElementById('er-caption').value.trim()});
    toast('Reel atualizado!','ok');closeModal('modal-reel');loadReels();
  }catch(e){toast('Erro: '+e.message,'err')}
}
async function delReel(id){
  const ok=await confirmDlg('Excluir reel',`Excluir reel #${id}?`,'🗑️');
  if(!ok)return;
  try{await api('DELETE',`/admin/reels/${id}`);toast('Reel excluído','ok');loadReels();loadStats()}catch(e){toast('Erro: '+e.message,'err')}
}

// MESSAGES
async function loadMsgs(){
  try{aMsgs=await api('GET','/admin/messages');renderMsgs(aMsgs)}catch(e){toast('Erro: '+e.message,'err')}
}
function renderMsgs(msgs){
  const tb=document.querySelector('#tbl-msgs tbody');
  if(!msgs.length){tb.innerHTML=`<tr><td colspan="8"><div class="empty"><p>Nenhuma mensagem</p></div></td></tr>`;return}
  tb.innerHTML='';
  msgs.forEach(m=>{
    const tr=document.createElement('tr');
    tr.innerHTML=`
      <td class="tid">#${m.id}</td>
      <td>${esc(m.sender_name)}</td>
      <td>${esc(m.recipient_name)}</td>
      <td class="ttr">${esc(m.content)||'—'}</td>
      <td><span class="bdg ${m.message_type==='audio'?'by':'bv'}">${m.message_type}</span></td>
      <td><span class="bdg ${m.is_read?'bg':'br'}">${m.is_read?'lida':'não lida'}</span></td>
      <td class="tmono">${fmt(m.timestamp)}</td>
      <td><div style="display:flex;gap:4px">
        <button class="btn bs btn-xs btn-ic" onclick='openEditMsg(${JSON.stringify(m)})'>✎</button>
        <button class="btn bd btn-xs btn-ic" onclick="delMsg(${m.id})">✕</button>
      </div></td>`;
    tb.appendChild(tr);
  });
}
function filterMsgs(){
  const q=document.getElementById('m-srch').value.toLowerCase();
  const unread=document.getElementById('unread-only').checked;
  renderMsgs(aMsgs.filter(m=>{
    const match=(m.content||'').toLowerCase().includes(q)||(m.sender_name||'').toLowerCase().includes(q)||(m.recipient_name||'').toLowerCase().includes(q);
    return match&&(!unread||!m.is_read);
  }));
}
function openEditMsg(m){
  document.getElementById('em-id').value=m.id;
  document.getElementById('em-lbl').textContent=`#${m.id}`;
  document.getElementById('em-content').value=m.content||'';
  openModal('modal-msg');
}
async function saveMsg(){
  const id=document.getElementById('em-id').value;
  try{
    await api('PUT',`/admin/messages/${id}`,{content:document.getElementById('em-content').value});
    toast('Mensagem atualizada!','ok');closeModal('modal-msg');loadMsgs();
  }catch(e){toast('Erro: '+e.message,'err')}
}
async function delMsg(id){
  const ok=await confirmDlg('Excluir mensagem',`Excluir mensagem #${id}?`,'🗑️');
  if(!ok)return;
  try{await api('DELETE',`/admin/messages/${id}`);toast('Mensagem excluída','ok');loadMsgs();loadStats()}catch(e){toast('Erro: '+e.message,'err')}
}

// FOLLOWS
async function loadFollows(){
  try{
    aFollows=await api('GET','/admin/follows');
    const tb=document.querySelector('#tbl-follows tbody');
    if(!aFollows.length){tb.innerHTML=`<tr><td colspan="6"><div class="empty"><p>Nenhum follow</p></div></td></tr>`;return}
    tb.innerHTML='';
    const pairs={};
    aFollows.forEach(f=>{const k=[f.follower_id,f.followed_id].sort().join('-');pairs[k]=(pairs[k]||0)+1});
    aFollows.forEach(f=>{
      const k=[f.follower_id,f.followed_id].sort().join('-');
      const mutual=pairs[k]>1;
      const tr=document.createElement('tr');
      tr.innerHTML=`
        <td class="tid">#${f.id}</td>
        <td>${esc(f.follower_name)} <span class="tmono">#${f.follower_id}</span></td>
        <td>${esc(f.followed_name)} <span class="tmono">#${f.followed_id}</span></td>
        <td><span class="bdg ${mutual?'bg':'by'}">${mutual?'mútuo':'unilateral'}</span></td>
        <td class="tmono">${fmt(f.created_at)}</td>
        <td><button class="btn bd btn-xs btn-ic" onclick="delFollow(${f.id})">✕</button></td>`;
      tb.appendChild(tr);
    });
  }catch(e){toast('Erro: '+e.message,'err')}
}
async function delFollow(id){
  const ok=await confirmDlg('Remover follow',`Remover follow #${id}?`,'🗑️');
  if(!ok)return;
  try{await api('DELETE',`/admin/follows/${id}`);toast('Follow removido','ok');loadFollows()}catch(e){toast('Erro: '+e.message,'err')}
}

// PUSH
async function loadPush(){
  try{
    aPush=await api('GET','/admin/push-subscriptions');
    const tb=document.querySelector('#tbl-push tbody');
    if(!aPush.length){tb.innerHTML=`<tr><td colspan="5"><div class="empty"><p>Nenhuma subscription</p></div></td></tr>`;return}
    tb.innerHTML='';
    aPush.forEach(s=>{
      const tr=document.createElement('tr');
      tr.innerHTML=`
        <td class="tid">#${s.id}</td>
        <td>${esc(s.user_name)} <span class="tmono">#${s.user_id}</span></td>
        <td class="tmono ttr" title="${esc(s.endpoint)}">${esc(s.endpoint.substring(0,55))}…</td>
        <td class="tmono">${fmt(s.created_at)}</td>
        <td><button class="btn bd btn-xs btn-ic" onclick="delPush(${s.id})">✕</button></td>`;
      tb.appendChild(tr);
    });
  }catch(e){toast('Erro: '+e.message,'err')}
}
async function delPush(id){
  const ok=await confirmDlg('Remover subscription',`Remover push subscription #${id}?`,'🗑️');
  if(!ok)return;
  try{await api('DELETE',`/admin/push-subscriptions/${id}`);toast('Subscription removida','ok');loadPush()}catch(e){toast('Erro: '+e.message,'err')}
}

// INIT
document.getElementById('top-action').style.display='none';
loadStats();
</script>
</body>
</html>"""

# ═══════════════════════════════════════════════════════════════
# ROTAS
# ═══════════════════════════════════════════════════════════════

@admin.get("/admin/login", response_class=HTMLResponse)
def login_page():
    return LOGIN_HTML

@admin.post("/admin/login")
def do_login(data: LoginForm):
    if data.username != ADMIN_USERNAME or data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    token = _make_token()
    _sessions[token] = True
    resp = JSONResponse({"status": "ok"})
    resp.set_cookie("admin_token", token, httponly=True, samesite="strict", max_age=60*60*8)
    return resp

@admin.post("/admin/logout")
def do_logout(admin_token: Optional[str] = Cookie(default=None)):
    if admin_token and admin_token in _sessions:
        del _sessions[admin_token]
    resp = JSONResponse({"status": "ok"})
    resp.delete_cookie("admin_token")
    return resp

@admin.get("/admin", response_class=HTMLResponse)
def admin_panel(admin_token: Optional[str] = Cookie(default=None)):
    if not admin_token or admin_token not in _sessions:
        return RedirectResponse("/admin/login", status_code=302)
    return ADMIN_HTML

@admin.get("/admin/stats")
def get_stats(db: Session = Depends(get_db), _: bool = Depends(_check_session)):
    mutual_count = 0
    pairs = set()
    for f in db.query(Follow).all():
        key = tuple(sorted([f.follower_id, f.followed_id]))
        if key in pairs: mutual_count += 1
        else: pairs.add(key)
    return {
        "users": db.query(User).count(), "posts": db.query(Post).count(),
        "reels": db.query(Reel).count(), "messages": db.query(Message).count(),
        "follows": db.query(Follow).count(), "push_subs": db.query(PushSubscription).count(),
        "unread_messages": db.query(Message).filter(Message.is_read == False).count(),
        "mutual_follows": mutual_count,
    }

@admin.get("/admin/users")
def list_users(limit: int = 1000, order: str = "asc", db: Session = Depends(get_db), _: bool = Depends(_check_session)):
    q = db.query(User).order_by(desc(User.created_at) if order == "desc" else User.id)
    return [{
        "id": u.id, "username": u.username, "email": u.email, "name": u.name,
        "bio": u.bio or "", "avatar_url": u.avatar_url or "",
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "followers_count": db.query(Follow).filter(Follow.followed_id == u.id).count(),
        "following_count": db.query(Follow).filter(Follow.follower_id == u.id).count(),
        "posts_count": db.query(Post).filter(Post.user_id == u.id).count(),
    } for u in q.limit(limit).all()]

@admin.post("/admin/users", status_code=201)
def create_user(data: UserCreate, db: Session = Depends(get_db), _: bool = Depends(_check_session)):
    if db.query(User).filter(User.username == data.username).first(): raise HTTPException(400, "Username já em uso")
    if db.query(User).filter(User.email == data.email).first(): raise HTTPException(400, "Email já cadastrado")
    u = User(username=data.username, email=data.email, name=data.name, hashed_password=get_password_hash(data.password))
    db.add(u); db.commit(); db.refresh(u)
    return {"id": u.id, "username": u.username}

@admin.put("/admin/users/{user_id}")
def update_user(user_id: int, data: UserUpdate, db: Session = Depends(get_db), _: bool = Depends(_check_session)):
    u = db.query(User).filter(User.id == user_id).first()
    if not u: raise HTTPException(404, "Usuário não encontrado")
    if data.username is not None: u.username = data.username
    if data.email is not None: u.email = data.email
    if data.name is not None: u.name = data.name
    if data.bio is not None: u.bio = data.bio
    if data.avatar_url is not None: u.avatar_url = data.avatar_url
    if data.new_password: u.hashed_password = get_password_hash(data.new_password)
    db.commit()
    return {"status": "ok"}

@admin.delete("/admin/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db), _: bool = Depends(_check_session)):
    u = db.query(User).filter(User.id == user_id).first()
    if not u: raise HTTPException(404, "Usuário não encontrado")
    db.delete(u); db.commit()
    return {"status": "deleted"}

@admin.get("/admin/posts")
def list_posts(limit: int = 1000, order: str = "asc", db: Session = Depends(get_db), _: bool = Depends(_check_session)):
    q = db.query(Post).order_by(desc(Post.created_at) if order == "desc" else Post.id)
    return [{
        "id": p.id, "user_id": p.user_id,
        "user_name": db.query(User).filter(User.id == p.user_id).first().name if db.query(User).filter(User.id == p.user_id).first() else "",
        "image_url": p.image_url, "text_content": p.text_content, "caption": p.caption,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "post_type": "text" if p.text_content and not p.image_url else "image",
    } for p in q.limit(limit).all()]

@admin.put("/admin/posts/{post_id}")
def update_post(post_id: int, data: PostUpdate, db: Session = Depends(get_db), _: bool = Depends(_check_session)):
    p = db.query(Post).filter(Post.id == post_id).first()
    if not p: raise HTTPException(404, "Post não encontrado")
    if data.caption is not None: p.caption = data.caption
    if data.text_content is not None: p.text_content = data.text_content
    db.commit(); return {"status": "ok"}

@admin.delete("/admin/posts/{post_id}")
def delete_post(post_id: int, db: Session = Depends(get_db), _: bool = Depends(_check_session)):
    p = db.query(Post).filter(Post.id == post_id).first()
    if not p: raise HTTPException(404, "Post não encontrado")
    db.delete(p); db.commit(); return {"status": "deleted"}

@admin.get("/admin/reels")
def list_reels(db: Session = Depends(get_db), _: bool = Depends(_check_session)):
    return [{
        "id": r.id, "user_id": r.user_id,
        "user_name": db.query(User).filter(User.id == r.user_id).first().name if db.query(User).filter(User.id == r.user_id).first() else "",
        "youtube_id": r.youtube_id, "caption": r.caption,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    } for r in db.query(Reel).order_by(desc(Reel.created_at)).all()]

@admin.put("/admin/reels/{reel_id}")
def update_reel(reel_id: int, data: ReelUpdate, db: Session = Depends(get_db), _: bool = Depends(_check_session)):
    r = db.query(Reel).filter(Reel.id == reel_id).first()
    if not r: raise HTTPException(404, "Reel não encontrado")
    if data.caption is not None: r.caption = data.caption
    if data.youtube_id is not None: r.youtube_id = data.youtube_id
    db.commit(); return {"status": "ok"}

@admin.delete("/admin/reels/{reel_id}")
def delete_reel(reel_id: int, db: Session = Depends(get_db), _: bool = Depends(_check_session)):
    r = db.query(Reel).filter(Reel.id == reel_id).first()
    if not r: raise HTTPException(404, "Reel não encontrado")
    db.delete(r); db.commit(); return {"status": "deleted"}

@admin.get("/admin/messages")
def list_messages(limit: int = 1000, order: str = "desc", db: Session = Depends(get_db), _: bool = Depends(_check_session)):
    q = db.query(Message).order_by(desc(Message.timestamp) if order == "desc" else Message.id)
    result = []
    for m in q.limit(limit).all():
        sender = db.query(User).filter(User.id == m.sender_id).first()
        recipient = db.query(User).filter(User.id == m.recipient_id).first()
        result.append({
            "id": m.id, "sender_id": m.sender_id, "recipient_id": m.recipient_id,
            "sender_name": sender.name if sender else "", "recipient_name": recipient.name if recipient else "",
            "content": m.content, "message_type": m.message_type,
            "file_url": m.file_url, "is_read": m.is_read,
            "timestamp": m.timestamp.isoformat() if m.timestamp else None,
        })
    return result

@admin.put("/admin/messages/{msg_id}")
def update_message(msg_id: int, data: MessageUpdate, db: Session = Depends(get_db), _: bool = Depends(_check_session)):
    m = db.query(Message).filter(Message.id == msg_id).first()
    if not m: raise HTTPException(404, "Mensagem não encontrada")
    if data.content is not None: m.content = data.content
    db.commit(); return {"status": "ok"}

@admin.delete("/admin/messages/{msg_id}")
def delete_message(msg_id: int, db: Session = Depends(get_db), _: bool = Depends(_check_session)):
    m = db.query(Message).filter(Message.id == msg_id).first()
    if not m: raise HTTPException(404, "Mensagem não encontrada")
    db.delete(m); db.commit(); return {"status": "deleted"}

@admin.get("/admin/follows")
def list_follows(db: Session = Depends(get_db), _: bool = Depends(_check_session)):
    result = []
    for f in db.query(Follow).order_by(desc(Follow.created_at)).all():
        follower = db.query(User).filter(User.id == f.follower_id).first()
        followed = db.query(User).filter(User.id == f.followed_id).first()
        result.append({
            "id": f.id, "follower_id": f.follower_id, "followed_id": f.followed_id,
            "follower_name": follower.name if follower else "",
            "followed_name": followed.name if followed else "",
            "created_at": f.created_at.isoformat() if f.created_at else None,
        })
    return result

@admin.delete("/admin/follows/{follow_id}")
def delete_follow(follow_id: int, db: Session = Depends(get_db), _: bool = Depends(_check_session)):
    f = db.query(Follow).filter(Follow.id == follow_id).first()
    if not f: raise HTTPException(404, "Follow não encontrado")
    db.delete(f); db.commit(); return {"status": "deleted"}

@admin.get("/admin/push-subscriptions")
def list_push(db: Session = Depends(get_db), _: bool = Depends(_check_session)):
    return [{
        "id": s.id, "user_id": s.user_id,
        "user_name": db.query(User).filter(User.id == s.user_id).first().name if db.query(User).filter(User.id == s.user_id).first() else "",
        "endpoint": s.endpoint, "created_at": s.created_at.isoformat() if s.created_at else None,
    } for s in db.query(PushSubscription).order_by(desc(PushSubscription.created_at)).all()]

@admin.delete("/admin/push-subscriptions/{sub_id}")
def delete_push_sub(sub_id: int, db: Session = Depends(get_db), _: bool = Depends(_check_session)):
    s = db.query(PushSubscription).filter(PushSubscription.id == sub_id).first()
    if not s: raise HTTPException(404, "Subscription não encontrada")
    db.delete(s); db.commit(); return {"status": "deleted"}

# ── Entrypoint ───────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    print("\n╔══════════════════════════════════════╗")
    print("║   Got App · Admin Panel              ║")
    print("║   http://localhost:8001/admin        ║")
    print(f"║   Usuário: {ADMIN_USERNAME:<26}║")
    print(f"║   Senha:   {ADMIN_PASSWORD:<26}║")
    print("║                                      ║")
    print("║   Personalize via variáveis:         ║")
    print("║   ADMIN_USER / ADMIN_PASS            ║")
    print("╚══════════════════════════════════════╝\n")
    uvicorn.run(admin, host="0.0.0.0", port=8001)

