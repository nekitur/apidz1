import time
time.sleep(5)

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, DateTime, func, ForeignKey, or_, and_
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
import redis
import uuid
import datetime
import os
from dotenv import load_dotenv
from typing import Optional

load_dotenv()

app = FastAPI()

DATABASE_URL = os.getenv("DATABASE_URL")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
SECRET_KEY = os.getenv("SECRET_KEY", "supersecret")
ACCESS_TOKEN_EXPIRE_MINUTES = 60
EXPIRED_DAYS = int(os.getenv("EXPIRED_DAYS", 30))

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    links = relationship("Link", back_populates="owner")

class Link(Base):
    __tablename__ = "links"
    id = Column(Integer, primary_key=True, index=True)
    original_url = Column(String, nullable=False)
    short_code = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=True)
    last_accessed_at = Column(DateTime, nullable=True)
    clicks = Column(Integer, default=0)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    owner = relationship("User", back_populates="links")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=401,
        detail="Не удалось проверить учетные данные",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        if not username:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

def get_current_user_optional(token: str = Depends(oauth2_scheme_optional), db: Session = Depends(get_db)) -> Optional[User]:
    if not token:
        return None
    return get_current_user(token, db)

def generate_short_code() -> str:
    return uuid.uuid4().hex[:6]

@app.post("/links/shorten")
def create_link(request: Request,
                original_url: str,
                custom_alias: str = None,
                expires_at: Optional[datetime.datetime] = None,
                db: Session = Depends(get_db),
                current_user: Optional[User] = Depends(get_current_user_optional)):
    if custom_alias:
        existing = db.query(Link).filter(Link.short_code == custom_alias).first()
        if existing:
            raise HTTPException(status_code=400, detail="Custom alias уже используется")
        short_code = custom_alias
    else:
        short_code = generate_short_code()
        while db.query(Link).filter(Link.short_code == short_code).first():
            short_code = generate_short_code()

    link = Link(
        original_url=original_url,
        short_code=short_code,
        expires_at=expires_at,
        user_id=current_user.id if current_user else None
    )
    db.add(link)
    db.commit()
    db.refresh(link)

    redis_client.set(short_code, original_url)

    return {"short_code": short_code, "original_url": original_url}

@app.get("/{short_code}")
def redirect_link(short_code: str, db: Session = Depends(get_db)):
    cached_url = redis_client.get(short_code)
    if cached_url:
        original_url = cached_url
    else:
        link = db.query(Link).filter(Link.short_code == short_code).first()
        if not link:
            raise HTTPException(status_code=404, detail="Ссылка не найдена")
        if link.expires_at and link.expires_at < datetime.datetime.utcnow():
            raise HTTPException(status_code=410, detail="Ссылка устарела")
        original_url = link.original_url
        redis_client.set(short_code, original_url)

    db.query(Link).filter(Link.short_code == short_code).update({
        Link.clicks: Link.clicks + 1,
        Link.last_accessed_at: datetime.datetime.utcnow()
    })
    db.commit()
    return RedirectResponse(original_url)

@app.get("/links/{short_code}/stats")
def link_stats(short_code: str, db: Session = Depends(get_db)):
    link = db.query(Link).filter(Link.short_code == short_code).first()
    if not link:
        raise HTTPException(status_code=404, detail="Ссылка не найдена")
    return {
        "original_url": link.original_url,
        "created_at": link.created_at,
        "clicks": link.clicks,
        "last_accessed_at": link.last_accessed_at,
        "expires_at": link.expires_at
    }

@app.put("/links/{short_code}")
def update_link(short_code: str, original_url: str,
                db: Session = Depends(get_db),
                current_user: User = Depends(get_current_user)):
    link = db.query(Link).filter(Link.short_code == short_code).first()
    if not link:
        raise HTTPException(status_code=404, detail="Ссылка не найдена")
    if link.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Нет доступа для обновления этой ссылки")
    link.original_url = original_url
    db.commit()
    redis_client.set(short_code, original_url)
    return {"message": "Ссылка обновлена", "short_code": short_code}

@app.delete("/links/{short_code}")
def delete_link(short_code: str,
                db: Session = Depends(get_db),
                current_user: User = Depends(get_current_user)):
    link = db.query(Link).filter(Link.short_code == short_code).first()
    if not link:
        raise HTTPException(status_code=404, detail="Ссылка не найдена")
    if link.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Нет доступа для удаления этой ссылки")
    db.delete(link)
    db.commit()
    redis_client.delete(short_code)
    return {"message": "Ссылка удалена"}

@app.get("/links/search")
def search_link(original_url: str, db: Session = Depends(get_db)):
    links = db.query(Link).filter(Link.original_url == original_url).all()
    return links

class UserCreate(BaseModel):
    username: str
    password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@app.post("/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = pwd_context.hash(user.password)
    new_user = User(username=user.username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered successfully"}

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + (expires_delta or datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/links/expired")
def expired_links(db: Session = Depends(get_db)):
    now = datetime.datetime.utcnow()
    expired = db.query(Link).filter(Link.expires_at != None, Link.expires_at < now).all()
    return expired

@app.delete("/links/cleanup")
def cleanup_links(db: Session = Depends(get_db),
                  current_user: User = Depends(get_current_user)):
    now = datetime.datetime.utcnow()
    cutoff = now - datetime.timedelta(days=EXPIRED_DAYS)
    links_to_delete = db.query(Link).filter(
        or_(
            and_(Link.last_accessed_at != None, Link.last_accessed_at < cutoff),
            and_(Link.expires_at != None, Link.expires_at < now)
        )
    ).all()
    count = len(links_to_delete)
    for link in links_to_delete:
        redis_client.delete(link.short_code)
        db.delete(link)
    db.commit()
    return {"message": f"Удалено {count} неиспользуемых или истекших ссылок"}
