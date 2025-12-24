from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Dict, List, Literal, Optional
from ulid import ULID
from fastapi import APIRouter, Depends, FastAPI, Form, HTTPException, Response, UploadFile
from fastapi.security import APIKeyCookie
from sqlalchemy import CHAR, DateTime, Engine, ForeignKey, String, create_engine, desc, event, exists, func, or_, select, text, union, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, Session
from pydantic import BaseModel, EmailStr, Field, model_validator
from argon2 import PasswordHasher, exceptions
from socketio import AsyncServer, ASGIApp
from PIL import Image
import os
import io
import hashlib
import aiofiles
import jwt
import secrets

load_dotenv()
if not os.getenv("JWT_SECRET"):
    with open(".env", 'w') as f:
        JWT_SECRET = secrets.token_hex(32)
        f.write(f"JWT_SECRET={JWT_SECRET}")
        print("Generated new JWT_SECRET into .env")
else:
    JWT_SECRET = os.environ["JWT_SECRET"]
    print("Loaded JWT_SECRET from .env")

password_hasher = PasswordHasher()

# Text field lengths
@dataclass(frozen=True)
class FieldLength:
    min: int
    max: int
    def kwargs(self) -> Dict[str, Any]:
        return {"min_length": self.min,"max_length": self.max}

ULID_LEN = 26
USERNAME_LEN = FieldLength(6, 32)
DISPLAY_NAME_LEN = FieldLength(1, 64)
PASSWORD_LEN = FieldLength(6, 1024)
SERVER_NAME_LEN = FieldLength(1, 64)
CHANNEL_NAME_LEN = FieldLength(1, 32)
MESSAGE_LEN = FieldLength(1, 4096)

# SQLAlchemy models:
class Base(DeclarativeBase):
    def to_dict(self):
        return {field.name:getattr(self, field.name) for field in self.__table__.c}
    
class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(CHAR(ULID_LEN), primary_key=True)
    username: Mapped[str] = mapped_column(String(USERNAME_LEN.max),index=True, unique=True)
    email: Mapped[str] = mapped_column(index=True, unique=True)
    display_name: Mapped[str] = mapped_column(String(DISPLAY_NAME_LEN.max))
    picture: Mapped[Optional[str]]
    password: Mapped[str]
    banned: Mapped[bool] = mapped_column(default=False)
    custom_status: Mapped[Optional[str]]
    
    servers: Mapped[List["Server"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    messages: Mapped[List["Message"]] = relationship(back_populates="user", cascade="all, delete-orphan")

class Server(Base):
    __tablename__ = "servers"
    id: Mapped[str] = mapped_column(CHAR(ULID_LEN), primary_key=True)
    owner_id: Mapped[str] = mapped_column(CHAR(ULID_LEN), ForeignKey("users.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(SERVER_NAME_LEN.max))
    picture: Mapped[Optional[str]]
    banner: Mapped[Optional[str]]
    roles: Mapped[Optional[str]]
    
    user: Mapped["User"] = relationship(back_populates="servers")
    channels: Mapped[List["Channel"]] = relationship(back_populates="server", cascade="all, delete-orphan")
    members: Mapped[List["Server_Member"]] = relationship(back_populates="server", cascade="all, delete-orphan")

class Channel(Base):
    __tablename__ = "channels"
    id: Mapped[str] = mapped_column(CHAR(ULID_LEN), primary_key=True)
    server_id: Mapped[str] = mapped_column(CHAR(ULID_LEN), ForeignKey("servers.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(CHANNEL_NAME_LEN.max))
    # private: Mapped[bool] = mapped_column(Boolean, default=False)
    # allowed_roles: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # allowed_users: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    
    server: Mapped["Server"] = relationship(back_populates="channels")
    messages: Mapped[List["Message"]] = relationship(back_populates="channel", cascade="all, delete-orphan")

class Message(Base):
    __tablename__ = "messages"
    id: Mapped[str] = mapped_column(CHAR(ULID_LEN), primary_key=True)
    sender_id: Mapped[str] = mapped_column(CHAR(ULID_LEN), ForeignKey("users.id", ondelete="CASCADE"))
    channel_id: Mapped[str] = mapped_column(CHAR(ULID_LEN), ForeignKey("channels.id", ondelete="CASCADE"))
    message: Mapped[str] = mapped_column(String(MESSAGE_LEN.max))
    attachments: Mapped[Optional[str]] = mapped_column(default=None)
    edited: Mapped[Optional[bool]] = mapped_column(default=None)
    
    channel: Mapped["Channel"] = relationship(back_populates="messages")
    user: Mapped["User"] = relationship(back_populates="messages")

class Server_Member(Base):
    __tablename__ = "server_members"
    server_id: Mapped[str] = mapped_column(CHAR(ULID_LEN), ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True, index=True)
    member_id: Mapped[str] = mapped_column(CHAR(ULID_LEN), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True)
    member_since: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    server: Mapped["Server"] = relationship(back_populates="members")


# Types:
RoomType = Literal["server", "channel"]

# Pydantic types:
UsernameStr = Annotated[str, Field(**USERNAME_LEN.kwargs())]
PasswordStr = Annotated[str, Field(**PASSWORD_LEN.kwargs())]
DisplayNameStr = Annotated[str, Field(**DISPLAY_NAME_LEN.kwargs())]
ServerNameStr = Annotated[str, Field(**SERVER_NAME_LEN.kwargs())]
ChannelNameStr = Annotated[str, Field(**CHANNEL_NAME_LEN.kwargs())]
MessageStr = Annotated[str, Field(**MESSAGE_LEN.kwargs())]

# Pydantic models:
class UserRegisterRequest(BaseModel):
    username: UsernameStr
    email: EmailStr
    password: PasswordStr
    password_repeat: PasswordStr

    @model_validator(mode="after")
    def check_passwords_match(self):
        if self.password != self.password_repeat:
            raise ValueError("passwords do not match")
        return self

class UserLoginRequest(BaseModel):
    email: EmailStr
    password: PasswordStr

class MessageCreateRequest(BaseModel):
    message: MessageStr

class UpdateUserInfoRequest(BaseModel):
    display_name: Optional[DisplayNameStr] = None
    picture: Optional[str] = None

class UpdateServerInfoRequest(BaseModel):
    name: Optional[ServerNameStr] = None
    picture: Optional[str] = None

class UpdateChannelInfoRequest(BaseModel):
    name: Optional[ChannelNameStr] = None


# Helpers
def room_path(room_type: RoomType, id: str):
    return f"{room_type}:{id}"

def get_display_name(db: Database, user_id: str): # TODO not optimal solution, extra query
    return db.execute(select(User.display_name).where(User.id == user_id)).scalar_one()


# Database setup
sqlite_filename = "database/database.db"
db_url = f"sqlite:///{sqlite_filename}"
connect_args = {}

if db_url.startswith("sqlite"): 
    os.makedirs(os.path.dirname(sqlite_filename), exist_ok=True)
    connect_args = {"check_same_thread": False}

engine = create_engine(url=db_url, connect_args=connect_args, echo=False)

if engine.url.drivername == "sqlite": # runs on every connection to sqlite
    @event.listens_for(Engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.close()


# FastAPI setup
@asynccontextmanager
async def lifespan(app: FastAPI): # runs on start or before shutdown
    Base.metadata.create_all(engine)
    if engine.url.drivername == "sqlite":
        with engine.connect() as db:
            db.execute(text("PRAGMA journal_mode=WAL;"))
    yield
    # code after yield runs before shutdown

app = FastAPI(lifespan=lifespan)


# Socket.IO
sio = AsyncServer(cors_allowed_origins='*', async_mode='asgi')
app.mount("/socket.io", ASGIApp(socketio_server=sio, other_asgi_app=app))

# Socket.IO helpers
async def sio_is_server_member(sid: str, server_id: str) -> str | None:
    sio_session = await sio.get_session(sid)
    user_id = sio_session.get("user_id")
    assert type(user_id) == str
    
    with Session(engine) as session:
        try: is_server_member(session, server_id, user_id)
        except Exception as e: return str(e)
    
async def subscribe(sid: str, room_type: RoomType, target: str):
    for room in sio.rooms(sid): 
        if room.startswith(room_type): 
            await sio.leave_room(sid, room)
            print(f"sid '{sid}' unsubscribed from: '{room}'")
            break

    room = room_path(room_type, target)
    await sio.enter_room(sid, room)
    print(f"sid '{sid}' subscribed to '{room}'")

# Socket.IO events
@sio.event
async def connect(sid: str, env):
    with Session(engine) as session:
        try:
            user_id = auth_user(session, env["HTTP_COOKIE"].split('token=', 1)[1])
        except:
            raise ConnectionRefusedError('authentication failed')
        
    await sio.save_session(sid, {"user_id": user_id})
    print(f"User ID '{user_id}' connected to Socket.IO as sid '{sid}'")

@sio.event
async def disconnect(sid: str, reason):
    print(f"Sid '{sid}' disconnected from Socket.IO, reason: {reason}")

@sio.event
async def subscribe_to_channel_list(sid: str, server_id: str):
    if issue := await sio_is_server_member(sid, server_id): return issue
    await subscribe(sid, "server", server_id)

@sio.event
async def subscribe_to_message_list(sid: str, server_id: str, channel_id: str):
    if issue := await sio_is_server_member(sid, server_id): return issue
    await subscribe(sid, "channel", channel_id)


# FastAPI middlewares:
def get_session():
    with Session(engine, expire_on_commit=False) as session:
        yield session
Database = Annotated[Session, Depends(get_session)]

def auth_user(db: Database, token: str = Depends(APIKeyCookie(name="token"))):
    try:
        jwt_payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except:
        raise HTTPException(401, "Error decoding jwt")
    
    user_id = jwt_payload.get("user_id")
    if not isinstance(user_id, str):
        raise HTTPException(401, "Error getting user_id from jwt")

    banned = db.scalar(select(User.banned).where(User.id == user_id))
    if banned is None:
        raise HTTPException(401, "User id from jwt doesn't exist in database")
    if banned is True:
        raise HTTPException(401, "User is banned")

    return user_id
AuthUser = Annotated[str, Depends(auth_user)]

def is_server_owner(db: Database, server_id: str, user_id: AuthUser):
    is_owner = db.scalar(select(exists().where(Server.id == server_id, Server.owner_id == user_id)))
    if not is_owner:
        raise HTTPException(401, "Not owner of server, which may not even exist")

    return user_id
IsServerOwner = Annotated[str, Depends(is_server_owner)]

def is_server_member(db: Database, server_id: str, user_id: AuthUser):
    is_owner = exists().where(Server.id == server_id, Server.owner_id == user_id)
    is_member = exists().where(Server_Member.server_id == server_id, Server_Member.member_id == user_id)
    result = db.scalar(select(is_owner | is_member))
    if not result:
        raise HTTPException(401, "Not member or owner of server, which may not even exist")
    return user_id
IsServerMember = Annotated[str, Depends(is_server_member)]

def is_in_permitted_role(db: Database, channel_id: str, user_id: AuthUser):
    return user_id
IsInPermittedRole = Annotated[str, Depends(is_in_permitted_role)]


# FastAPI paths
v1 = APIRouter(prefix="/api/v1")

@v1.post("/user/register", status_code=204, response_class=Response)
def register_user(req: Annotated[UserRegisterRequest, Form()], db: Database):
    try:
        user = User(id=str(ULID()), email=req.email, username=req.username, display_name=req.username, 
                    password=password_hasher.hash(req.password))
        db.add(user); db.commit()
    except IntegrityError:
        raise HTTPException(409)

@v1.post("/user/login", status_code=204, response_class=Response)
def login_user(req: Annotated[UserLoginRequest, Form()], db: Database, response: Response):
    user = db.scalar(select(User).where(User.email == req.email))
    if not user:
        raise HTTPException(401)
    try:
        password_hasher.verify(user.password, req.password)
    except exceptions.VerifyMismatchError:
        raise HTTPException(401)

    days: int = 14
    expires = datetime.now(timezone.utc) + timedelta(days=days)
    encoded_jwt = jwt.encode({"user_id": user.id, "exp": expires}, JWT_SECRET, algorithm="HS256")
    response.set_cookie(key="token", value=encoded_jwt, httponly=True, secure=True, samesite="lax", max_age=days * 24 * 3600)

@v1.get("/user/logout", status_code=204, response_class=Response)
def logout_user(response: Response):
    response.delete_cookie(key="token")

@v1.delete("/user/delete", status_code=204, response_class=Response)
def delete_user(db: Database, user_id: AuthUser):
    user = db.execute(select(User).where(User.id == user_id)).scalar_one()
    db.delete(user); db.commit()

@v1.get("/test", response_class=PlainTextResponse)
def test():
    return "Hello world!"

@v1.get("/user_id", response_class=PlainTextResponse)
def get_user_id(user_id: AuthUser):
    return user_id

@v1.get("/user")
def get_user_info(db: Database, user_id: AuthUser):
    display_name, picture = db.execute(select(User.display_name, User.picture).where(User.id == user_id)).one()
    return {"display_name": display_name, "picture": picture}

@v1.patch("/user")
def update_user_info(req: Annotated[UpdateUserInfoRequest, Form()], db: Database, user_id: AuthUser):
    values = req.model_dump()
    db.execute(update(User).where(User.id == user_id).values(values)); db.commit()
    return values

@v1.post("/user/avatar")
async def update_user_avatar(avatar: UploadFile, db: Database, user_id: AuthUser):
    with Image.open(avatar.file) as img:
        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")
            
        s = min(img.size) # size 
        w, h = img.size # width, height 
        img = img.crop(((w - s) // 2, (h - s) // 2, (w + s) // 2, (h + s) // 2))

        full_img = img.resize((256, 256), Image.Resampling.LANCZOS)
        full_buffer = io.BytesIO()
        full_img.save(full_buffer, format="WEBP", quality=50)
        full_bytes = full_buffer.getvalue()
        
        small_img = img.resize((80, 80), Image.Resampling.LANCZOS)
        small_buffer = io.BytesIO()
        small_img.save(small_buffer, format="WEBP", quality=50)
        small_bytes = small_buffer.getvalue()

    file_hash = hashlib.sha256(full_bytes).hexdigest()
    
    full_path = f"public/avatars/{file_hash}.webp"
    small_path = f"public/avatars/small/{file_hash}.webp"
    
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    os.makedirs(os.path.dirname(small_path), exist_ok=True)

    async with aiofiles.open(full_path, "wb") as f:
        await f.write(full_bytes)
    async with aiofiles.open(small_path, "wb") as f:
        await f.write(small_bytes)

    db.execute(update(User).where(User.id == user_id).values(picture=file_hash)); db.commit()

@v1.post("/server")
def create_server(name: ServerNameStr, db: Database, user_id: AuthUser):
    server = Server(id=str(ULID()), owner_id=user_id, name=name)
    db.add(server)
    db.add(Channel(id=str(ULID()), server_id=server.id, name="Default channel"))
    db.commit()
    db.refresh(server)
    return server

@v1.get("/server")
def get_server_info(server_id: str, db: Database, user_id: AuthUser):
    server = db.scalar(select(Server).where(Server.id == server_id, Server.owner_id == user_id))
    if not server:
        raise HTTPException(401)
    return server

@v1.patch("/server")
def update_server_info(server_id: str, req: Annotated[UpdateServerInfoRequest, Form()], db: Database, user_id: IsServerOwner):
    values = req.model_dump()
    db.execute(update(Server).where(Server.id == server_id, Server.owner_id ==  user_id).values(values)); db.commit()
    return values

@v1.get("/servers")
def get_servers(db: Database, user_id: AuthUser):
    return db.scalars(select(Server).where(
        or_(Server.owner_id == user_id, Server.members.any(Server_Member.member_id == user_id)))).all()

@v1.delete("/server", status_code=202, response_class=Response)
async def delete_server(server_id: str, db: Database, user_id: AuthUser):
    server = db.scalar(select(Server).where(Server.id == server_id, Server.owner_id == user_id))
    if not server:
        raise HTTPException(401)
    
    db.delete(server); db.commit()
    
    await sio.emit("delete_server", server_id, room_path("server", server_id))

@v1.post("/channel", status_code=202, response_class=Response)
async def create_channel(server_id: str, name: ChannelNameStr, db: Database, user_id: IsServerOwner):
    channel = Channel(id=str(ULID()), server_id=server_id, name=name)
    db.add(channel); db.commit()

    await sio.emit("create_channel", channel.to_dict(), room_path("server", server_id))

@v1.get("/channel")
def get_channel_info(server_id: str, channel_id: str, db: Database, user_id: IsServerOwner):
    channel = db.scalar(select(Channel).where(Channel.id == channel_id, Channel.server_id == server_id))
    if not channel:
        raise HTTPException(401)
    return channel

@v1.patch("/channel")
async def update_channel_info(server_id: str, channel_id: str, req: Annotated[UpdateChannelInfoRequest, Form()], db: Database, user_id: IsServerOwner):
    values = req.model_dump()
    channel = db.scalar(update(Channel).where(Channel.id == channel_id, Channel.server_id == server_id).values(values).returning(Channel)); 
    if channel is None:
        raise HTTPException(401)
    db.commit()
    await sio.emit("modify_channel", channel.to_dict(), room_path("server", server_id))
    return values

@v1.get("/channels")
async def get_channels(server_id: str, db: Database, user_id: IsServerMember):
    return db.scalars(select(Channel).where(Channel.server_id == server_id)).all()

@v1.delete("/channel", status_code=202, response_class=Response)
async def delete_channel(server_id: str, channel_id: str, db: Database, user_id: IsServerOwner):
    channel = db.scalar(select(Channel).where(Channel.id == channel_id, Channel.server_id == server_id))
    if not channel:
        raise HTTPException(401)
    
    db.delete(channel); db.commit()

    await sio.emit("delete_channel", channel_id, room_path("server", server_id))

@v1.get("/member")
def get_members(server_id: str, db: Database, _: IsServerMember):
    owner_stmt = (select(User.id, User.display_name, User.picture, User.custom_status).join(Server, Server.owner_id == User.id)
                  .where(Server.id == server_id))
    member_stmt = (select(User.id, User.display_name, User.picture, User.custom_status).join(Server_Member, Server_Member.member_id == User.id)
                   .where(Server_Member.server_id == server_id))
    rows = db.execute(union(owner_stmt, member_stmt)).all()

    return [{"user_id": user_id, "display_name": display_name, "picture": picture, "custom_status": custom_status} 
        for user_id, display_name, picture, custom_status in rows]

@v1.post("/message", status_code=202, response_class=Response)
async def create_message(req: MessageCreateRequest, channel_id: str, db: Database, user_id: IsServerMember):
    message = Message(id=str(ULID()), sender_id=user_id, channel_id=channel_id, message=req.message)
    db.add(message); db.commit()

    display_name, picture = db.execute(select(User.display_name, User.picture).where(User.id == user_id)).one()

    data = {**message.to_dict(), "display_name": display_name, "picture": picture}
    await sio.emit("create_message", data, room_path("channel", channel_id))

@v1.get("/message")
async def get_messages(channel_id: str, db: Database, user_id: IsServerMember):
    results = db.execute(select(Message, User.display_name, User.picture).join(User)
                      .where(Message.channel_id == channel_id).order_by(desc(Message.id)).limit(50)).all()
    return [{**message.to_dict(), "display_name": display_name, "picture": picture} 
            for message, display_name, picture in results]

@v1.delete("/message", status_code=202, response_class=Response)
async def delete_message(message_id: str, db: Database, user_id: AuthUser):
    message = db.scalar(select(Message).where(Message.id == message_id, Message.sender_id == user_id))
    if not message:
        raise HTTPException(401)
    
    db.delete(message); db.commit()

    await sio.emit("delete_message", message.id, room_path("channel", message.channel_id))

@v1.post("/typing", status_code=202, response_class=Response)
async def typing(db: Database, value: Literal["start", "stop"], channel_id: str, user_id: IsServerMember):
    display_name = get_display_name(db, user_id)
    await sio.emit(f"{value}_typing", display_name, room_path("channel", channel_id))

@v1.post("/upload", response_class=Response)
async def upload_attachment(attachment: UploadFile, user_id: AuthUser):
    temp_path = f"public/attachments/temp_{attachment.filename}"
    os.makedirs(os.path.dirname(temp_path), exist_ok=True)

    async with aiofiles.open(temp_path, "wb") as tmp:
        while chunk := await attachment.read(4 * 1024 * 1024): # 4 mb chunks
            hashlib.sha256().update(chunk)
            await tmp.write(chunk)

    hash_name = hashlib.sha256().hexdigest()
    _, ext = os.path.splitext(str(attachment.filename))
    final_path = f"public/attachments/{hash_name}{ext}"

    if os.path.exists(final_path):
        os.remove(temp_path)
    else:
        os.rename(temp_path, final_path)

    return final_path

app.include_router(v1)

# Svelte file handlers
if os.path.exists("./dist"): # serve svelte frontend from dist folder, if it's there
    app.mount("/", StaticFiles(directory="dist", html=True))

# Public file handlers
@app.get("/public/avatars/{file_path:path}")
async def serve_avatar(file_path: str, user_id: AuthUser):
    base_dir = Path("public/avatars").resolve()
    requested_path = (base_dir / file_path).resolve()

    if not str(requested_path).startswith(str(base_dir)):
        raise HTTPException(403)

    if not requested_path.is_file():
        raise HTTPException(404)

    return FileResponse(requested_path, headers={"Cache-Control": "private, max-age=31536000, immutable"}) 