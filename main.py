from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path as FilePath
import shutil
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Dict, List, Literal, Optional
from ulid import ULID
from fastapi import APIRouter, Depends, FastAPI, Form, HTTPException, Response, UploadFile, Path
from fastapi.security import APIKeyCookie
from sqlalchemy import CHAR, Engine, ForeignKey, String, create_engine, desc, event, exists, func, or_, select, text, union, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, Session
from pydantic import BaseModel, EmailStr, Field, StringConstraints, model_validator
from argon2 import PasswordHasher, exceptions
from socketio import AsyncServer, ASGIApp
from PIL import Image
import os
import io
import hashlib
import aiofiles
import jwt
import secrets
import asyncio

# Constants
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
    edited: Mapped[Optional[str]] = mapped_column(default=None)
    
    channel: Mapped["Channel"] = relationship(back_populates="messages")
    user: Mapped["User"] = relationship(back_populates="messages")

class Server_Member(Base):
    __tablename__ = "server_members"
    server_id: Mapped[str] = mapped_column(CHAR(ULID_LEN), ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True, index=True)
    member_id: Mapped[str] = mapped_column(CHAR(ULID_LEN), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True)
    member_since: Mapped[str] = mapped_column(server_default=func.now())

    server: Mapped["Server"] = relationship(back_populates="members")


# Types:
RoomType = Literal["server", "channel"]

# Pydantic types:
UlidStr = Annotated[str, StringConstraints(pattern=r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")]
UsernameStr = Annotated[str, Field(**USERNAME_LEN.kwargs())]
PasswordStr = Annotated[str, Field(**PASSWORD_LEN.kwargs())]
DisplayNameStr = Annotated[str, Field(**DISPLAY_NAME_LEN.kwargs())]
ServerNameStr = Annotated[str, Field(**SERVER_NAME_LEN.kwargs())]
ChannelNameStr = Annotated[str, Field(**CHANNEL_NAME_LEN.kwargs())]
MessageStr = Annotated[str, Field(**MESSAGE_LEN.kwargs())]
PictureName = Annotated[str, Path(pattern=r"^[a-f0-9]{64}\.webp$")]

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

class UserInfoResponse(BaseModel):
    username: UsernameStr
    display_name: DisplayNameStr
    picture: Optional[str]
    custom_status: Optional[str]

class UserEditRequest(BaseModel):
    display_name: Optional[DisplayNameStr] = None

class UserMemberResponse(BaseModel):
    user_id: str
    display_name: DisplayNameStr
    picture: Optional[str] = None
    custom_status: Optional[str] = None

class ServerSchema(BaseModel):
    id: str
    owner_id: str
    name: ServerNameStr
    picture: Optional[str] = None
    banner: Optional[str] = None
    roles: Optional[str] = None

class ServerCreateRequest(BaseModel):
    name: ServerNameStr

class ServerEditRequest(BaseModel):
    name: Optional[ServerNameStr] = None

class ChannelSchema(BaseModel):
    id: str
    server_id: str
    name: ChannelNameStr

class ChannelCreateRequest(BaseModel):
    name: ChannelNameStr

class ChannelEditRequest(BaseModel):
    name: Optional[ChannelNameStr] = None

class MessageCreateRequest(BaseModel):
    message: MessageStr

class MessageEditRequest(BaseModel):
    message: MessageStr

class MessageEditResponse(BaseModel):
    class Config: from_attributes = True
    id: str
    message: MessageStr
    attachments: Optional[str] = None
    edited: Optional[str] = None

class MessageResponse(BaseModel):
    class Config: from_attributes = True
    id: str
    sender_id: str
    channel_id: str
    message: MessageStr
    attachments: Optional[str] = None
    edited: Optional[str] = None
    display_name: DisplayNameStr
    picture: Optional[str] = None

class TypingSchema(BaseModel):
    user_id: str
    display_name: Optional[str] = None


# Helpers
def room_path(room_type: RoomType, id: str):
    return f"{room_type}:{id}"

def get_display_name(db: Database, user_id: str): # TODO not optimal solution, extra query
    return db.execute(select(User.display_name).where(User.id == user_id)).scalar_one()

async def save_picture(file: bytes, path: str, resolution: tuple[int, int], crop_square: bool | None = None, name: str | None = None):
    try:
        with Image.open(io.BytesIO(file)) as img:
            if img.mode != "RGB":
                img = img.convert("RGB")
            
            if crop_square:
                s = min(img.size) # size 
                w, h = img.size # width, height 
                img = img.crop(((w - s) // 2, (h - s) // 2, (w + s) // 2, (h + s) // 2))

            img = img.resize(resolution, Image.Resampling.LANCZOS)
            buffer = io.BytesIO()
            img.save(buffer, format="WEBP", quality=75)
            bytes = buffer.getvalue()
    except: 
        raise HTTPException(422, "Error processing received picture")

    file_hash: str | None = None
    if name:
        final_path = FilePath(f"{path}/{name}")
    else:
        file_hash = hashlib.sha256(bytes).hexdigest()
        final_path = FilePath(f"{path}/{file_hash}.webp")

    os.makedirs(os.path.dirname(final_path), exist_ok=True)

    async with aiofiles.open(final_path, "wb") as f:
        await f.write(bytes)

    if file_hash: 
        return file_hash
    return None


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
async def sio_has_server_access(sid: str, server_id: str) -> str | None:
    sio_session = await sio.get_session(sid)
    user_id = sio_session.get("user_id")
    assert type(user_id) == str
    
    with Session(engine) as session:
        try: has_server_access(session, server_id, user_id)
        except Exception as e: return str(e)

async def sio_has_channel_access(sid: str, channel_id: str) -> str | None:
    sio_session = await sio.get_session(sid)
    user_id = sio_session.get("user_id")
    assert type(user_id) == str

    with Session(engine) as session:
        try: has_channel_access(session, channel_id, user_id)
        except Exception as e: return str(e)
    
async def subscribe(sid: str, room_type: RoomType, target: str):
    for room in sio.rooms(sid): 
        if room.startswith(room_type): 
            await sio.leave_room(sid, room)
            # print(f"sid '{sid}' unsubscribed from: '{room}'")
            break

    room = room_path(room_type, target)
    await sio.enter_room(sid, room)
    # print(f"sid '{sid}' subscribed to '{room}'")

# Socket.IO events
@sio.event
async def connect(sid: str, env):
    with Session(engine) as session:
        try:
            user_id = auth_user(session, env["HTTP_COOKIE"].split('token=', 1)[1])
        except:
            raise ConnectionRefusedError('authentication failed')
        
    await sio.save_session(sid, {"user_id": user_id})
    # print(f"User ID '{user_id}' connected to Socket.IO as sid '{sid}'")

# @sio.event
# async def disconnect(sid: str, reason):
    # print(f"Sid '{sid}' disconnected from Socket.IO, reason: '{reason}'")

@sio.event
async def subscribe_to_channel_list(sid: str, server_id: str):
    if issue := await sio_has_server_access(sid, server_id): return issue
    await subscribe(sid, "server", server_id)

@sio.event
async def subscribe_to_message_list(sid: str, channel_id: str):
    if issue := await sio_has_channel_access(sid, channel_id): return issue
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

def is_server_owner(db: Database, server_id: UlidStr, user_id: AuthUser):
    is_owner = db.scalar(select(exists().where(Server.id == server_id, Server.owner_id == user_id)))
    if not is_owner:
        raise HTTPException(401, f"Not owner of server ID '{server_id}', which may not even exist")
    return user_id
IsServerOwner = Annotated[str, Depends(is_server_owner)]

def has_server_access(db: Database, server_id: UlidStr, user_id: AuthUser):
    is_owner = exists().where(Server.id == server_id, Server.owner_id == user_id)
    is_member = exists().where(Server_Member.server_id == server_id, Server_Member.member_id == user_id)
    result = db.scalar(select(is_owner | is_member))
    if not result:
        raise HTTPException(401, f"Not member or owner of server ID '{server_id}', which may not even exist")
    return user_id
HasServerAccess = Annotated[str, Depends(has_server_access)]

def is_channel_owner(db: Database, channel_id: UlidStr, user_id: AuthUser):
    server_id = db.scalar(select(Channel.server_id).where(Channel.id == channel_id))
    if not server_id:
        raise HTTPException(404, f"Channel ID '{channel_id}' doesn't belong to any server")
    is_server_owner(db, server_id, user_id)
    return user_id, server_id
IsChannelOwner = Annotated[str, Depends(is_channel_owner)]

def has_channel_access(db: Database, channel_id: UlidStr, user_id: AuthUser):
    server_id = db.scalar(select(Channel.server_id).where(Channel.id == channel_id))
    if not server_id:
        raise HTTPException(404, f"Channel ID '{channel_id}' doesn't belong to any server")
    has_server_access(db, server_id, user_id)
    return user_id
HasChannelAccess = Annotated[str, Depends(has_channel_access)]


# FastAPI paths
v1 = APIRouter(prefix="/api/v1")

@v1.post("/user/register", response_class=RedirectResponse)
async def register_user(req: Annotated[UserRegisterRequest, Form()], db: Database):
    try:
        user = User(id=str(ULID()), email=req.email, username=req.username, display_name=req.username, 
                    password=password_hasher.hash(req.password))
        db.add(user)
        db.commit()
    except IntegrityError:
        raise HTTPException(409, "User with same e-mail or username already exists")
    return RedirectResponse("/login.html", 303)

@v1.post("/user/login", response_class=RedirectResponse)
async def login_user(req: Annotated[UserLoginRequest, Form()], db: Database):
    user = db.scalar(select(User).where(User.email == req.email))
    if not user:
        raise HTTPException(401, "Bad login")
    try:
        password_hasher.verify(user.password, req.password)
    except exceptions.VerifyMismatchError:
        raise HTTPException(401, "Bad login")

    days: int = 14
    expires = datetime.now(timezone.utc) + timedelta(days=days)
    encoded_jwt = jwt.encode({"user_id": user.id, "exp": expires}, JWT_SECRET, algorithm="HS256")
    
    response = RedirectResponse("/", 303)
    response.set_cookie(key="token", value=encoded_jwt, httponly=True, secure=True, samesite="lax", max_age=days * 24 * 3600)
    return response

@v1.get("/user/logout", status_code=204, response_class=Response)
async def logout_user(response: Response):
    response.delete_cookie(key="token")

@v1.delete("/user/delete", status_code=204, response_class=Response)
async def delete_user(db: Database, user_id: AuthUser):
    user = db.execute(select(User).where(User.id == user_id)).scalar_one()
    db.delete(user)
    db.commit()

@v1.get("/test", response_class=PlainTextResponse)
async def test():
    return "Hello world!"

@v1.get("/user_id", response_class=PlainTextResponse)
async def get_user_id(user_id: AuthUser):
    return user_id

@v1.get("/user", response_model=UserInfoResponse)
async def get_user_info(db: Database, user_id: AuthUser):
    return db.execute(select(User.username, User.display_name, User.picture, User.custom_status)
        .where(User.id == user_id)).one()

@v1.patch("/user", response_class=Response)
async def update_user_info(req: Annotated[UserEditRequest, Form()], db: Database, user_id: AuthUser):
    values = req.model_dump()
    db.execute(update(User).where(User.id == user_id).values(values))
    db.commit()

@v1.post("/user/upload/avatar", status_code=202, response_class=Response)
async def upload_user_avatar(avatar: UploadFile, db: Database, user_id: AuthUser):
    file_hash = await save_picture(await avatar.read(), "public/avatars", (256, 256), crop_square=True)
    db.execute(update(User).where(User.id == user_id).values(picture=file_hash))
    db.commit()

@v1.post("/server", response_model=ServerSchema)
async def create_server(req: ServerCreateRequest, db: Database, user_id: AuthUser):
    server = Server(id=str(ULID()), owner_id=user_id, name=req.name)
    db.add(server)
    db.add(Channel(id=str(ULID()), server_id=server.id, name="Default channel"))
    db.commit()
    db.refresh(server)
    return server

@v1.get("/server/{server_id}", response_model=ServerSchema)
async def get_server_info(server_id: UlidStr, db: Database, user_id: AuthUser):
    server = db.scalar(select(Server).where(Server.id == server_id, Server.owner_id == user_id))
    if not server:
        raise HTTPException(401, f"You don't own any server with ID '{server_id}'")
    return server

@v1.patch("/server/{server_id}", response_class=Response)
async def update_server_info(server_id: str, req: Annotated[ServerEditRequest, Form()], db: Database, user_id: IsServerOwner):
    values = req.model_dump()
    db.execute(update(Server).where(Server.id == server_id, Server.owner_id ==  user_id).values(values))
    db.commit()

@v1.post("/server/{server_id}/upload/avatar", response_class=Response)
async def upload_server_avatar(avatar: UploadFile, server_id: UlidStr, db: Database, user_id: AuthUser):
    file_hash = await save_picture(await avatar.read(), "public/avatars", (256, 256), crop_square=True)
    result = db.scalar(update(Server).where(Server.id == server_id, Server.owner_id == user_id)
        .values(picture=file_hash).returning(Server.id))
    if not result:
        raise HTTPException(401, f"Not authorised to update avatar of server ID '{server_id}'")
    db.commit()

@v1.get("/servers", response_model=list[ServerSchema])
async def get_servers(db: Database, user_id: AuthUser):
    return db.scalars(select(Server).where(
        or_(Server.owner_id == user_id, Server.members.any(Server_Member.member_id == user_id)))).all()

@v1.delete("/server/{server_id}", status_code=202, response_class=Response)
async def delete_server(server_id: UlidStr, db: Database, user_id: AuthUser):
    server = db.scalar(select(Server).where(Server.id == server_id, Server.owner_id == user_id))
    if not server:
        raise HTTPException(401, f"You don't own any server with ID '{server_id}'")
    
    db.delete(server)
    db.commit()
    
    await sio.emit("delete_server", server_id, room_path("server", server_id))

@v1.post("/server/{server_id}/channel", status_code=202, response_class=Response)
async def create_channel(server_id: str, req: ChannelCreateRequest, db: Database, user_id: IsServerOwner):
    channel = Channel(id=str(ULID()), server_id=server_id, name=req.name)
    db.add(channel)
    db.commit()

    await sio.emit("create_channel", channel.to_dict(), room_path("server", server_id))

@v1.get("/channel/{channel_id}", response_model=ChannelSchema)
async def get_channel_info(channel_id: str, db: Database, auth: IsChannelOwner):
    user_id, server_id = auth
    channel = db.scalar(select(Channel).where(Channel.id == channel_id, Channel.server_id == server_id))
    if not channel:
        raise HTTPException(401, f"Not authorised to get info of channel ID '{channel_id}'")
    return channel

@v1.patch("/channel/{channel_id}", status_code=202, response_class=Response)
async def update_channel_info(channel_id: str, req: Annotated[ChannelEditRequest, Form()], db: Database, auth: IsChannelOwner):
    user_id, server_id = auth
    values = req.model_dump()
    channel = db.scalar(update(Channel).where(Channel.id == channel_id, Channel.server_id == server_id).values(values).returning(Channel))
    if not channel:
        raise HTTPException(401, f"Not authorised to edit channel ID '{channel_id}'")
    db.commit()
    await sio.emit("modify_channel", channel.to_dict(), room_path("server", server_id))

@v1.get("/server/{server_id}/channels", response_model=list[ChannelSchema])
async def get_channels(server_id: str, db: Database, user_id: HasServerAccess):
    return db.scalars(select(Channel).where(Channel.server_id == server_id)).all()

@v1.delete("/channel/{channel_id}", status_code=202, response_class=Response)
async def delete_channel(channel_id: str, db: Database, auth: IsChannelOwner):
    user_id, server_id = auth
    channel = db.scalar(select(Channel).where(Channel.id == channel_id, Channel.server_id == server_id))
    if not channel:
        raise HTTPException(401, f"Not authorised to delete channel ID '{channel_id}'")
    
    db.delete(channel)
    db.commit()

    await sio.emit("delete_channel", channel_id, room_path("server", server_id))

@v1.get("/server/{server_id}/members", response_model=list[UserMemberResponse])
async def get_members(server_id: str, db: Database, _: HasServerAccess):
    owner_stmt = (select(User.id, User.display_name, User.picture, User.custom_status).join(Server, Server.owner_id == User.id)
                  .where(Server.id == server_id))
    member_stmt = (select(User.id, User.display_name, User.picture, User.custom_status).join(Server_Member, Server_Member.member_id == User.id)
                   .where(Server_Member.server_id == server_id))
    rows = db.execute(union(owner_stmt, member_stmt)).all()

    return [UserMemberResponse(user_id=user_id, display_name=display_name, picture=picture, custom_status=custom_status) 
        for user_id, display_name, picture, custom_status in rows]

@v1.post("/channel/{channel_id}/message", status_code=202, response_class=Response)
async def create_message(channel_id: str, req: MessageCreateRequest, db: Database, user_id: HasChannelAccess):
    message = Message(id=str(ULID()), sender_id=user_id, channel_id=channel_id, message=req.message)
    db.add(message)
    db.commit()

    display_name, picture = db.execute(select(User.display_name, User.picture).where(User.id == user_id)).one()

    data = MessageResponse(**message.to_dict(), display_name=display_name, picture=picture).model_dump()
    await sio.emit("create_message", data, room_path("channel", channel_id))

@v1.patch("/message/{message_id}", status_code=202, response_class=Response)
async def edit_message(message_id: UlidStr, req: MessageEditRequest, db: Database, user_id: AuthUser):
    msg = db.scalar(update(Message).where(Message.id == message_id, Message.sender_id == user_id)
        .values({"message": req.message, "edited": func.now()}).returning(Message)); 
    if not msg:
        raise HTTPException(401, f"Not authorised to edit message ID '{message_id}'")
    db.commit()

    data = MessageEditResponse.model_validate(msg).model_dump()
    await sio.emit("edit_message", data, room_path("channel", msg.channel_id))

@v1.delete("/message/{message_id}", status_code=202, response_class=Response)
async def delete_message(message_id: UlidStr, db: Database, user_id: AuthUser):
    msg = db.scalar(select(Message).where(Message.id == message_id, Message.sender_id == user_id))
    if not msg:
        raise HTTPException(401, f"Not authorised to delete message ID '{message_id}'")
    
    db.delete(msg)
    db.commit()

    await sio.emit("delete_message", msg.id, room_path("channel", msg.channel_id))

@v1.get("/channel/{channel_id}/messages", response_model=list[MessageResponse])
async def get_messages(channel_id: str, db: Database, user_id: HasChannelAccess):
    results = db.execute(select(Message, User.display_name, User.picture).join(User)
                      .where(Message.channel_id == channel_id).order_by(desc(Message.id)).limit(50)).all()
    return [MessageResponse(**message.to_dict(), display_name=display_name, picture=picture) 
        for message, display_name, picture in results]

@v1.post("/channel/{channel_id}/typing/{value}", status_code=202, response_class=Response)
async def typing(db: Database, value: Literal["start", "stop"], channel_id: str, user_id: HasChannelAccess):
    if value == "start":
        data = TypingSchema(user_id=user_id, display_name=get_display_name(db, user_id)).model_dump()
    else:
        data = user_id
    await sio.emit(f"{value}_typing", data, room_path("channel", channel_id))

@v1.post("/upload/attachment", response_class=Response)
async def upload_attachment(attachment: UploadFile, user_id: AuthUser):
    MAX_SIZE = 16 * 1024 * 1024 # 16 mb
    if not attachment.filename or not attachment.size:
        raise HTTPException(422, "No filename or content length provided")
    if attachment.size > MAX_SIZE:
        raise HTTPException(413, f"Exceeding max upload limit of '{MAX_SIZE/1024/1024}' mb")

    temp_path = FilePath(f"public/attachments/temp/{os.urandom(16).hex()}")
    os.makedirs(os.path.dirname(temp_path), exist_ok=True)

    hash = hashlib.sha256()
    real_size: int = 0 # this is calculated in case user sends fake content-length header
    async with aiofiles.open(temp_path, "wb") as tmp:
        while chunk := await attachment.read(256 * 1024): # 256 kb chunks
            if real_size > MAX_SIZE:
                os.remove(temp_path)
                raise HTTPException(413, "Why spoof file size?")
            hash.update(chunk)
            real_size += len(chunk)
            await tmp.write(chunk)

    hash_name = hash.hexdigest()
    final_path = FilePath(f"public/attachments/{user_id}/{hash_name}_{attachment.filename}")

    os.makedirs(os.path.dirname(final_path), exist_ok=True)
    if final_path.is_file():
        os.remove(temp_path)
    else:
        shutil.move(temp_path, final_path)

app.include_router(v1)

# Svelte file handlers
if os.path.exists("./dist"): # serve svelte frontend from dist folder, if it's there
    app.mount("/", StaticFiles(directory="dist", html=True))

# Public file handlers
serve_avatars_lock = asyncio.Lock()
@app.get("/avatars/{name:path}", response_class=FileResponse)
async def serve_avatars(user_id: AuthUser, name: PictureName, size: Optional[Literal["80", "96"]] = None):
    base_dir = FilePath("public/avatars").resolve()
    original_file_path = (base_dir / name).resolve()
    headers = {"Cache-Control": "private, max-age=2592000, immutable"}

    if not size: # if requests original
        if original_file_path.is_file():
            return FileResponse(original_file_path, headers=headers)
        raise HTTPException(404)
            
    resized_file_path = (base_dir / size / name).resolve() # if requests resized
    if resized_file_path.is_file():
        return FileResponse(resized_file_path, headers=headers)
        
    if not original_file_path.is_file(): # create resized if not found
        raise HTTPException(404)
    async with serve_avatars_lock:
        if not resized_file_path.is_file():
            os.makedirs(os.path.dirname(resized_file_path), exist_ok=True)
            async with aiofiles.open(original_file_path, "rb") as img_file:
                await save_picture(await img_file.read(),f"public/avatars/{size}", (int(size), int(size)), name=name)
    return FileResponse(resized_file_path, headers=headers)