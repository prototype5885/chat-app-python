from contextlib import asynccontextmanager
import os
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
import jwt
import secrets
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Dict, List, Literal, Optional
from ulid import ULID
from fastapi import APIRouter, Depends, FastAPI, Form, HTTPException, Query, Request, Response
from fastapi.security import APIKeyCookie
from sqlalchemy import CHAR, Boolean, DateTime, Engine, ForeignKey, String, create_engine, desc, event, exists, func, or_, select, text, union, update
from sqlalchemy.exc import IntegrityError, NoResultFound
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, Session
from pydantic import BaseModel, EmailStr, Field, model_validator
from argon2 import PasswordHasher, exceptions
from socketio import AsyncServer, ASGIApp

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

# field kwargs
Kwargs = Dict[str, Any]
USERNAME_KW: Kwargs = {"min_length": 6, "max_length": 32}
DISPLAY_NAME_KW: Kwargs = {"min_length": 1, "max_length": 64}
PASSWORD_KW: Kwargs = {"min_length": 6, "max_length": 1024} 
SERVER_NAME_KW: Kwargs = {"min_length": 1, "max_length": 64}
CHANNEL_NAME_KW: Kwargs = {"min_length": 1, "max_length": 32}
MESSAGE_KW: Kwargs = {"min_length": 1, "max_length": 4096}


# SQLAlchemy models:
class Base(DeclarativeBase):
    def to_dict(self):
        return {field.name:getattr(self, field.name) for field in self.__table__.c}
    
class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(CHAR(26), primary_key=True)
    username: Mapped[str] = mapped_column(index=True, unique=True)
    email: Mapped[str] = mapped_column(index=True, unique=True)
    display_name: Mapped[str]
    picture: Mapped[Optional[str]]
    password: Mapped[str]
    banned: Mapped[bool] = mapped_column(Boolean, default=False)
    
    servers: Mapped[List["Server"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    messages: Mapped[List["Message"]] = relationship(back_populates="user", cascade="all, delete-orphan")

class Server(Base):
    __tablename__ = "servers"
    id: Mapped[str] = mapped_column(CHAR(26), primary_key=True)
    owner_id: Mapped[str] = mapped_column(CHAR(26), ForeignKey("users.id", ondelete="CASCADE"))
    name: Mapped[str]
    picture: Mapped[Optional[str]]
    banner: Mapped[Optional[str]]
    roles: Mapped[Optional[str]]
    
    user: Mapped["User"] = relationship(back_populates="servers")
    channels: Mapped[List["Channel"]] = relationship(back_populates="server", cascade="all, delete-orphan")
    members: Mapped[List["Server_Member"]] = relationship(back_populates="server", cascade="all, delete-orphan")

class Channel(Base):
    __tablename__ = "channels"
    id: Mapped[str] = mapped_column(CHAR(26), primary_key=True)
    server_id: Mapped[str] = mapped_column(String, ForeignKey("servers.id", ondelete="CASCADE"))
    name: Mapped[str]
    # private: Mapped[bool] = mapped_column(Boolean, default=False)
    # allowed_roles: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # allowed_users: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    
    server: Mapped["Server"] = relationship(back_populates="channels")
    messages: Mapped[List["Message"]] = relationship(back_populates="channel", cascade="all, delete-orphan")

class Message(Base):
    __tablename__ = "messages"
    id: Mapped[str] = mapped_column(CHAR(26), primary_key=True)
    sender_id: Mapped[str] = mapped_column(CHAR(26), ForeignKey("users.id", ondelete="CASCADE"))
    channel_id: Mapped[str] = mapped_column(CHAR(26), ForeignKey("channels.id", ondelete="CASCADE"))
    message: Mapped[str] = mapped_column(String(4096))
    attachments: Mapped[Optional[str]] = mapped_column(default=None)
    edited: Mapped[Optional[bool]] = mapped_column(default=None)
    
    channel: Mapped["Channel"] = relationship(back_populates="messages")
    user: Mapped["User"] = relationship(back_populates="messages")

class Server_Member(Base):
    __tablename__ = "server_members"
    server_id: Mapped[str] = mapped_column(CHAR(26), ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True, index=True)
    member_id: Mapped[str] = mapped_column(CHAR(26), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True)
    member_since: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    server: Mapped["Server"] = relationship(back_populates="members")

# Pydantic models:
class UserRegisterRequest(BaseModel):
    username: str = Field(**USERNAME_KW)
    email: EmailStr
    password: str = Field(**PASSWORD_KW)
    password_repeat: str = Field(**PASSWORD_KW)

    @model_validator(mode="after")
    def check_passwords_match(self):
        if self.password != self.password_repeat:
            raise ValueError("passwords do not match")
        return self

class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(**PASSWORD_KW)

class MessageCreateRequest(BaseModel):
    message: str = Field(**MESSAGE_KW)

class UpdateUserInfoRequest(BaseModel):
    display_name: Optional[str] = Field(**DISPLAY_NAME_KW)
    picture: Optional[str] = None


# Macros
def room_path(room_type: Literal["server", "channel"], id: str):
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

engine = create_engine(url=db_url, connect_args=connect_args, echo=True)

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
async def enter_room(sid: str, server_id: str, channel_id: str, room_type: str):
    sio_session = await sio.get_session(sid)
    user_id: str | None = sio_session.get("user_id")
    if user_id is None:
        raise Exception(f"sid '{sid}' is supposed to have a user_id value, but returned None")
    
    with Session(engine) as session:
        try: 
            is_server_member(session, server_id, user_id)
        except Exception as e: 
            await sio.emit("exception", str(e), to=sid)

    for room in sio.rooms(sid): # leave previous room of same type
        if room.startswith(room_type):
            await sio.leave_room(sid, room)
            print(f"sid: {sid} left room: {room}")
            break

    if room_type == "server": 
        to_enter = server_id
    elif room_type == "channel": 
        to_enter = channel_id
    else:
        await sio.emit("exception", f"Wrong room type received: '{room_type}'", to=sid)
        return

    room = room_path(room_type, to_enter)
    await sio.enter_room(sid, room)
    print(f"sid: {sid} entered room: {room}")


# middlewares:
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

    try:
        banned = db.execute(select(User.banned).where(User.id == user_id)).scalar_one()
    except NoResultFound:
        raise HTTPException(401, "User id from jwt doesn't exist in database")
    
    if banned:
        raise HTTPException(401, "User is banned")

    return user_id
AuthUser = Annotated[str, Depends(auth_user)]

def is_server_owner(db: Database, server_id: str, user_id: AuthUser):
    owner_id = db.scalar(select(Server.owner_id).where(Server.id == server_id, Server.owner_id == user_id))
    if not owner_id:
        raise HTTPException(401, "Not owner of server, which may not even exist")

    return user_id
IsServerOwner = Annotated[str, Depends(is_server_owner)]

def is_server_member(db: Database, server_id: str, user_id: AuthUser):
    is_owner = exists().where(Server.id == server_id, Server.owner_id == user_id)
    is_member = exists().where(Server_Member.server_id == server_id, Server_Member.member_id == user_id)
    result = db.execute(select(is_owner | is_member)).scalar()
    if not result:
        raise HTTPException(401, "Not member or owner of server, which may not even exist")
    return user_id
IsServerMember = Annotated[str, Depends(is_server_member)]

def is_in_permitted_role(db: Database, channel_id: str, user_id: AuthUser):
    return user_id
IsInPermittedRole = Annotated[str, Depends(is_in_permitted_role)]


# FastAPI
v1 = APIRouter(prefix="/api/v1")

@v1.post("/user/register")
def register_user(req: Annotated[UserRegisterRequest, Form()], db: Database):
    try:
        user = User(id=str(ULID()), email=req.email, username=req.username, display_name=req.username, 
                    password=password_hasher.hash(req.password))
        db.add(user); db.commit()
    except IntegrityError:
        raise HTTPException(409)

@v1.post("/user/login")
def login_user(req: Annotated[UserLoginRequest, Form()], db: Database):
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

    response = Response()
    response.set_cookie(key="token", value=encoded_jwt, httponly=True, secure=True, samesite="lax", max_age=days * 24 * 3600)
    return response

@v1.get("/user/logout")
def logout_user():
    response = Response()
    response.delete_cookie(key="token")
    return response

@v1.get("/test", response_class=PlainTextResponse)
def test():
    return "Hello world!"

@v1.get("/test_auth", response_class=PlainTextResponse)
def test_auth(user_id: AuthUser):
    return user_id

@v1.get("/user")
def get_user_info(db: Database, user_id: AuthUser):
    display_name, picture = db.execute(select(User.display_name, User.picture).where(User.id == user_id)).one()
    return {"id": user_id, "display_name": display_name, "picture": picture}

@v1.patch("/user")
def update_user_info(req: Annotated[UpdateUserInfoRequest, Form()], db: Database, user_id: AuthUser):
    values = req.model_dump()
    db.execute(update(User).where(User.id == user_id).values(values)); db.commit()
    return values

@v1.post("/server")
def create_server(name: Annotated[str, Query(**SERVER_NAME_KW)], db: Database, user_id: AuthUser):
    server = Server(id=str(ULID()), owner_id=user_id, name=name)
    db.add(server)
    db.add(Channel(id=str(ULID()), server_id=server.id, name="Default channel"))
    db.commit()
    db.refresh(server)
    return server

@v1.get("/server")
def get_servers(db: Database, user_id: AuthUser):
    return db.scalars(select(Server).where(
        or_(Server.owner_id == user_id, Server.members.any(Server_Member.member_id == user_id)))).all()

@v1.delete("/server", status_code=202, response_class=Response)
async def delete_server(server_id: str, db: Database, user_id: AuthUser):
    server = db.execute(select(Server).where(Server.id == server_id, Server.owner_id == user_id)).scalar_one_or_none()
    if not server:
        raise HTTPException(401)
    
    db.delete(server); db.commit()
    
    await sio.emit("delete_server", server_id, room_path("server", server_id))

@v1.post("/channel", status_code=202, response_class=Response)
async def create_channel(server_id: str, name: Annotated[str, Query(**CHANNEL_NAME_KW)], db: Database, user_id: IsServerOwner):
    channel = Channel(id=str(ULID()), server_id=server_id, name=name)
    db.add(channel); db.commit()

    await sio.emit("create_channel", channel.to_dict(), room_path("server", server_id))

@v1.get("/channel")
async def get_channels(server_id: str, db: Database, user_id: IsServerMember):
    channels = db.scalars(select(Channel).where(Channel.server_id == server_id)).all()
    return channels

@v1.delete("/channel", status_code=202, response_class=Response)
async def delete_channel(server_id: str, channel_id: str, db: Database, user_id: IsServerOwner):
    channel = db.execute(select(Channel).where(Channel.id == channel_id, Channel.server_id == server_id)).scalar_one_or_none()
    if not channel:
        raise HTTPException(401)
    
    db.delete(channel); db.commit()

    await sio.emit("delete_channel", channel_id, room_path("server", server_id))

@v1.get("/member")
def get_members(server_id: str, db: Database, _: IsServerMember):
    owner_stmt = (select(User.id, User.display_name, User.picture).join(Server, Server.owner_id == User.id)
                  .where(Server.id == server_id))
    member_stmt = (select(User.id, User.display_name, User.picture).join(Server_Member, Server_Member.member_id == User.id)
                   .where(Server_Member.server_id == server_id))
    rows = db.execute(union(owner_stmt, member_stmt)).all()

    return [{"user_id": user_id, "display_name": display_name, "picture": picture} 
        for user_id, display_name, picture in rows]

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
    message = db.execute(select(Message).where(Message.id == message_id, Message.sender_id == user_id)).scalar_one_or_none()
    if not message:
        raise HTTPException(401)
    
    db.delete(message); db.commit()

    await sio.emit("delete_message", message.id, room_path("channel", message.channel_id))

@v1.post("/typing", status_code=202, response_class=Response)
async def typing(db: Database, value: Literal["start", "stop"], channel_id: str, user_id: IsServerMember):
    display_name = get_display_name(db, user_id)
    await sio.emit(f"{value}_typing", display_name, room_path("channel", channel_id))

app.include_router(v1)

# static files
@app.get("/login")
def login_page():
    return FileResponse("./static/login.html")

@app.get("/register")
def register_page():
    return FileResponse("./static/register.html")

if os.path.exists("./dist"):
    app.mount("/", StaticFiles(directory="dist", html=True))

@app.exception_handler(404)
def not_found(request: Request, exc):
    response = FileResponse("./static/404.html")
    response.status_code = 404
    return response
