from contextlib import asynccontextmanager
import os
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import jwt
import secrets
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Dict, Literal, Self, Sequence
from ulid import ULID
from fastapi import APIRouter, Depends, FastAPI, Form, HTTPException, Query, Request, Response, Header
from fastapi.security import APIKeyCookie
from sqlalchemy import Engine, event
from sqlalchemy.exc import IntegrityError, NoResultFound
from sqlmodel import Field,  Session, SQLModel, create_engine, CHAR, desc, func, or_, text, select, update, Relationship
from pydantic import BaseModel, EmailStr, model_validator
from argon2 import PasswordHasher, exceptions
from socketio import AsyncServer, ASGIApp # type: ignore

load_dotenv()
if not os.getenv("JWT_SECRET"):
    with open(".env", 'w') as f:
        JWT_SECRET = secrets.token_hex(32)
        f.write(f"JWT_SECRET={JWT_SECRET}")
        print("Generated new JWT_SECRET into .env")
else:
    JWT_SECRET = os.environ["JWT_SECRET"]
    print("Loaded JWT_SECRET from .env")

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

@asynccontextmanager
async def lifespan(app: FastAPI): # runs on start or before shutdown
    SQLModel.metadata.create_all(engine)
    if engine.url.drivername == "sqlite":
        with engine.connect() as db:
            db.execute(text("PRAGMA journal_mode=WAL;"))
    yield
    # code after yield runs before shutdown

app = FastAPI(lifespan=lifespan)
password_hasher = PasswordHasher()

# socket.io
sio = AsyncServer(cors_allowed_origins='*',async_mode='asgi')
app.mount("/socket.io", ASGIApp(socketio_server=sio, other_asgi_app=app))
   
# types
RoomType = Literal["server", "channel"]

# field kwargs
Kwargs = Dict[str, Any]
ULID_KW: Kwargs = {"min_length": 26, "max_length": 26, "sa_type": CHAR(26)}
USERNAME_KW: Kwargs = {"min_length": 6, "max_length": 32}
DISPLAY_NAME_KW: Kwargs = {"min_length": 1, "max_length": 64}
PASSWORD_KW: Kwargs = {"min_length": 6, "max_length": 1024}
SERVER_NAME_KW: Kwargs = {"min_length": 1, "max_length": 64}
CHANNEL_NAME_KW: Kwargs = {"min_length": 1, "max_length": 32}
MESSAGE_KW: Kwargs = {"min_length": 1, "max_length": 4096}

# models:
class User(SQLModel, table=True):
    id: str = Field(primary_key=True, **ULID_KW)
    username: str = Field(index=True, unique=True, **USERNAME_KW)
    email: str = Field(index=True, unique=True)
    display_name: str = Field(**DISPLAY_NAME_KW)
    picture: str | None = Field(default=None)
    password: str
    banned: bool = Field(default=False)

    servers: list["Server"] = Relationship(back_populates="user", cascade_delete=True)
    messages: list["Message"] = Relationship(back_populates="user", cascade_delete=True)

class Server(SQLModel, table=True):
    id: str = Field(primary_key=True, **ULID_KW)
    owner_id: str = Field(foreign_key="user.id", ondelete="CASCADE", **ULID_KW)
    name: str = Field(**SERVER_NAME_KW)
    picture: str | None = Field(default=None)
    roles: str | None = Field(default=None)

    user: User = Relationship(back_populates="servers")
    channels: list["Channel"] = Relationship(back_populates="server", cascade_delete=True)

class Channel(SQLModel, table=True):
    id: str = Field(primary_key=True, **ULID_KW)
    server_id: str = Field(foreign_key="server.id", ondelete="CASCADE", **ULID_KW)
    name: str = Field(**CHANNEL_NAME_KW)
    # private: bool = Field(default=False)
    # allowed_roles: str | None = Field(default=None)
    # allowed_users: str | None = Field(default=None)

    server: Server = Relationship(back_populates="channels")
    messages: list["Message"] = Relationship(back_populates="channel", cascade_delete=True)

class Message(SQLModel, table=True):
    id: str = Field(primary_key=True, **ULID_KW)
    sender_id: str = Field(foreign_key="user.id", ondelete="CASCADE", **ULID_KW)
    channel_id: str = Field(foreign_key="channel.id", ondelete="CASCADE", **ULID_KW)
    message: str = Field(**MESSAGE_KW)

    channel: Channel = Relationship(back_populates="messages")
    user: User = Relationship(back_populates="messages")

class Server_Member(SQLModel, table=True):
    server_id: str = Field(foreign_key="server.id", primary_key=True, ondelete="CASCADE", **ULID_KW, index=True)
    member_id: str = Field(foreign_key="user.id", primary_key=True, ondelete="CASCADE", **ULID_KW, index=True)
    member_since: datetime = Field(sa_column_kwargs={"server_default": func.now()})

# DTOs:
class UserRegisterRequest(BaseModel):
    username: str = Field(**USERNAME_KW)
    email: EmailStr
    password: str = Field(**PASSWORD_KW)
    password_repeat: str = Field(**PASSWORD_KW)

    @model_validator(mode="after")
    def check_passwords_match(self) -> Self:
        if self.password != self.password_repeat:
            raise ValueError("passwords do not match")
        return self

class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(**PASSWORD_KW)

class MessageCreateRequest(BaseModel):
    message: str = Field(**MESSAGE_KW)

class UserUpdateRequest(BaseModel):
    display_name: str = Field(**DISPLAY_NAME_KW)

# middlewares:
def get_session():
    with Session(engine, expire_on_commit=False) as session:
        yield session

def auth_user(db: Database, token: str = Depends(APIKeyCookie(name="token"))) -> str:
    try:
        jwt_payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except:
        raise HTTPException(401, "Error decoding jwt")
    
    user_id = jwt_payload.get("user_id")
    if not isinstance(user_id, str):
        raise HTTPException(401, "Error getting user_id from jwt")

    try:
        banned = db.exec(select(User.banned).where(User.id == user_id)).one()
    except NoResultFound:
        raise HTTPException(401, "User id from jwt doesn't exist in database")
    
    if banned:
        raise HTTPException(401, "User is banned")

    return user_id

def is_server_owner(db: Database, server_id: str, user_id: AuthUser) -> str:
    owner_id = db.exec(select(Server.owner_id).where(Server.id == server_id and Server.owner_id == user_id)).one_or_none()
    if not owner_id:
        raise HTTPException(401, "Not owner of server, which may not even exist")

    return user_id

def is_server_member(db: Database, server_id: str, user_id: AuthUser) -> str:
    result = db.exec(select(Server.owner_id, Server_Member.member_id).where(Server.id == server_id)
                    .join(Server_Member, isouter=True)
                    .where(or_(Server.owner_id == user_id, Server_Member.member_id == user_id))
                    .distinct()).one_or_none()
    if not result:
        raise HTTPException(401, "Not member or owner of server, which may not even exist")
    return user_id

def is_in_permitted_role(db: Database, channel_id: str, user_id: AuthUser) -> str:
    return user_id

async def socket_io_id(sid: Annotated[str | None, Header()] = None, token: str = Depends(APIKeyCookie(name="token"))):
    if sid is None:
        raise HTTPException(400, "No header with name 'Sid' found")
    try:
        session = await sio.get_session(sid)
    except:
        raise HTTPException(401, "No Socket.IO session is associated with received sid")
    if session.get("token") != token:
        raise HTTPException(401, "Received token and token associated with received sid don't match")
    return sid

Database = Annotated[Session, Depends(get_session)]
AuthUser = Annotated[str, Depends(auth_user)]
IsServerOwner = Annotated[str, Depends(is_server_owner)]
IsServerMember = Annotated[str, Depends(is_server_member)]
IsInPermittedRole = Annotated[str, Depends(is_in_permitted_role)]
Sid = Annotated[str, Depends(socket_io_id)]

# macros
def room_path(room_type: RoomType, id: str):
    return f"{room_type}:{id}"

async def enter_room(sid: str, room_type: RoomType, to_enter: str):
    for room in sio.rooms(sid):
        if room.startswith(room_type):
            await sio.leave_room(sid, room)
            print(f"sid: {sid} left room: {room}")
            break

    room = room_path(room_type, to_enter)
    await sio.enter_room(sid, room)
    print(f"sid: {sid} joined room: {room}")

def gen_id() -> str:
    ulid = str(ULID())
    if len(ulid) != 26:
        raise Exception(f"generated ULID {ulid} should contain exactly 26 characters, but is {len(ulid)}")
    return ulid

# socket.io paths
@sio.event
async def connect(sid, env):
    with Session(engine) as session:
        try:
            token: str = env["HTTP_COOKIE"].split('token=', 1)[1]
            user_id = auth_user(session, env["HTTP_COOKIE"].split('token=', 1)[1])
        except:
            raise ConnectionRefusedError('authentication failed')

    await sio.save_session(sid, {"token": token})
    print(f"Socket connected: {sid} with token: {token}")

@sio.event
async def disconnect(sid, reason):
    print(f"Client Disconnected: {sid}, reason: {reason}")

# FastAPI paths
v1 = APIRouter(prefix="/api/v1")

@v1.post("/user/register")
def register_user(req: Annotated[UserRegisterRequest, Form()], db: Database) -> Response:
    try:
        user = User(id=gen_id(), email=req.email, username=req.username, display_name=req.username, 
                    password=password_hasher.hash(req.password))
        db.add(user); db.commit()
    except IntegrityError:
        raise HTTPException(409)
    
    return Response(status_code=303, headers={"Location": "/login"})

@v1.post("/user/login")
def login_user(req: Annotated[UserLoginRequest, Form()], db: Database) -> Response:
    user = db.exec(select(User).where(User.email == req.email)).one_or_none()
    if not user:
        raise HTTPException(401)
    
    try:
        password_hasher.verify(user.password, req.password)
    except exceptions.VerifyMismatchError:
        raise HTTPException(401)

    days: int = 14
    expires = datetime.now(timezone.utc) + timedelta(days=days)
    encoded_jwt = jwt.encode({"user_id": str(user.id), "exp": expires}, JWT_SECRET, algorithm="HS256")

    response = Response(status_code=303, headers={"Location": "/"})
    response.set_cookie(key="token", value=encoded_jwt, httponly=True, secure=True, samesite="lax", max_age=days * 24 * 3600)
    return response

@v1.get("/user/logout")
def logout_user() -> Response:
    response = Response(status_code=303, headers={"Location": "/login"})
    response.delete_cookie(key="token")
    return response

@v1.get("/test")
def test() -> str:
    return "Hello world!"

@v1.get("/test_auth")
def test_auth(user_id: AuthUser) -> str:
    return user_id

@v1.get("/user")
def get_user_info(db: Database, user_id: AuthUser) -> dict:
    display_name, picture = db.exec(select(User.display_name, User.picture).where(User.id == user_id)).one()
    return {"id": user_id, "display_name": display_name, "picture": picture}

@v1.patch("/user")
def update_user_info(req: Annotated[UserUpdateRequest, Form()], db: Database, user_id: AuthUser) -> dict:
    values = req.model_dump()
    db.exec(update(User).where(User.id == user_id).values(values)); db.commit() # pyright: ignore[reportArgumentType]
    return values

@v1.post("/server")
def create_server(name: Annotated[str, Query(**SERVER_NAME_KW)], db: Database, user_id: AuthUser) -> Server:
    server_id = gen_id()
    server = Server(id=server_id, owner_id=user_id, name=name)
    db.add(server)
    db.add(Channel(id=gen_id(), server_id=server_id, name="Default channel"))
    db.commit()
    return server

@v1.get("/server")
def get_servers(db: Database, user_id: AuthUser) -> Sequence[Server]:
    return db.exec(select(Server).join(Server_Member, isouter=True)
                   .where(or_(Server.owner_id == user_id, Server_Member.member_id == user_id)).distinct()).all()

@v1.delete("/server")
async def delete_server(server_id: str, db: Database, user_id: AuthUser) -> Response:
    server = db.exec(select(Server).where(Server.id == server_id and Server.owner_id == user_id)).one_or_none()
    if not server:
        raise HTTPException(401)
    
    db.delete(server); db.commit()
    
    await sio.emit("delete_server", server_id, room_path("server", server_id))
    return Response(status_code=202)

@v1.post("/channel")
async def create_channel(server_id: str, name: Annotated[str, Query(**CHANNEL_NAME_KW)], db: Database, user_id: IsServerOwner) -> Response:
    channel = Channel(id=gen_id(), server_id=server_id, name=name)
    channel_dict = channel.model_dump()
    db.add(channel); db.commit()

    await sio.emit("create_channel", channel_dict, room_path("server", server_id))
    return Response(status_code=202)

@v1.get("/channel")
async def get_channels(server_id: str, db: Database, user_id: IsServerMember, sid: Sid) -> Sequence[Channel]:
    channels = db.exec(select(Channel).where(Channel.server_id == server_id)).all()
    await enter_room(sid, "server", server_id)
    return channels

@v1.delete("/channel")
async def delete_channel(server_id: str, channel_id: str, db: Database, user_id: IsServerOwner) -> Response:
    channel = db.exec(select(Channel).where(Channel.id == channel_id and Channel.server_id == server_id)).one_or_none()
    if not channel:
        raise HTTPException(401)
    
    db.delete(channel); db.commit()

    await sio.emit("delete_channel", channel_id, room_path("server", server_id))
    return Response(status_code=202)

@v1.post("/message")
async def create_message(req: MessageCreateRequest, channel_id: str, db: Database, user_id: IsServerMember) -> Response:
    message = Message(id=gen_id(), sender_id=user_id, channel_id=channel_id, message=req.message)
    db.add(message); db.commit()

    display_name, picture = db.exec(select(User.display_name, User.picture).where(User.id == user_id)).one()

    data = {**message.model_dump(), "display_name": display_name, "picture": picture}
    await sio.emit("create_message", data, room_path("channel", channel_id))
    return Response(status_code=202)

@v1.get("/message")
async def get_messages(channel_id: str, db: Database, user_id: IsServerMember, sid: Sid) -> list:
    results = db.exec(select(Message, User.display_name, User.picture).join(User)
                      .where(Message.channel_id == channel_id).order_by(desc(Message.id)).limit(50)).all()
    
    await enter_room(sid, "channel", channel_id)

    return [{**message.model_dump(), "display_name": display_name, "picture": picture} 
            for message, display_name, picture in results]

@v1.delete("/message")
async def delete_message(message_id: str, db: Database, user_id: AuthUser) -> Response:
    message = db.exec(select(Message).where(Message.id == message_id and Message.sender_id == user_id)).one_or_none()
    if not message:
        raise HTTPException(401)
    
    db.delete(message); db.commit()

    await sio.emit("delete_message", message.id, room_path("channel", message.channel_id))
    return Response(status_code=202)

@v1.post("/typing")
async def typing(value: Literal["start", "stop"], channel_id: str, user_id: IsServerMember):
    await sio.emit(f"{value}_typing", user_id, room_path("channel", channel_id))

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
