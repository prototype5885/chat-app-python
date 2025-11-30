import os
import jwt
import secrets
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from typing import Annotated, Self, Sequence
from sqlalchemy.exc import IntegrityError, NoResultFound
from ulid import ULID
from fastapi import APIRouter, Depends, FastAPI, Form, HTTPException,  Query, Response
from fastapi.security import APIKeyCookie
from sqlmodel import Field,  Session, SQLModel, create_engine, CHAR, func, or_, text, select, Relationship
from pydantic import BaseModel, EmailStr, model_validator
from argon2 import PasswordHasher, exceptions
from socketio import AsyncServer, ASGIApp # type: ignore
# from cachetools import TTLCache, cached

USER_LENGTH = 32
SERVER_LENGTH = 64
CHANNEL_LENGTH = 32
MESSAGE_LENGTH = 4096

ULID_LENGTH = 26
ULID_TYPE = CHAR(ULID_LENGTH) # ULID will be always 26 char

load_dotenv()
if not os.getenv("JWT_SECRET"):
    with open(".env", 'w') as f:
        JWT_SECRET = secrets.token_hex(32)
        f.write(f"JWT_SECRET={JWT_SECRET}")
        print("Generated new JWT_SECRET into .env")
else:
    JWT_SECRET = os.environ["JWT_SECRET"]
    print("Loaded JWT_SECRET from .env")

engine = create_engine("sqlite:///database.db", connect_args={"check_same_thread": False})
app = FastAPI()
password_hasher = PasswordHasher()


def gen_id() -> str:
    ulid = str(ULID())
    if len(ulid) != ULID_LENGTH:
        raise Exception(f"generated ULID {ulid} should contain exactly {ULID_LENGTH} characters, but is {len(ulid)}")
    return ulid

# ttl_cache = TTLCache(maxsize=1024, ttl=900)
   

# class ULIDType(TypeDecorator):
#     impl = CHAR
#     cache_ok = True

#     def load_dialect_impl(self, dialect: Dialect):
#         return dialect.type_descriptor(CHAR(26))  # ULID will be always 26 char

#     def process_bind_param(self, value, dialect: Dialect) -> str:
#         return str(value)

#     def process_result_value(self, value, dialect: Dialect) -> ULID:
#         return ULID.from_str(value)

# models:
class User(SQLModel, table=True):
    id: str = Field(primary_key=True, sa_type=ULID_TYPE)
    username: str = Field(index=True, unique=True)
    email: str = Field(index=True, unique=True)
    display_name: str | None = Field(default=None)
    picture: str | None = Field(default=None)
    password: str = Field()
    banned: bool = Field(default=False)

    servers: list["Server"] = Relationship(back_populates="user", cascade_delete=True)
    messages: list["Message"] = Relationship(back_populates="user", cascade_delete=True)

class Server(SQLModel, table=True):
    id: str = Field(primary_key=True, sa_type=ULID_TYPE)
    owner_id: str = Field(foreign_key="user.id", ondelete="CASCADE", sa_type=ULID_TYPE)
    name: str = Field(max_length=SERVER_LENGTH)
    picture: str | None = Field(default=None)
    roles: str | None = Field(default=None)

    user: User = Relationship(back_populates="servers")
    channels: list["Channel"] = Relationship(back_populates="server", cascade_delete=True)

class Channel(SQLModel, table=True):
    id: str = Field(primary_key=True, sa_type=ULID_TYPE)
    server_id: str = Field(foreign_key="server.id", ondelete="CASCADE", sa_type=ULID_TYPE)
    name: str = Field(max_length=CHANNEL_LENGTH)
    # private: bool = Field(default=False)
    # allowed_roles: str | None = Field(default=None)
    # allowed_users: str | None = Field(default=None)

    server: Server = Relationship(back_populates="channels")
    messages: list["Message"] = Relationship(back_populates="channel", cascade_delete=True)

class Message(SQLModel, table=True):
    id: str = Field(primary_key=True, sa_type=ULID_TYPE)
    sender_id: str = Field(foreign_key="user.id", ondelete="CASCADE", sa_type=ULID_TYPE)
    channel_id: str = Field(foreign_key="channel.id", ondelete="CASCADE", sa_type=ULID_TYPE)
    message: str = Field(max_length=MESSAGE_LENGTH)

    channel: Channel = Relationship(back_populates="messages")
    user: User = Relationship(back_populates="messages")

class Server_Member(SQLModel, table=True):
    server_id: str = Field(foreign_key="server.id", primary_key=True, ondelete="CASCADE", sa_type=ULID_TYPE, index=True)
    member_id: str = Field(foreign_key="user.id", primary_key=True, ondelete="CASCADE", sa_type=ULID_TYPE, index=True)
    member_since: datetime = Field(sa_column_kwargs={"server_default": func.now()})

# DTOs:
class UserRegisterRequest(BaseModel):
    user_name: str = Field(min_length=6, max_length=USER_LENGTH)
    email: EmailStr
    password: str = Field(min_length=6, max_length=1024)
    password_repeat: str = Field(min_length=6, max_length=1024)

    @model_validator(mode="after")
    def check_passwords_match(self) -> Self:
        if self.password != self.password_repeat:
            raise ValueError("passwords do not match")
        return self

class UserLoginRequest(BaseModel):
    email: str
    password: str

class MessageCreateRequest(BaseModel):
    message: str = Field(max_length=MESSAGE_LENGTH)


# middlewares:
def get_session():
    with Session(engine) as session:
        yield session

# @cached(cache=ttl_cache, key=lambda db, token: (token))
def auth_user(db: Database, token: str = Depends(APIKeyCookie(name="token"))) -> str:
    try:
        jwt_payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except:
        raise HTTPException(401, "error decoding jwt")
    
    user_id = jwt_payload.get("user_id")
    if not isinstance(user_id, str):
        raise HTTPException(401, "error getting user_id from jwt")

    try:
        banned = db.exec(select(User.banned).where(User.id == user_id)).one()
    except NoResultFound:
        raise HTTPException(401, "user doesn't exist")
    
    if banned:
        raise HTTPException(401, "user is banned")

    return user_id

def is_server_owner(db: Database, server_id: str, user_id: AuthUser) -> str:
    owner_id = db.exec(select(Server.owner_id).where(Server.id == server_id and Server.owner_id == user_id)).one_or_none()
    if not owner_id:
        raise HTTPException(401, f"not owner of server ID {server_id}")

    return user_id

def is_server_member(db: Database, server_id: str, user_id: AuthUser) -> str:
    result = db.exec(select(Server.owner_id, Server_Member.member_id).where(Server.id == server_id)
                    .join(Server_Member, isouter=True)
                    .where(or_(Server.owner_id == user_id,Server_Member.member_id == user_id))
                    .distinct()).one_or_none()
    if not result:
        raise HTTPException(401, f"not member or owner of server ID {server_id}")
    return user_id

def is_in_permitted_role(db: Database, channel_id: str, user_id: AuthUser) -> str:
    return user_id

Database = Annotated[Session, Depends(get_session)]
AuthUser = Annotated[str, Depends(auth_user)]
IsServerOwner = Annotated[str, Depends(is_server_owner)]
IsServerMember = Annotated[str, Depends(is_server_member)]
IsInPermittedRole = Annotated[str, Depends(is_in_permitted_role)]

# socket.io
sio = AsyncServer(cors_allowed_origins='*',async_mode='asgi')
socket_app = ASGIApp(sio)
app.mount("/sio", socket_app)

@sio.on("connect") # type: ignore
async def connect(sid, env):
    print("New Client Connected to This id :"+" "+str(sid))
@sio.on("disconnect") # type: ignore
async def disconnect(sid):
    print("Client Disconnected: "+" "+str(sid))

# FastAPI paths
@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)
    with engine.connect() as db:
        queries = ["PRAGMA foreign_keys=ON"] # running this for sqlite
        # queries.extend(["PRAGMA journal_mode=WAL", "PRAGMA synchronous=NORMAL"])
        for query in queries:
            db.execute(text(query))

v1 = APIRouter(prefix="/api/v1")

@v1.post("/user/register")
def register_user(req: Annotated[UserRegisterRequest, Form()], db: Database) -> Response:
    try:
        db.add(User(id=gen_id(), email=req.email, username=req.user_name, password=password_hasher.hash(req.password)))
        db.commit()
    except IntegrityError:
        raise HTTPException(409, "email or username already exists")
    return Response(status_code=201)

@v1.post("/user/login")
def login_user(req: Annotated[UserLoginRequest, Form()], db: Database) -> Response:
    user = db.exec(select(User).where(User.email == req.email)).one()
    if not user:
        raise HTTPException(401, "email not found")
    
    try:
        password_hasher.verify(user.password, req.password)
    except exceptions.VerifyMismatchError:
        raise HTTPException(401, "wrong password")

    days: int = 14
    expires = datetime.now(timezone.utc) + timedelta(days=days)
    encoded_jwt = jwt.encode({"user_id": str(user.id), "exp": expires}, JWT_SECRET, algorithm="HS256")

    response = Response(status_code=200)
    response.set_cookie(key="token", value=encoded_jwt, httponly=True, secure=True, samesite="lax", max_age=days * 24 * 3600)
    return response


@v1.get("/test")
def test():
    return "Hello world!"

@v1.get("/test_auth")
def test_auth(user_id: AuthUser):
    return user_id

@v1.post("/server")
def create_server(name: Annotated[str, Query(min_length=1, max_length=SERVER_LENGTH)], db: Database, user_id: AuthUser) -> Response:
    db.add(Server(id=gen_id(), owner_id=user_id, name=name))
    db.commit()
    return Response(status_code=201)

@v1.get("/server")
def get_servers(db: Database, user_id: AuthUser) -> Sequence[Server]:
    return db.exec(select(Server).join(Server_Member, isouter=True).where(or_(Server.owner_id == user_id, Server_Member.member_id == user_id)).distinct()).all()

@v1.delete("/server")
async def delete_server(server_id: str, db: Database, user_id: AuthUser) -> Response:
    server = db.exec(select(Server).where(Server.id == server_id and Server.owner_id == user_id)).one()
    if not server:
        raise HTTPException(404)
    db.delete(server)
    db.commit()
    
    return Response(status_code=202)

@v1.post("/channel")
async def create_channel(server_id: str, name: Annotated[str, Query(min_length=1, max_length=CHANNEL_LENGTH)], db: Database, user_id: IsServerOwner) -> Response:
    channel = Channel(id=gen_id(), server_id=server_id, name=name)
    db.add(channel)
    db.commit()

    return Response(status_code=202)

@v1.get("/channel")
def get_channels(server_id: str, db: Database, user_id: IsServerMember) -> Sequence[Channel]:
    return db.exec(select(Channel).where(Channel.server_id == server_id)).all()

@v1.delete("/channel")
def delete_channel(server_id: str, channel_id: str, db: Database, user_id: IsServerOwner) -> Response:
    channel = db.exec(select(Channel).where(Channel.id == channel_id and Channel.server_id == server_id)).one()
    if not channel:
        raise HTTPException(404)
    db.delete(channel)
    db.commit()

    return Response(status_code=202)

@v1.post("/message")
async def create_message(req: MessageCreateRequest, channel_id: str, db: Database, user_id: IsServerMember) -> Response:
    message = Message(id=gen_id(), sender_id=user_id, channel_id=channel_id, message=req.message)
    db.add(message)
    db.commit()
    db.refresh(message)

    display_name, picture = db.exec(select(User.display_name, User.picture).where(User.id == user_id)).one()

    await sio.emit(f"message_created:{channel_id}", {**message.model_dump(), "display_name": display_name, "picture": picture})
    return Response(status_code=202)

@v1.get("/message")
def get_messages(channel_id: str, db: Database, user_id: IsServerMember):
    results = db.exec(select(Message, User.display_name, User.picture).join(User).where(Message.channel_id == channel_id)).all()
    if results == None:
        raise HTTPException(404)
    
    messages = []
    for message, display_name, picture in results:
        message_data = {**message.__dict__, "display_name": display_name, "picture": picture}
        messages.append(message_data)
        
    return messages
    
@v1.delete("/message")
def delete_message(message_id: str, db: Database, user_id: AuthUser) -> Response:
    message = db.exec(select(Message).where(Message.id == message_id and Message.sender_id == user_id)).one()
    if not message:
        raise HTTPException(404)
    db.delete(message)
    db.commit()

    return Response(status_code=202)

app.include_router(v1)