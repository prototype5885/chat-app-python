from contextlib import asynccontextmanager
from dataclasses import astuple, dataclass
from pathlib import Path as FilePath
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Dict, Literal, Optional
from ulid import ULID
from fastapi import APIRouter, FastAPI,  Response, UploadFile
from fastapi.param_functions import Depends, Form, Path
from fastapi.exceptions import HTTPException, WebSocketException
from fastapi.security import APIKeyCookie
from fastapi.websockets import WebSocket, WebSocketState, WebSocketDisconnect
from pydantic import AfterValidator, BaseModel, ConfigDict, EmailStr, Field, StringConstraints, model_validator
from argon2 import PasswordHasher, exceptions
from PIL import Image
import os
import io
import hashlib
import aiofiles
import jwt
import secrets
import asyncio
import bleach
import shutil
import json
import sqlite3

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

PATH_PUBLIC = "public"
PATH_AVATARS = "public/avatars"
PATH_ATTACHMENTS = "public/attachments"

password_hasher = PasswordHasher()
db: sqlite3.Connection


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


# Pydantic helpers:
def clean_text_message(v: str) -> str:
    safe_text = bleach.clean(v, protocols=['http', 'https']).strip()
    if safe_text == "":
        raise ValueError("Invalid text")
    return safe_text

# Pydantic types:
UlidStr = Annotated[str, StringConstraints(pattern=r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")]
UsernameStr = Annotated[str, Field(**USERNAME_LEN.kwargs())]
PasswordStr = Annotated[str, Field(**PASSWORD_LEN.kwargs())]
DisplayNameStr = Annotated[str, Field(**DISPLAY_NAME_LEN.kwargs())]
ServerNameStr = Annotated[str, Field(**SERVER_NAME_LEN.kwargs())]
ChannelNameStr = Annotated[str, Field(**CHANNEL_NAME_LEN.kwargs())]
MessageStr = Annotated[str, Field(**MESSAGE_LEN.kwargs()), AfterValidator(clean_text_message)]
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

class UserSchema(BaseModel):
    id: str
    username: UsernameStr
    display_name: DisplayNameStr
    picture: Optional[str] = None
    custom_status: Optional[str] = None

class UserEditRequest(BaseModel):
    display_name: Optional[DisplayNameStr] = None

class UserEditResponse(BaseModel):
    id: str
    display_name: Optional[str] = None
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
    model_config = ConfigDict(from_attributes=True)
    id: str
    message: MessageStr
    attachments: Optional[str] = None
    edited: Optional[str] = None

class MessageResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    sender_id: str
    channel_id: str
    message: MessageStr
    attachments: Optional[str] = None
    edited: Optional[str] = None
    display_name: DisplayNameStr
    picture: Optional[str] = None

# Cache
class UserCache:
    @dataclass()
    class UserCacheValue:
        display_name: str
        picture: str
        def __iter__(self):
            return iter(astuple(self))

    _cache: dict[str, UserCacheValue] = {}

    def _set_from_db(self, user_id: str):
        q = "SELECT display_name, picture FROM users WHERE id = ?"
        row = db.execute(q, (user_id,)).fetchone()
        if not row:
            self.delete(user_id)
            raise HTTPException(500)
        
        self._cache[user_id] = self.UserCacheValue(row[0], row[1])
 
    def get(self, user_id: str):
        if user_id not in self._cache:
            self._set_from_db(user_id)
        return self._cache[user_id]

    def set(self, user_id: str, display_name: str | None = None, picture: str | None = None):
        if user_id in self._cache:
            if display_name:
                self._cache[user_id].display_name = display_name
            if picture:
                self._cache[user_id].picture = picture

    def delete(self, user_id: str):
        self._cache.pop(user_id, None)

user_cache = UserCache()

# Helpers
def process_picture(file: bytes, resolution: tuple[int, int], crop_square: bool):
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
            return buffer.getvalue()
    except: 
        raise HTTPException(422, "Error processing received picture")

async def save_avatar(file: UploadFile | None, path: str, resolution: tuple[int, int], crop_square: bool):
    if not file:
        raise HTTPException(400, "No file was received")
    avatar = await file.read()
    bytes = process_picture(avatar, resolution, crop_square) 
   
    file_hash = hashlib.sha256(bytes).hexdigest()
    file_name = f"{file_hash}.webp"
    final_path = FilePath(f"{path}/{file_name}")

    os.makedirs(os.path.dirname(final_path), exist_ok=True)
    async with aiofiles.open(final_path, "wb") as f:
        await f.write(bytes)
    return file_name

async def generate_resized_picture(path: FilePath, size: int):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    async with aiofiles.open(path, "rb") as img_file:
        bytes = process_picture(await img_file.read(), (size, size), False) 

    path = FilePath(f"{path.parent}/{size}/{path.name}")

    os.makedirs(os.path.dirname(path), exist_ok=True)
    async with aiofiles.open(path, "wb") as f:
        await f.write(bytes)

def update_set_values(values: dict):
    return ", ".join([f"{column} = :{column}" for column in values.keys()])

# FastAPI setup
@asynccontextmanager
async def lifespan(app: FastAPI): # runs on start or before shutdown
    SQLITE_FILE_NAME = "database/database.db"
    os.makedirs(os.path.dirname(SQLITE_FILE_NAME), exist_ok=True)

    global db
    db = sqlite3.connect(SQLITE_FILE_NAME)
    db.row_factory = sqlite3.Row

    schema = f"""
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS users (
            id CHAR(26) PRIMARY KEY,
            username VARCHAR({USERNAME_LEN.max}) NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            display_name VARCHAR({DISPLAY_NAME_LEN.max}) NOT NULL,
            picture TEXT,
            password TEXT NOT NULL,
            banned BOOLEAN NOT NULL DEFAULT 0,
            custom_status TEXT
        );

        CREATE TABLE IF NOT EXISTS servers (
            id CHAR(26) PRIMARY KEY,
            owner_id CHAR(26) NOT NULL,
            name VARCHAR({SERVER_NAME_LEN.max}) NOT NULL,
            picture TEXT,
            banner TEXT,
            roles TEXT,
            FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS channels (
            id CHAR(26) PRIMARY KEY,
            server_id CHAR(26) NOT NULL,
            name VARCHAR({CHANNEL_NAME_LEN.max}) NOT NULL,
            FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS messages (
            id CHAR(26) PRIMARY KEY,
            sender_id CHAR(26) NOT NULL,
            channel_id CHAR(26) NOT NULL,
            message VARCHAR({MESSAGE_LEN.max}) NOT NULL,
            attachments TEXT DEFAULT NULL,
            edited TEXT DEFAULT NULL,
            FOREIGN KEY (sender_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (channel_id) REFERENCES channels (id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS server_members (
            server_id CHAR(26) NOT NULL,
            member_id CHAR(26) NOT NULL,
            member_since DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (server_id, member_id),
            FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE,
            FOREIGN KEY (member_id) REFERENCES users (id) ON DELETE CASCADE
        );
    """
    with db as tx:
        tx.executescript(schema)

    yield
    db.close()

app = FastAPI(lifespan=lifespan)


# FastAPI middlewares:
async def auth_user(token: str | None = Depends(APIKeyCookie(name="token", auto_error=False))) -> str:
    redirect_headers = {"Location": "/login.html"}
    if not token:
        raise HTTPException(303, headers=redirect_headers)
    try:
        jwt_payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except:
        raise HTTPException(303, "Error decoding jwt", headers=redirect_headers)
    
    user_id = jwt_payload.get("user_id")
    if not isinstance(user_id, str):
        raise HTTPException(303, "Error getting user_id from jwt", headers=redirect_headers)

    row = db.execute("SELECT banned FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(303, "User id from jwt doesn't exist in database", headers=redirect_headers)
    if bool(row[0]) is not False:
        raise HTTPException(303, "User is banned", headers=redirect_headers)

    return user_id
AuthUser = Annotated[str, Depends(auth_user)]

async def is_server_owner(server_id: UlidStr, user_id: AuthUser) -> str:
    q = "SELECT EXISTS(SELECT 1 FROM servers WHERE id = ? AND owner_id = ?)"
    row = db.execute(q, (server_id, user_id,)).fetchone()

    is_owner: bool = row[0] if row else False
    if not is_owner:
        raise HTTPException(403, f"You don't own server ID '{server_id}'")

    return user_id
IsServerOwner = Annotated[str, Depends(is_server_owner)]

async def has_server_access(server_id: UlidStr, user_id: AuthUser) -> str:
    q = """
        SELECT EXISTS (
            SELECT 1 FROM server_members WHERE server_id = :s_id AND member_id = :u_id
            UNION
            SELECT 1 FROM servers WHERE id = :s_id AND owner_id = :u_id
        )"""
    row = db.execute(q, {"s_id": server_id, "u_id": user_id}).fetchone()
    has_access: bool = row[0] if row else False
    if not has_access:
        raise HTTPException(403, f"You have no access to server ID '{server_id}'")

    return user_id
HasServerAccess = Annotated[str, Depends(has_server_access)]

async def is_channel_owner(channel_id: UlidStr, user_id: AuthUser) -> str:
    q = """
        SELECT EXISTS (
            SELECT 1 FROM channels 
            JOIN servers ON channels.server_id = servers.id 
            WHERE channels.id = ? AND servers.owner_id = ?
        )"""
    row = db.execute(q, (channel_id, user_id,)).fetchone()

    is_owner: bool = row[0] if row else False
    if not is_owner:
        raise HTTPException(403, f"You don't own channel ID '{channel_id}'")

    return user_id
IsChannelOwner = Annotated[str, Depends(is_channel_owner)]

async def has_channel_access(channel_id: UlidStr, user_id: AuthUser) -> str:
    q = """
        SELECT EXISTS (
            SELECT 1 FROM channels c
            JOIN servers s ON c.server_id = s.id
            LEFT JOIN server_members m ON s.id = m.server_id AND m.member_id = :u_id
            WHERE c.id = :c_id 
            AND (s.owner_id = :u_id OR m.member_id IS NOT NULL)
        )"""
    row = db.execute(q, {"c_id": channel_id, "u_id": user_id}).fetchone()

    has_access: bool = row[0] if row else False
    if not has_access:
        raise HTTPException(403, f"You have no access to channel ID '{channel_id}'")

    return user_id
HasChannelAccess = Annotated[str, Depends(has_channel_access)]


# WebSocket
class WebSocketClient:
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.server_id: str | None = None
        self.channel_id: str | None = None

SubscriptionTarget = Literal["server_list", "server", "channel"]

class WebSocketManager:
    def __init__(self):
        self.clients: dict[WebSocket, WebSocketClient] = {}

    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        self.clients[websocket] = WebSocketClient(user_id=user_id)

    async def disconnect(self, websocket: WebSocket):
        if websocket in self.clients:
            if websocket.client_state != WebSocketState.DISCONNECTED:
                try: await websocket.close()
                except: pass
            del self.clients[websocket]

    async def handle_incoming_message(self, message: str, websocket: WebSocket):
        if websocket not in self.clients:
            return

        user_id = self.clients[websocket].user_id
        event, data = message.split(" ", maxsplit=1)

        def subscribe(target_subs: SubscriptionTarget, id: str):  
            match target_subs:
                case "channel": self.clients[websocket].channel_id = id
                case "server": self.clients[websocket].server_id = id

        async def reply_exception(error: Exception):
            await websocket.send_text(f"exception error on event: '{event}', error: '{error}'")
        
        match event:
            case "subscribe_to_message_list":
                channel_id = data
                try: 
                    await has_channel_access(channel_id, user_id)
                    subscribe("channel", channel_id)
                except Exception as e: 
                    await reply_exception(e)

            case "subscribe_to_channel_list":
                server_id = data
                try: 
                    await has_server_access(server_id, user_id)
                    subscribe("server", server_id)
                except Exception as e: 
                    await reply_exception(e)
    
    async def emit(self, event: str, data: dict, target_subs: SubscriptionTarget, target_id: str):
        message = f"{event} {json.dumps(data)}"
        tasks = []

        match target_subs:
            case "server_list":
                q = """
                    SELECT owner_id FROM servers WHERE id = :s_id
                    UNION
                    SELECT member_id FROM server_members WHERE server_id = :s_id
                """
                rows = db.execute(q, {"s_id": target_id}).fetchall()
                user_ids: list[str] = [(row[0]) for row in rows]
                assert user_ids
                    
                for ws_conn, ws_info in list(self.clients.items()):
                    if ws_info.user_id in user_ids:
                        tasks.append(ws_conn.send_text(message))

            case "server":
                for ws_conn, ws_info in list(self.clients.items()):
                    if ws_info.server_id == target_id:
                        tasks.append(ws_conn.send_text(message))

            case "channel":
                for ws_conn, ws_info in list(self.clients.items()):
                    if ws_info.channel_id == target_id:
                        tasks.append(ws_conn.send_text(message))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
                
    # will send to those who have visual on affected change (like: user changed name)
    async def emit_to_servers(self, event: str, data: dict, user_id: str):
        q = """
            SELECT id FROM servers WHERE owner_id = :u_id
            UNION
            SELECT server_id FROM server_members WHERE member_id = :u_id
        """
        cursor = db.execute(q, {"u_id": user_id})
        server_ids: list[str] = [row[0] for row in cursor.fetchall()]

        for server_id in server_ids:
            await self.emit(event, data, "server", server_id)

    async def emit_to_user(self, event: str, data: dict, user_id: str):
        message = f"{event} {json.dumps(data)}"
        for ws_conn, ws_info in self.clients.items():
            if ws_info.user_id == user_id:
                await ws_conn.send_text(message)

ws = WebSocketManager()

# WebSocket handler
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    try:
        try:
            user_id = await auth_user(websocket.cookies["token"])
            await ws.connect(websocket, user_id)
        except Exception:
            raise WebSocketException(1008, "Unauthorized")

        while True:
            raw_msg = await websocket.receive_text()
            await ws.handle_incoming_message(raw_msg, websocket)
    except WebSocketDisconnect:
        pass
    finally:
        await ws.disconnect(websocket)
        

# FastAPI paths
v1 = APIRouter(prefix="/api/v1")

@v1.post("/user/register", response_class=RedirectResponse)
async def register_user(req: Annotated[UserRegisterRequest, Form()]):
    hashed_password = password_hasher.hash(req.password)
    try:
        with db as tx:
            q = "INSERT INTO users (id, email, username, display_name, password) VALUES (?, ?, ?, ?, ?)"
            tx.execute(q, (str(ULID()), req.email, req.username, req.username, hashed_password))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "User with same e-mail or username already exists")
    return RedirectResponse("/login.html", 303)

@v1.post("/user/login", response_class=RedirectResponse)
async def login_user(req: Annotated[UserLoginRequest, Form()]):
    q = "SELECT id, password FROM users WHERE email = ?"
    row = db.execute(q, (req.email,)).fetchone()
    if not row:
        raise HTTPException(401, "Bad login")
    
    user_id, password = row
    try:
        password_hasher.verify(password, req.password)
    except exceptions.VerifyMismatchError:
        raise HTTPException(401, "Bad login")

    days: int = 14
    expires = datetime.now(timezone.utc) + timedelta(days=days)
    encoded_jwt = jwt.encode({"user_id": user_id, "exp": expires}, JWT_SECRET, algorithm="HS256")
    
    response = RedirectResponse("/", 303)
    response.set_cookie(key="token", value=encoded_jwt, httponly=True, secure=True, samesite="lax", max_age=days * 24 * 3600)
    return response

@v1.get("/user/logout", status_code=204, response_class=Response)
async def logout_user(response: Response):
    response.delete_cookie(key="token")

@v1.delete("/user/delete", status_code=204, response_class=Response)
async def delete_user(user_id: AuthUser):
    with db as tx:
        tx.execute("DELETE FROM users WHERE id = ?", (user_id,))
    user_cache.delete(user_id)

@v1.get("/test", response_class=PlainTextResponse)
async def test():
    return "Hello world!"

@v1.get("/user_id", response_class=PlainTextResponse)
async def get_user_id(user_id: AuthUser):
    return user_id

@v1.get("/user", response_model=UserSchema)
async def get_user_info(user_id: AuthUser):
    q = "SELECT id, username, display_name, picture, custom_status FROM users WHERE id = ?"
    row = db.execute(q, (user_id,)).fetchone()
    if row is None:
        raise HTTPException(404, detail="User not found")
    return dict(row)
    
@v1.patch("/user", response_model=UserEditResponse)
async def update_user_info(req: Annotated[UserEditRequest, Form()], user_id: AuthUser):
    values = req.model_dump(exclude_unset=True)
    if not values:
        raise HTTPException(400, "No fields received")

    with db as tx:
        q = f"UPDATE users SET {update_set_values(values)} WHERE id = :u_id"
        tx.execute(q, {**values, "u_id": user_id})

    user_cache.set(user_id, display_name=req.display_name)

    data = UserEditResponse(id=user_id, **values).model_dump(exclude_unset=True)
    await ws.emit_to_user("self_user_info", data, user_id)
    await ws.emit_to_servers("user_info", data, user_id)
    return data

@v1.post("/user/upload/avatar", response_class=PlainTextResponse)
async def upload_user_avatar(user_id: AuthUser, file: UploadFile | None = None):
    file_name = await save_avatar(file, PATH_AVATARS, (256, 256), crop_square=True)
    
    with db as tx:
        q = "UPDATE users SET picture = ? WHERE id = ?"
        tx.execute(q, (file_name, user_id,))

    user_cache.set(user_id, picture=file_name)

    data = UserEditResponse(id=user_id, picture=file_name).model_dump(exclude_unset=True)
    await ws.emit_to_user("self_user_info", data, user_id)
    await ws.emit_to_servers("user_info", data, user_id)
    return file_name

@v1.post("/server", response_model=ServerSchema)
async def create_server(req: ServerCreateRequest, user_id: AuthUser):
    server_id = str(ULID())
    channel_id = str(ULID())

    with db as tx: 
        q1 = "INSERT INTO servers (id, owner_id, name) VALUES (?, ?, ?)"
        tx.execute(q1, (server_id, user_id, req.name))

        q2 = "INSERT INTO channels (id, server_id, name) VALUES (?, ?, ?)"
        tx.execute(q2, (channel_id, server_id, "Default channel"))
    
    q3 = "SELECT id, owner_id, name, picture, banner, roles FROM servers WHERE id = ?"
    row = db.execute(q3, (server_id,)).fetchone()
    return dict(row)

@v1.get("/server/{server_id}", response_model=ServerSchema)
async def get_server_info(server_id: UlidStr, user_id: AuthUser):
    q = "SELECT * FROM servers WHERE id = ? AND owner_id = ?"
    row = db.execute(q, (server_id, user_id,)).fetchone()
    if not row:
        raise HTTPException(403, f"You don't own any server with ID '{server_id}'")
    return dict(row)

@v1.patch("/server/{server_id}", response_model=ServerSchema)
async def update_server_info(server_id: str, req: Annotated[ServerEditRequest, Form()], user_id: IsServerOwner):
    values = req.model_dump(exclude_unset=True)
    if not values:
        raise HTTPException(400, "No fields were provided")

    with db as tx:
        q = f"UPDATE servers SET {update_set_values(values)} WHERE id = :s_id AND owner_id = :u_id RETURNING *"
        row = tx.execute(q, {**values, "s_id": server_id, "u_id": user_id}).fetchone()
        assert row

    server = ServerSchema(**row)
    await ws.emit("server_info", server.model_dump(), "server_list", server_id)
    return server

@v1.post("/server/{server_id}/upload/avatar", response_class=PlainTextResponse)
async def upload_server_avatar(server_id: str, user_id: IsServerOwner, file: UploadFile | None = None):
    file_name = await save_avatar(file, PATH_AVATARS, (256, 256), crop_square=True)

    with db as tx:
        q = "UPDATE servers SET picture = ? WHERE id = ? AND owner_id = ? RETURNING *"
        row = tx.execute(q, (file_name, server_id, user_id,)).fetchone()
        assert row

    server = ServerSchema(**row).model_dump()
    await ws.emit("server_info", server, "server_list", server_id)
    return file_name

@v1.get("/servers", response_model=list[ServerSchema])
async def get_servers(user_id: AuthUser):
    q = """
        SELECT s.* FROM servers s WHERE s.owner_id = :u_id
        UNION
        SELECT s.* FROM servers s
        JOIN server_members m ON s.id = m.server_id
        WHERE m.member_id = :u_id
    """
    rows = db.execute(q, {"u_id": user_id}).fetchall()
    return [(dict(row)) for row in rows]

@v1.delete("/server/{server_id}", status_code=202, response_class=Response)
async def delete_server(server_id: UlidStr, user_id: IsServerOwner):
    # need to emit event before deletion as it would be no longer possible to get affected clients after
    data = {"id": server_id}
    await ws.emit("delete_server", data, "server_list", server_id)

    with db as tx:
        tx.execute("DELETE FROM servers WHERE id = ?", (server_id,))
    
@v1.post("/server/{server_id}/channel", status_code=202, response_class=Response)
async def create_channel(server_id: str, req: ChannelCreateRequest, user_id: IsServerOwner):
    channel = ChannelSchema(id=str(ULID()), server_id=server_id, name=req.name).model_dump()
    with db as tx:
        q = "INSERT INTO channels (id, server_id, name) VALUES(:id, :server_id, :name)"
        tx.execute(q, channel)

    await ws.emit("create_channel", channel, "server", server_id)

@v1.get("/channel/{channel_id}", response_model=ChannelSchema)
async def get_channel_info(channel_id: str, user_id: IsChannelOwner):
    q = "SELECT * FROM channels WHERE id = ?"
    row = db.execute(q, (channel_id,)).fetchone()
    return dict(row)

@v1.patch("/channel/{channel_id}", response_model=ChannelSchema)
async def update_channel_info(channel_id: str, req: Annotated[ChannelEditRequest, Form()], user_id: IsChannelOwner):
    values = req.model_dump(exclude_unset=True)
    if not values:
        raise HTTPException(400, "No fields were provided")
        
    q = f"UPDATE channels SET {update_set_values(values)} WHERE id = :c_id RETURNING *"
    with db as tx:
        row = tx.execute(q, {**values, "c_id": channel_id}).fetchone()

    channel = ChannelSchema(**row)
    await ws.emit("modify_channel", channel.model_dump(), "server", channel.server_id)
    return channel

@v1.get("/server/{server_id}/channels", response_model=list[ChannelSchema])
async def get_channels(server_id: str, user_id: HasServerAccess):
    q = "SELECT * FROM channels WHERE server_id = ?"
    rows = db.execute(q, (server_id,)).fetchall()
    return [(dict(row)) for row in rows]

@v1.delete("/channel/{channel_id}", status_code=202, response_class=Response)
async def delete_channel(channel_id: str, user_id: IsChannelOwner):
    with db as tx:
        q = "DELETE FROM channels WHERE id = ? RETURNING server_id"
        row = tx.execute(q, (channel_id,)).fetchone()
        assert row

    server_id: str = row[0]
    data = {"id": channel_id}
    await ws.emit("delete_channel", data, "server", server_id)

@v1.get("/server/{server_id}/members", response_model=list[UserSchema])
async def get_members(server_id: str, _: HasServerAccess):
    q = """
        SELECT u.id, u.username, u.display_name, u.picture, u.custom_status
        FROM users u JOIN servers s ON s.owner_id = u.id WHERE s.id = :s_id
        UNION
        SELECT u.id, u.username, u.display_name, u.picture, u.custom_status
        FROM users u JOIN server_members sm ON sm.member_id = u.id WHERE sm.server_id = :s_id
    """
    with db as tx:
        rows = tx.execute(q, {"s_id": server_id}).fetchall()

    return [dict(row) for row in rows]

@v1.post("/channel/{channel_id}/message", status_code=202, response_class=Response)
async def create_message(channel_id: str, req: MessageCreateRequest, user_id: HasChannelAccess):
    message_id = str(ULID())

    with db as tx:
        q = "INSERT INTO messages (id, sender_id, channel_id, message) VALUES (?, ?, ?, ?)"
        tx.execute(q, (message_id, user_id, channel_id, req.message))

    display_name, picture = user_cache.get(user_id)
    data = MessageResponse(
        id=message_id, sender_id=user_id, channel_id=channel_id, 
        message=req.message, display_name=display_name, picture=picture
    ).model_dump()
    await ws.emit("create_message", data, "channel", channel_id)

@v1.patch("/message/{message_id}", status_code=202, response_class=Response)
async def edit_message(message_id: UlidStr, req: MessageEditRequest, user_id: AuthUser):
    with db as tx:
        q = """
            UPDATE messages SET message = ?, edited = CURRENT_TIMESTAMP 
            WHERE id = ? AND sender_id = ? 
            RETURNING *
        """
        row = tx.execute(q, (req.message, message_id, user_id,)).fetchone()
    if not row:
        raise HTTPException(403, f"Not authorised to edit message ID '{message_id}'")

    msg = MessageEditResponse(**row).model_dump()
    channel_id = row["channel_id"]
    await ws.emit("edit_message", msg, "channel", channel_id)

@v1.delete("/message/{message_id}", status_code=202, response_class=Response)
async def delete_message(message_id: UlidStr, user_id: AuthUser):
    with db as tx:
        q = "DELETE FROM messages WHERE id = ? AND sender_id = ? RETURNING channel_id"
        row = tx.execute(q, (message_id, user_id,)).fetchone()
    if not row:
        raise HTTPException(403, f"Not authorised to delete message ID '{message_id}'")

    channel_id: str = row[0]

    data = {"id": message_id}
    await ws.emit("delete_message", data, "channel", channel_id)

@v1.get("/channel/{channel_id}/messages", response_model=list[MessageResponse])
async def get_messages(channel_id: str, user_id: HasChannelAccess,
    message_id: str | None = None, direction: Literal["before", "after", None] = None
):
    # fetch newer messages scrolling down
    if message_id and direction == "after": 
        q = """
            SELECT m.*, u.display_name, u.picture FROM messages m 
            JOIN users u ON m.sender_id = u.id 
            WHERE m.channel_id = :c_id AND m.id > :m_id
            ORDER BY m.id ASC LIMIT 100
        """
        params = {"c_id": channel_id, "m_id": message_id}

    # fetch older messages scrolling up
    elif message_id and direction == "before": 
        q = """
            SELECT m.*, u.display_name, u.picture FROM messages m 
            JOIN users u ON m.sender_id = u.id 
            WHERE m.channel_id = :c_id AND m.id < :m_id
            ORDER BY m.id DESC LIMIT 100
        """
        params = {"c_id": channel_id, "m_id": message_id}

    # fetch last messages
    else: 
        q = """
            SELECT m.*, u.display_name, u.picture FROM messages m 
            JOIN users u ON m.sender_id = u.id 
            WHERE m.channel_id = :c_id
            ORDER BY m.id DESC LIMIT 100
        """
        params = {"c_id": channel_id}

    rows = db.execute(q, params).fetchall()
    return [(dict(row)) for row in rows]

@v1.post("/channel/{channel_id}/typing/{value}", status_code=202, response_class=Response)
async def typing(value: Literal["start", "stop"], channel_id: str, user_id: HasChannelAccess):
    if value == "start":
        display_name = user_cache.get(user_id).display_name
        data = {"id": user_id, "display_name": display_name}
    else:
        data = {"id": user_id}
    await ws.emit(f"{value}_typing", data, "channel", channel_id)

upload_attachment_lock = asyncio.Lock()
@v1.post("/upload/attachment", response_class=Response)
async def upload_attachment(attachment: UploadFile, user_id: AuthUser):
    MAX_SIZE = 16 * 1024 * 1024 # 16 mb
    if not attachment.filename or not attachment.size:
        raise HTTPException(422, "No filename or content length provided")
    if attachment.size > MAX_SIZE:
        raise HTTPException(413, f"Exceeding max upload limit of '{MAX_SIZE/1024/1024}' mb")

    temp_path = FilePath(f"{PATH_ATTACHMENTS}/temp/{os.urandom(16).hex()}")
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
    final_path = FilePath(f"{PATH_ATTACHMENTS}/{user_id}/{hash_name}_{attachment.filename}")

    async with upload_attachment_lock:
        os.makedirs(os.path.dirname(final_path), exist_ok=True)
        if final_path.is_file():
            os.remove(temp_path)
        else:
            shutil.move(temp_path, final_path)

app.include_router(v1)

# Public file handlers
serve_avatars_lock = asyncio.Lock()
@app.get("/avatars/{name}", response_class=FileResponse)
async def serve_avatars(user_id: AuthUser, name: PictureName, size: Optional[Literal["80", "96"]] = None):
    headers = {"Cache-Control": "private, max-age=2592000, immutable"}
    original_file_path = FilePath(f"{PATH_AVATARS}/{name}")

    if not size: # if requests original
        if original_file_path.is_file():
            return FileResponse(original_file_path, headers=headers)
        raise HTTPException(404)
            
    resized_file_path = FilePath(f"{PATH_AVATARS}/{size}/{name}") # if requests resized
    if resized_file_path.is_file():
        return FileResponse(resized_file_path, headers=headers)
        
    if not original_file_path.is_file(): # create resized if not found
        raise HTTPException(404)
    async with serve_avatars_lock:
        if not resized_file_path.is_file():
            await generate_resized_picture(original_file_path, int(size))
    return FileResponse(resized_file_path, headers=headers)

# Svelte file handlers
if os.path.exists("./dist"): # serve svelte frontend from dist folder, if it's there
    app.mount("/", StaticFiles(directory="dist", html=True))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)