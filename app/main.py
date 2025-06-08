from fastapi import FastAPI, Request, APIRouter, Header, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi import status

from sqlmodel import select

from contextlib import asynccontextmanager

from pathlib import Path

from typing import Dict, Optional, List

import jwt
from jwt import PyJWTError

from datetime import datetime, timedelta

from app.db import init_db, SessionDep
from app.models import User

key = "6e4486e782d27b01c63ce61fa2ad197df535f3f1f2fa91a128d6f2ac71772576"

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield None
    pass

app = FastAPI(
    title="Jif-Tube-API",
    lifespan=lifespan
)

class SPAStatic(StaticFiles):
    def __init__(self, directory:Path, html:bool=True, check_dir:bool=True, index_html:Path = Path("index.html")):
        super().__init__(directory=directory, html=html, check_dir=check_dir)
        self.index_html = index_html

        self.app = super.__call__

    async def __call__(self, scope, receive, send):

        assert scope["type"] == "http"

        request = Request(scope, receive)

        path = request.url.path.lstrip("/")

        if request.url.path.startswith("/api"):
            await self.app(scope, receive, send)
            return None

        full_path = (Path(self.directory) / path).resolve()

        if full_path.exists():
            await self.app(scope, receive, send)
            return None

        index_path = Path(self.directory) / self.index_html
        response = FileResponse(index_path)

        return response(scope, receive, send)

def get_token(payload:Dict, refresh:bool = False):
    payload.setdefault("iat", datetime.now())
    payload.setdefault("iss", f"Jif-Tube-API/0.0.1")
    if refresh:
        payload.setdefault("exp", datetime.now() + timedelta(minutes=60))
        payload.setdefault("type", "refresh")
    else:
        payload.setdefault("exp", datetime.now() + timedelta(minutes=30))
    return jwt.encode(payload, key, algorithm="HS256")

def decode_token(token:str) -> Dict | None:
    try:
        payload = jwt.decode(token, key, algorithms=["HS256"])
        return payload
    except PyJWTError:
        return None

def get_user(request: Request, session: SessionDep, authorization: Optional[str] = Header(None)) -> User | None:
    if authorization is None:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if authorization.startswith("Bearer"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    token = authorization.split(" ")[1]

    payload = decode_token(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Unauthorized (Token error)")

    user_id: int = payload.get("sub")

    if not user_id:
        raise HTTPException(status_code=401, detail="Unauthorized (Not User)")

    try:
        user = session.exec(select(User).where(User.id == user_id)).first()

        request.state.user = user
        request.state.scopes = payload.get("scopes")

        return user
    except Exception:
        print("Not User DB")
        raise HTTPException(status_code=401, detail="Unauthorized")

auth = APIRouter(
    prefix="/api",
    tags=["auth"],
    dependencies=[
        Depends(get_user),
    ]
)

@auth.get("/scopes", response_model=Dict[str, List[str]])
async def get_scopes(request: Request, _=Depends(auth)):
    scopes = request.state.scopes
    return {
        "scopes":scopes,
    }