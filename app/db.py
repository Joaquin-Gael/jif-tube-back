from sqlmodel import create_engine, SQLModel, Session

from fastapi import Depends

from typing import Annotated

from rich.console import Console

console = Console()

engine = create_engine('sqlite:///jif.db', echo=False, pool_pre_ping=True, furuture=True)

def init_db():
    console.rule("Initializing database")
    SQLModel.metadata.create_all(engine)
    console.rule("Database initialized")

def get_db():
    db = Session(engine)
    try:
        yield db
    finally:
        db.close()

SessionDep = Annotated[Session, Depends(get_db)]