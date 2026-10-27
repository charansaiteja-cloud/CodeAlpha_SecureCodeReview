"""Corrected application for the CodeAlpha secure-coding lab."""
import hmac
import os
import sqlite3
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

DB_PATH = Path(
    os.environ.get(
        "LAB_DB_PATH",
        str(Path.home() / ".local" / "share" / "codealpha-review" / "review.sqlite3"),
    )
)
API_KEY = os.environ.get("LAB_API_KEY", "")
app = FastAPI(title="CodeAlpha Secure Coding Review", debug=False)


class Item(BaseModel):
    name: str = Field(min_length=1, max_length=80, pattern=r"^[\w .-]+$")


def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        db.execute(
            "CREATE TABLE IF NOT EXISTS items "
            "(id INTEGER PRIMARY KEY, name TEXT NOT NULL)"
        )
        db.execute(
            "INSERT OR IGNORE INTO items(id, name) VALUES(1, 'demo')"
        )
        db.commit()
        yield db
    finally:
        db.close()


def require_key(x_api_key: str | None = Header(default=None)):
    if not API_KEY or not x_api_key or not hmac.compare_digest(
        API_KEY, x_api_key
    ):
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.middleware("http")
async def headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    return response


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/items/{item_id}")
def get_item(
    item_id: int,
    db: sqlite3.Connection = Depends(get_db),
    _auth: None = Depends(require_key),
):
    if item_id < 1:
        raise HTTPException(status_code=422, detail="Invalid item ID")
    row = db.execute(
        "SELECT id, name FROM items WHERE id = ?", (item_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return dict(row)


@app.post("/items", status_code=201)
def create_item(
    item: Item,
    db: sqlite3.Connection = Depends(get_db),
    _auth: None = Depends(require_key),
):
    cursor = db.execute("INSERT INTO items(name) VALUES(?)", (item.name,))
    db.commit()
    return {"id": cursor.lastrowid, "name": item.name}


@app.get("/search")
def search(
    q: str = Query(min_length=1, max_length=80),
    db: sqlite3.Connection = Depends(get_db),
    _auth: None = Depends(require_key),
):
    rows = db.execute(
        "SELECT id, name FROM items WHERE name LIKE ? LIMIT 20",
        (f"%{q}%",),
    ).fetchall()
    return {"items": [dict(row) for row in rows]}
