"""Corrected application for the CodeAlpha secure-coding lab."""
import hmac
import logging
import os
import sqlite3
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field
from app.scanner.orchestrator import ScanOrchestrator
from app.middleware import SecurityHeadersMiddleware

logger = logging.getLogger(__name__)

# FastAPI app instance defined at module top-level
app = FastAPI(title="CodeAlpha SecureCodeReview", version="2.0.0")

# Register security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

DB_PATH = Path(
    os.environ.get(
        "LAB_DB_PATH",
        Path(__file__).resolve().parent.parent / "data" / "review.sqlite3",
    )
)
API_KEY = os.environ.get("LAB_API_KEY", "")


class Item(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)


def get_db():
    db = None
    try:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        db.execute(
            "CREATE TABLE IF NOT EXISTS items "
            "(id INTEGER PRIMARY KEY, name TEXT NOT NULL)"
        )
        db.commit()
        yield db
    except sqlite3.Error:
        logger.exception("Database operation failed")
        raise
    except OSError:
        logger.exception("Database directory or file access failed")
        raise
    finally:
        if db is not None:
            db.close()


def require_key(x_api_key: str | None = Header(default=None)):
    if not API_KEY or not x_api_key or not hmac.compare_digest(
        API_KEY, x_api_key
    ):
        raise HTTPException(
            status_code=401, detail="Unauthorized or missing API Key"
        )
    return x_api_key


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.get("/api/v1/demo", dependencies=[Depends(require_key)])
def read_demo(db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]
    return {"status": "ok", "tables": tables}


@app.get("/items", dependencies=[Depends(require_key)])
def search_items(
    q: str = Query(default="", max_length=64),
    db: sqlite3.Connection = Depends(get_db),
):
    cursor = db.cursor()
    cursor.execute("SELECT id, name FROM items WHERE name LIKE ?", (f"%{q}%",))
    items = [dict(row) for row in cursor.fetchall()]
    return {"items": items}


@app.post("/items", status_code=201, dependencies=[Depends(require_key)])
def create_item(item: Item, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("INSERT INTO items (name) VALUES (?)", (item.name,))
    db.commit()
    return {"id": cursor.lastrowid, "name": item.name}


@app.get("/items/{item_id}", dependencies=[Depends(require_key)])
def get_item(item_id: int, db: sqlite3.Connection = Depends(get_db)):
    if item_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid ID")
    cursor = db.cursor()
    cursor.execute("SELECT id, name FROM items WHERE id = ?", (item_id,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    return dict(row)


class ScanRequest(BaseModel):
    target_path: str = Field(default=".", description="Relative path or directory to scan")


@app.post("/api/v1/scan", dependencies=[Depends(require_key)])
def trigger_security_scan(request: ScanRequest):
    workspace_dir = Path(".").resolve()
    try:
        target_dir = (workspace_dir / request.target_path).resolve()
        if not target_dir.is_relative_to(workspace_dir):
            raise HTTPException(status_code=400, detail="Path traversal detected.")
        if not target_dir.is_dir():
            raise HTTPException(status_code=400, detail="Target directory does not exist.")
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=400, detail="Invalid path.")

    orchestrator = ScanOrchestrator()
    return orchestrator.run_scan(target_dir)
