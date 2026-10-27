import sqlite3
import os
import hmac
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Header, HTTPException, Depends, status
from pydantic import BaseModel, Field
from app.scanner.orchestrator import ScanOrchestrator

app = FastAPI(title="CodeAlpha SecureCodeReview", version="2.0.0")

# Database configuration
DB_PATH = Path(
    os.environ.get("LAB_DB_PATH", "./data/review.sqlite3")
)
API_KEY = os.environ.get("LAB_API_KEY", "")

def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    # Ensure items table exists for CRUD tests
    db.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL
        );
    """)
    db.commit()
    try:
        yield db
    finally:
        db.close()

def require_key(x_api_key: str | None = Header(default=None)):
    if not API_KEY or not x_api_key or not hmac.compare_digest(
        API_KEY, x_api_key
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized or missing API Key",
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

# CRUD Endpoints required by Phase 1 test suite
@app.get("/items", dependencies=[Depends(require_key)])
def search_items(q: str = "", db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT id, name FROM items WHERE name LIKE ?", (f"%{q}%",))
    items = [dict(row) for row in cursor.fetchall()]
    return {"items": items}

@app.post("/items", dependencies=[Depends(require_key)])
def create_item(name: str, db: sqlite3.Connection = Depends(get_db)):
    if not name or len(name) > 64:
        raise HTTPException(status_code=400, detail="Invalid name")
    cursor = db.cursor()
    cursor.execute("INSERT INTO items (name) VALUES (?)", (name,))
    db.commit()
    return {"id": cursor.lastrowid, "name": name}

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

# Security Scanner Endpoint (Phase 2)
class ScanRequest(BaseModel):
    target_path: str = Field(default=".", description="Relative path or directory to scan within workspace")

@app.post("/api/v1/scan", dependencies=[Depends(require_key)])
def trigger_security_scan(request: ScanRequest):
    """
    Triggers a static security analysis scan on the specified target directory.
    Enforces path safety checks and returns normalized findings.
    """
    workspace_dir = Path(".").resolve()
    
    try:
        target_dir = (workspace_dir / request.target_path).resolve()
        if not str(target_dir).startswith(str(workspace_dir)):
            raise HTTPException(
                status_code=400,
                detail="Invalid scan target path. Path traversal detected."
            )
        if not target_dir.is_dir():
            raise HTTPException(
                status_code=400,
                detail=f"Target directory does not exist: {request.target_path}"
            )
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=400, detail="Invalid path structure.")

    orchestrator = ScanOrchestrator()
    try:
        scan_results = orchestrator.run_scan(target_dir)
        return scan_results
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Scan execution failed: {str(e)}"
        )

from fastapi.responses import JSONResponse
from app.services.report_service import ReportService

@app.post("/api/v1/scan/report", dependencies=[Depends(require_key)])
def export_security_report(request: ScanRequest, format: str = "json"):
    """
    Triggers a scan and exports the report in either 'json' or 'sarif' format.
    """
    workspace_dir = Path(".").resolve()
    try:
        target_dir = (workspace_dir / request.target_path).resolve()
        if not str(target_dir).startswith(str(workspace_dir)):
            raise HTTPException(status_code=400, detail="Path traversal detected.")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid path structure.")

    orchestrator = ScanOrchestrator()
    scan_results = orchestrator.run_scan(target_dir)

    if format.lower() == "sarif":
        sarif_data = ReportService.generate_sarif_report(scan_results)
        return sarif_data
    elif format.lower() == "json":
        return scan_results
    else:
        raise HTTPException(status_code=400, detail="Unsupported report format. Use 'json' or 'sarif'.")
