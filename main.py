"""
TSI Particle Counter — FastAPI WebApp
======================================
Port: 8080  (Microsoft Entra redirect URI is http://localhost:8080/msgraph/oauth/callback)

Authentication:
  Every route except /auth/login, /auth/logout, /msgraph/oauth/callback and /health
  requires a valid Microsoft Entra session cookie.

  Flow:
    1. Browser → GET /  → no cookie → redirect to /auth/login
    2. /auth/login  → redirect to Microsoft login page
    3. Microsoft → GET /msgraph/oauth/callback?code=…&state=…
    4. Callback exchanges code, validates id_token, sets signed session cookie
    5. Browser lands on /  — now authenticated, sees the dashboard

Configuration:
    App-level settings (host/port, DB path, CORS origins, Entra client/tenant
    IDs, scheduler poll interval, ...) are read from config.yaml at startup.
    Override the file location with TSI_CONFIG_PATH. See config.py.

Environment variables (secrets only — never stored in config.yaml):
    TSI_CLIENT_SECRET   Azure app client secret (required in confidential client mode)
    TSI_SESSION_SECRET  32+ char string for cookie encryption (recommended in production)
    TSI_CONFIG_PATH     Path to an alternate config.yaml (optional)
"""

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from config import CONFIG
from db.database import (
    init_db, db_session,
    list_devices, get_device, get_records_page,
    get_channels_for_record, get_record_count,
    save_device_data, start_sync_log, finish_sync_log,
    get_or_create_device, reset_device_records,
    get_channel_stats, get_sync_log, record_belongs_to_device,
)
from instrument.tsi_modbus import TSIClient
from backthread.scheduler import (
    init_scheduler_db, get_scheduler, execute_job,
    _next_run, _now_utc, _iso, _parse_iso,
)
from backthread.workflow import WorkflowGraph, TEMPLATES
from db.localDB import db_session as scheduler_db_session  # scheduler_jobs/scheduler_runs
                                                             # always live in the local SQLite
                                                             # file (see backthread/scheduler.py),
                                                             # independent of database.driver.
import auth

logging.basicConfig(level=CONFIG.app.log_level,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("tsi_api")

DB_PATH = CONFIG.db_path
APP_PORT = CONFIG.app.port

# ─── Public routes (no auth check) ───────────────────────────────────────────
PUBLIC_PATHS = {
    "/auth/login",
    "/auth/logout",
    "/msgraph/oauth/callback",
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
}

# ─── Shared sync-progress state ───────────────────────────────────────────────
_sync_progress: dict[int, dict] = {}


# ─── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db(DB_PATH)
    init_scheduler_db(DB_PATH)
    log.info("DB initialised")
    sched = get_scheduler()
    sched.start()
    log.info("Scheduler started")
    yield
    sched.stop()
    log.info("Scheduler stopped")


# ─── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="TSI Particle Counter API",
    description="TSI 9xxx Modbus TCP reader with Microsoft Entra authentication",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CONFIG.cors.allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Auth middleware ──────────────────────────────────────────────────────────

@app.middleware("http")
async def require_auth(request: Request, call_next):
    path = request.url.path

    # always allow public paths and static assets
    if path in PUBLIC_PATHS or path.startswith("/static/"):
        return await call_next(request)

    # read session cookie
    cookie = request.cookies.get(auth.SESSION_COOKIE)
    if cookie:
        session = auth.read_session_cookie(cookie)
        if session:
            request.state.user = session
            return await call_next(request)

    # API requests get 401 JSON; browser requests get redirect
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return RedirectResponse(url="/auth/login", status_code=302)
    raise HTTPException(401, detail="Authentication required")


# ─── Helper ───────────────────────────────────────────────────────────────────

def row_to_dict(row) -> dict:
    return dict(row) if row else None

def _parse_json_fields(d: dict, *fields) -> dict:
    for f in fields:
        if f in d and isinstance(d[f], str):
            try:
                d[f] = json.loads(d[f])
            except Exception:
                pass
    return d


# ═══════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/health", include_in_schema=False)
async def health():
    return {"status": "ok"}


@app.get("/auth/login", include_in_schema=False)
async def login(response: Response):
    """Redirect browser to Microsoft Entra login page."""
    state = auth.generate_state()
    url   = auth.build_auth_url(state)
    resp  = RedirectResponse(url=url, status_code=302)
    # store state in a short-lived cookie for CSRF validation
    resp.set_cookie(
        auth.STATE_COOKIE, state,
        max_age=600, httponly=True, samesite="lax",
    )
    return resp


@app.get("/auth/logout", include_in_schema=False)
async def logout(request: Request):
    """Clear session cookie and redirect to Microsoft logout."""
    resp = RedirectResponse(
        url=auth.build_logout_url(f"http://localhost:{APP_PORT}/"),
        status_code=302,
    )
    resp.delete_cookie(auth.SESSION_COOKIE)
    resp.delete_cookie(auth.STATE_COOKIE)
    return resp


@app.get("/msgraph/oauth/callback", include_in_schema=False)
async def oauth_callback(
    request: Request,
    code:  Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    error_description: Optional[str] = Query(None),
):
    """
    Microsoft redirects here after authentication.
    Exchange the authorization code for tokens, validate, set session cookie.
    """
    # ── error from Microsoft ──────────────────────────────────────────────────
    if error:
        log.warning(f"OAuth error: {error} — {error_description}")
        return _auth_error_page(error, error_description or "")

    # ── CSRF state check ──────────────────────────────────────────────────────
    stored_state = request.cookies.get(auth.STATE_COOKIE)
    if not stored_state or stored_state != state:
        log.warning("OAuth state mismatch")
        return _auth_error_page("state_mismatch", "Invalid OAuth state. Please try again.")

    if not code:
        return _auth_error_page("no_code", "No authorization code received.")

    # ── Token exchange ────────────────────────────────────────────────────────
    try:
        tokens = auth.exchange_code(code)
    except Exception as exc:
        log.error(f"Token exchange failed: {exc}")
        return _auth_error_page("token_error", str(exc))

    # ── Validate id_token ─────────────────────────────────────────────────────
    id_token = tokens.get("id_token", "")
    if not id_token:
        return _auth_error_page("no_id_token", "No id_token in token response.")

    try:
        claims = auth.decode_id_token(id_token)
    except Exception as exc:
        log.error(f"id_token validation failed: {exc}")
        return _auth_error_page("token_invalid", str(exc))

    # ── Build & store session ─────────────────────────────────────────────────
    import time
    session = auth.session_from_claims(claims)
    # Clamp session TTL to id_token exp (or +8h from now, whichever is sooner)
    session.exp = min(session.exp, time.time() + auth.SESSION_TTL)
    cookie_val  = auth.make_session_cookie(session)

    log.info(f"User authenticated: {session.email} (oid={session.oid})")

    resp = RedirectResponse(url="/", status_code=302)
    resp.set_cookie(
        auth.SESSION_COOKIE, cookie_val,
        max_age=auth.SESSION_TTL,
        httponly=True,
        samesite="lax",
        secure=False,   # set True when behind HTTPS in production
    )
    resp.delete_cookie(auth.STATE_COOKIE)
    return resp


def _auth_error_page(code: str, message: str) -> HTMLResponse:
    return HTMLResponse(status_code=400, content=f"""
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Authentication Error</title>
<style>
  body{{font-family:system-ui,sans-serif;display:flex;align-items:center;
        justify-content:center;min-height:100vh;margin:0;background:#f0f4f8;}}
  .box{{background:#fff;border-radius:12px;padding:40px 48px;max-width:440px;
        box-shadow:0 4px 24px #0002;text-align:center;}}
  h2{{color:#c0392b;margin-top:0;}}
  code{{background:#fdf;padding:2px 8px;border-radius:4px;font-size:.85em;}}
  a{{color:#1a3a5c;font-weight:600;}}
</style></head>
<body><div class="box">
  <h2>⚠️ Authentication Error</h2>
  <p><code>{code}</code></p>
  <p>{message}</p>
  <p><a href="/auth/login">← Try again</a></p>
</div></body></html>
""")


# ═══════════════════════════════════════════════════════════════════════════════
# ALL EXISTING API ROUTES (unchanged)
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Pydantic models ──────────────────────────────────────────────────────────

class ConnectRequest(BaseModel):
    ip: str = Field(..., description="IP address of the instrument")
    port: int = Field(502, description="Modbus TCP port (default 502)")
    max_records: int = Field(1000, ge=1, le=10000)
    timeout: float = Field(3.0, ge=0.5, le=30.0)

class SyncRequest(BaseModel):
    max_records: int = Field(1000, ge=1, le=10000)
    timeout: float = Field(3.0, ge=0.5, le=30.0)

class JobCreateRequest(BaseModel):
    device_id:        int
    name:             str
    description:      str = ""
    graph_json:       dict = Field(...)
    enabled:          bool = True
    interval_seconds: Optional[int]  = Field(None, ge=60)
    cron_hour:        Optional[int]  = Field(None, ge=0, le=23)
    cron_minute:      int            = Field(0, ge=0, le=59)
    first_run_at:     Optional[str]  = None

class JobUpdateRequest(BaseModel):
    name:             Optional[str]  = None
    description:      Optional[str]  = None
    graph_json:       Optional[dict] = None
    enabled:          Optional[bool] = None
    interval_seconds: Optional[int]  = Field(None, ge=60)
    cron_hour:        Optional[int]  = Field(None, ge=0, le=23)
    cron_minute:      Optional[int]  = Field(None, ge=0, le=59)
    next_run_at:      Optional[str]  = None


# ─── Devices ──────────────────────────────────────────────────────────────────

@app.get("/devices", summary="List devices")
async def api_list_devices():
    with db_session(DB_PATH) as conn:
        rows = list_devices(conn)
        result = []
        for r in rows:
            d = row_to_dict(r)
            _parse_json_fields(d, "channel_sizes", "locations")
            result.append(d)
    return result

@app.get("/devices/{device_id}", summary="Device info")
async def api_get_device(device_id: int):
    with db_session(DB_PATH) as conn:
        row = get_device(conn, device_id)
        if not row:
            raise HTTPException(404, detail="Device not found")
        d = row_to_dict(row)
        _parse_json_fields(d, "channel_sizes", "locations")
        d["record_count"] = get_record_count(conn, device_id)
    return d

@app.get("/devices/{device_id}/records", summary="Paginated samples")
async def api_get_records(
    device_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    from_ts: Optional[str] = Query(None),
    to_ts:   Optional[str] = Query(None),
):
    with db_session(DB_PATH) as conn:
        if not get_device(conn, device_id):
            raise HTTPException(404, detail="Device not found")
        rows  = get_records_page(conn, device_id, skip, limit, from_ts, to_ts)
        total = get_record_count(conn, device_id)
    return {"total": total, "skip": skip, "limit": limit,
            "data": [row_to_dict(r) for r in rows]}

@app.get("/devices/{device_id}/records/{record_id}/channels")
async def api_get_channels(device_id: int, record_id: int):
    with db_session(DB_PATH) as conn:
        if not record_belongs_to_device(conn, record_id, device_id):
            raise HTTPException(404, detail="Record not found")
        rows = get_channels_for_record(conn, record_id)
    return [row_to_dict(r) for r in rows]

@app.get("/devices/{device_id}/stats", summary="Aggregate stats per channel")
async def api_stats(device_id: int,
                    from_ts: Optional[str] = Query(None),
                    to_ts:   Optional[str] = Query(None)):
    with db_session(DB_PATH) as conn:
        if not get_device(conn, device_id):
            raise HTTPException(404, detail="Device not found")
        rows = get_channel_stats(conn, device_id, from_ts, to_ts)
    return [row_to_dict(r) for r in rows]

@app.get("/sync_log")
async def api_sync_log(limit: int = Query(50, ge=1, le=500)):
    with db_session(DB_PATH) as conn:
        rows = get_sync_log(conn, limit)
    return [row_to_dict(r) for r in rows]


# ─── Connect & sync ───────────────────────────────────────────────────────────

def _do_sync(ip, port, max_records, timeout, device_id=None):
    client = TSIClient(ip, port, timeout)
    device = client.fetch_all(max_records)
    stats  = save_device_data(device, DB_PATH)
    with db_session(DB_PATH) as conn:
        lid = start_sync_log(conn, stats["device_id"])
        finish_sync_log(conn, lid, stats["records_read"], stats["records_new"])
    _sync_progress[stats["device_id"]] = {
        "status": "done", "done": stats["records_read"],
        "new": stats["records_new"], "total": device.num_records,
        "finished_at": datetime.utcnow().isoformat(),
    }
    return stats

@app.post("/connect")
async def api_connect(req: ConnectRequest, background_tasks: BackgroundTasks):
    import socket as _sock
    try:
        s = _sock.create_connection((req.ip, req.port), timeout=3); s.close()
    except OSError as e:
        raise HTTPException(503, detail=f"Instrument unreachable: {e}")
    with db_session(DB_PATH) as conn:
        device_id = get_or_create_device(conn, req.ip, req.port)
    _sync_progress[device_id] = {"status": "running", "done": 0, "total": 0}
    def _task():
        try:
            _do_sync(req.ip, req.port, req.max_records, req.timeout, device_id)
        except Exception as e:
            _sync_progress[device_id] = {"status": "error", "error": str(e)}
    background_tasks.add_task(_task)
    return {"message": "Sync started", "device_id": device_id,
            "stream_url": f"/devices/{device_id}/sync/stream"}

@app.post("/devices/{device_id}/sync")
async def api_resync(device_id: int, req: SyncRequest, background_tasks: BackgroundTasks):
    with db_session(DB_PATH) as conn:
        row = get_device(conn, device_id)
        if not row:
            raise HTTPException(404, detail="Device not found")
        ip, port = row["ip"], row["port"]
    _sync_progress[device_id] = {"status": "running", "done": 0, "total": 0}
    def _task():
        try:
            _do_sync(ip, port, req.max_records, req.timeout, device_id)
        except Exception as e:
            _sync_progress[device_id] = {"status": "error", "error": str(e)}
    background_tasks.add_task(_task)
    return {"message": "Resync started", "device_id": device_id}

@app.get("/devices/{device_id}/sync/stream")
async def api_sync_stream(device_id: int):
    async def gen():
        while True:
            prog = _sync_progress.get(device_id, {"status": "unknown"})
            yield f"data: {json.dumps(prog)}\n\n"
            if prog.get("status") in ("done", "error"):
                break
            await asyncio.sleep(1)
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─── Device command helpers ───────────────────────────────────────────────────

def _get_device_ip_port(device_id: int):
    with db_session(DB_PATH) as conn:
        row = get_device(conn, device_id)
        if not row:
            raise HTTPException(404, detail="Device not found")
        return row["ip"], row["port"]

def _run_command(device_id: int, cmd_fn, timeout: float = 3.0) -> dict:
    ip, port = _get_device_ip_port(device_id)
    client = TSIClient(ip, port, timeout)
    client.connect()
    try:
        ok = cmd_fn(client)
    finally:
        client.disconnect()
    return {"success": ok, "device_id": device_id, "ip": ip}


# ─── Status ───────────────────────────────────────────────────────────────────

@app.get("/devices/{device_id}/status")
async def api_device_status(device_id: int, timeout: float = Query(3.0)):
    ip, port = _get_device_ip_port(device_id)
    c = TSIClient(ip, port, timeout); c.connect()
    try:
        s = c.read_status()
    finally:
        c.disconnect()
    s.update({"device_id": device_id, "ip": ip})
    return s


# ─── Measurement ──────────────────────────────────────────────────────────────

@app.post("/devices/{device_id}/measure/start")
async def api_measure_start(device_id: int, timeout: float = Query(3.0)):
    return _run_command(device_id, lambda c: c.start_manual(), timeout)

@app.post("/devices/{device_id}/measure/stop")
async def api_measure_stop(device_id: int, timeout: float = Query(3.0)):
    return _run_command(device_id, lambda c: c.stop_measurement(), timeout)

@app.post("/devices/{device_id}/measure/start_auto")
async def api_measure_start_auto(device_id: int, timeout: float = Query(3.0)):
    return _run_command(device_id, lambda c: c.start_auto(), timeout)

@app.post("/devices/{device_id}/measure/stop_auto")
async def api_measure_stop_auto(device_id: int, timeout: float = Query(3.0)):
    return _run_command(device_id, lambda c: c.stop_auto(), timeout)

@app.post("/devices/{device_id}/measure/start_pump")
async def api_start_pump(device_id: int, timeout: float = Query(3.0)):
    return _run_command(device_id, lambda c: c.start_pump(), timeout)

@app.post("/devices/{device_id}/measure/stop_pump")
async def api_stop_pump(device_id: int, timeout: float = Query(3.0)):
    return _run_command(device_id, lambda c: c.stop_pump(), timeout)


# ─── Maintenance ──────────────────────────────────────────────────────────────

@app.post("/devices/{device_id}/maintenance/clear_data")
async def api_clear_data(device_id: int, confirm: bool = Query(False), timeout: float = Query(3.0)):
    if not confirm:
        raise HTTPException(400, detail="Add ?confirm=true to proceed (destructive).")
    result = _run_command(device_id, lambda c: c.clear_all_data(), timeout)
    if result["success"]:
        with db_session(DB_PATH) as conn:
            reset_device_records(conn, device_id)
    return result

@app.post("/devices/{device_id}/maintenance/sync_clock")
async def api_sync_clock(device_id: int, timeout: float = Query(3.0)):
    return _run_command(device_id, lambda c: c.sync_clock(), timeout)

@app.post("/devices/{device_id}/maintenance/purge")
async def api_purge(device_id: int, timeout: float = Query(3.0)):
    return _run_command(device_id, lambda c: c.purge_start(), timeout)

@app.post("/devices/{device_id}/maintenance/silence")
async def api_silence(device_id: int, timeout: float = Query(3.0)):
    return _run_command(device_id, lambda c: c.silence(), timeout)

@app.post("/devices/{device_id}/maintenance/unsilence")
async def api_unsilence(device_id: int, timeout: float = Query(3.0)):
    return _run_command(device_id, lambda c: c.unsilence(), timeout)

@app.post("/devices/{device_id}/maintenance/reboot")
async def api_reboot(device_id: int, confirm: bool = Query(False), timeout: float = Query(3.0)):
    if not confirm:
        raise HTTPException(400, detail="Add ?confirm=true to proceed.")
    return _run_command(device_id, lambda c: c.reboot(), timeout)

@app.post("/devices/{device_id}/maintenance/disable_local_control")
async def api_disable_local(device_id: int, timeout: float = Query(3.0)):
    return _run_command(device_id, lambda c: c.disable_local_control(), timeout)

@app.post("/devices/{device_id}/maintenance/enable_local_control")
async def api_enable_local(device_id: int, timeout: float = Query(3.0)):
    return _run_command(device_id, lambda c: c.enable_local_control(), timeout)


# ─── Workflow ─────────────────────────────────────────────────────────────────

@app.get("/workflow/templates")
async def api_workflow_templates():
    return {n: {"name": n, "description": t["description"], "graph": t["graph"]}
            for n, t in TEMPLATES.items()}

@app.post("/workflow/validate")
async def api_workflow_validate(graph: dict):
    try:
        wf   = WorkflowGraph.from_dict(graph)
        errs = wf.validate()
        if errs:
            return {"valid": False, "errors": errs}
        return {"valid": True, "node_count": len(wf.nodes), "edge_count": len(wf.edges),
                "entry": wf.entry, "node_types": list({n.type for n in wf.nodes.values()})}
    except Exception as exc:
        return {"valid": False, "errors": [str(exc)]}


# ─── Scheduler jobs ───────────────────────────────────────────────────────────

@app.post("/scheduler/jobs")
async def api_create_job(req: JobCreateRequest):
    try:
        wf   = WorkflowGraph.from_dict(req.graph_json)
        errs = wf.validate()
        if errs:
            raise HTTPException(422, detail={"graph_errors": errs})
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(422, detail=str(exc))
    with db_session(DB_PATH) as conn:
        if not get_device(conn, req.device_id):
            raise HTTPException(404, detail="Device not found")
    next_run = _parse_iso(req.first_run_at) if req.first_run_at else _now_utc()
    now = _iso(_now_utc())
    with scheduler_db_session(DB_PATH) as conn:
        cur = conn.execute("""
            INSERT INTO scheduler_jobs
              (device_id,name,description,graph_json,enabled,
               interval_seconds,cron_hour,cron_minute,next_run_at,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (req.device_id, req.name, req.description, json.dumps(req.graph_json),
              int(req.enabled), req.interval_seconds, req.cron_hour, req.cron_minute,
              _iso(next_run), now, now))
        row = conn.execute("SELECT * FROM scheduler_jobs WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)

@app.get("/scheduler/jobs")
async def api_list_jobs(device_id: Optional[int] = Query(None), enabled_only: bool = Query(False)):
    with scheduler_db_session(DB_PATH) as conn:
        q, params, conds = "SELECT * FROM scheduler_jobs", [], []
        if device_id is not None: conds.append("device_id=?"); params.append(device_id)
        if enabled_only:           conds.append("enabled=1")
        if conds: q += " WHERE " + " AND ".join(conds)
        rows = conn.execute(q + " ORDER BY id", params).fetchall()
    sched = get_scheduler()
    result = []
    for r in rows:
        d = dict(r); d["device_busy"] = sched.is_device_busy(d["device_id"])
        try: d["graph_json"] = json.loads(d["graph_json"])
        except Exception: pass
        result.append(d)
    return result

@app.get("/scheduler/jobs/{job_id}")
async def api_get_job(job_id: int):
    with scheduler_db_session(DB_PATH) as conn:
        row = conn.execute("SELECT * FROM scheduler_jobs WHERE id=?", (job_id,)).fetchone()
        if not row: raise HTTPException(404, detail="Job not found")
        d = dict(row)
        try: d["graph_json"] = json.loads(d["graph_json"])
        except Exception: pass
        d["device_busy"] = get_scheduler().is_device_busy(d["device_id"])
    return d

@app.patch("/scheduler/jobs/{job_id}")
async def api_update_job(job_id: int, req: JobUpdateRequest):
    with scheduler_db_session(DB_PATH) as conn:
        row = conn.execute("SELECT * FROM scheduler_jobs WHERE id=?", (job_id,)).fetchone()
        if not row: raise HTTPException(404, detail="Job not found")
        upd: dict = {}
        if req.name             is not None: upd["name"]             = req.name
        if req.description      is not None: upd["description"]      = req.description
        if req.enabled          is not None: upd["enabled"]          = int(req.enabled)
        if req.interval_seconds is not None: upd["interval_seconds"] = req.interval_seconds
        if req.cron_hour        is not None: upd["cron_hour"]        = req.cron_hour
        if req.cron_minute      is not None: upd["cron_minute"]      = req.cron_minute
        if req.next_run_at      is not None: upd["next_run_at"]      = req.next_run_at
        if req.graph_json       is not None:
            wf = WorkflowGraph.from_dict(req.graph_json)
            errs = wf.validate()
            if errs: raise HTTPException(422, detail={"graph_errors": errs})
            upd["graph_json"] = json.dumps(req.graph_json)
        if not upd: return dict(row)
        upd["updated_at"] = _iso(_now_utc())
        conn.execute(
            f"UPDATE scheduler_jobs SET {', '.join(f'{k}=?' for k in upd)} WHERE id=?",
            list(upd.values()) + [job_id])
        d = dict(conn.execute("SELECT * FROM scheduler_jobs WHERE id=?", (job_id,)).fetchone())
        try: d["graph_json"] = json.loads(d["graph_json"])
        except Exception: pass
    return d

@app.delete("/scheduler/jobs/{job_id}")
async def api_delete_job(job_id: int):
    with scheduler_db_session(DB_PATH) as conn:
        if not conn.execute("SELECT id FROM scheduler_jobs WHERE id=?", (job_id,)).fetchone():
            raise HTTPException(404, detail="Job not found")
        conn.execute("DELETE FROM scheduler_jobs WHERE id=?", (job_id,))
    return {"deleted": True, "job_id": job_id}

@app.post("/scheduler/jobs/{job_id}/enable")
async def api_enable_job(job_id: int):
    with scheduler_db_session(DB_PATH) as conn:
        conn.execute("UPDATE scheduler_jobs SET enabled=1, updated_at=? WHERE id=?",
                     (_iso(_now_utc()), job_id))
    return {"job_id": job_id, "enabled": True}

@app.post("/scheduler/jobs/{job_id}/disable")
async def api_disable_job(job_id: int):
    with scheduler_db_session(DB_PATH) as conn:
        conn.execute("UPDATE scheduler_jobs SET enabled=0, updated_at=? WHERE id=?",
                     (_iso(_now_utc()), job_id))
    return {"job_id": job_id, "enabled": False}

@app.post("/scheduler/jobs/{job_id}/trigger")
async def api_trigger_job(job_id: int):
    with scheduler_db_session(DB_PATH) as conn:
        if not conn.execute("SELECT id FROM scheduler_jobs WHERE id=?", (job_id,)).fetchone():
            raise HTTPException(404, detail="Job not found")
    if not get_scheduler().trigger_now(job_id):
        raise HTTPException(409, detail="Device busy with another run")
    return {"triggered": True, "job_id": job_id}


# ─── Scheduler runs ───────────────────────────────────────────────────────────

@app.get("/scheduler/runs")
async def api_list_runs(
    job_id:    Optional[int] = Query(None),
    device_id: Optional[int] = Query(None),
    outcome:   Optional[str] = Query(None),
    limit:     int           = Query(50, ge=1, le=500),
    skip:      int           = Query(0, ge=0),
):
    with scheduler_db_session(DB_PATH) as conn:
        q = "SELECT r.*, j.name as job_name FROM scheduler_runs r LEFT JOIN scheduler_jobs j ON j.id=r.job_id"
        params, conds = [], []
        if job_id    is not None: conds.append("r.job_id=?");    params.append(job_id)
        if device_id is not None: conds.append("r.device_id=?"); params.append(device_id)
        if outcome:               conds.append("r.outcome=?");   params.append(outcome)
        if conds: q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY r.started_at DESC LIMIT ? OFFSET ?"
        rows = conn.execute(q, params + [limit, skip]).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        for f in ("node_trace", "full_log"):
            if d.get(f):
                try: d[f] = json.loads(d[f])
                except Exception: pass
        result.append(d)
    return result

@app.get("/scheduler/runs/{run_id}")
async def api_get_run(run_id: int):
    with scheduler_db_session(DB_PATH) as conn:
        row = conn.execute("""
            SELECT r.*, j.name as job_name, j.description as job_description
            FROM scheduler_runs r LEFT JOIN scheduler_jobs j ON j.id=r.job_id
            WHERE r.id=?""", (run_id,)).fetchone()
        if not row: raise HTTPException(404, detail="Run not found")
        d = dict(row)
        for f in ("node_trace", "full_log", "report_json"):
            if d.get(f):
                try: d[f] = json.loads(d[f])
                except Exception: pass
    return d

@app.get("/scheduler/runs/{run_id}/report")
async def api_get_run_report(run_id: int):
    with scheduler_db_session(DB_PATH) as conn:
        row = conn.execute("SELECT report_json FROM scheduler_runs WHERE id=?", (run_id,)).fetchone()
        if not row or not row["report_json"]:
            raise HTTPException(404, detail="Run or report not found")
    return json.loads(row["report_json"])

@app.get("/scheduler/status")
async def api_scheduler_status():
    sched = get_scheduler()
    with scheduler_db_session(DB_PATH) as conn:
        tj   = conn.execute("SELECT COUNT(*) FROM scheduler_jobs").fetchone()[0]
        ej   = conn.execute("SELECT COUNT(*) FROM scheduler_jobs WHERE enabled=1").fetchone()[0]
        rr   = conn.execute("SELECT COUNT(*) FROM scheduler_runs WHERE outcome='running'").fetchone()[0]
        tr   = conn.execute("SELECT COUNT(*) FROM scheduler_runs").fetchone()[0]
        fr   = conn.execute("SELECT COUNT(*) FROM scheduler_runs WHERE outcome='failure'").fetchone()[0]
        next_due = conn.execute("""
            SELECT id,name,device_id,next_run_at FROM scheduler_jobs
            WHERE enabled=1 ORDER BY next_run_at ASC LIMIT 5
        """).fetchall()
    return {
        "running": sched.running, "total_jobs": tj, "enabled_jobs": ej,
        "running_runs": rr, "total_runs": tr, "failed_runs": fr,
        "next_due_jobs": [dict(r) for r in next_due],
        "recent_reports": sched.recent_reports[:10],
    }


# ─── Frontend (React/Vite build) ──────────────────────────────────────────────
#
# Serves frontend/dist (built via `npm run build`, outDir set to ../dist) as
# a static SPA: index.html at "/", hashed assets under "/assets", favicon.svg
# etc. at the root. Mounted last so it never shadows the API routes above.
#
# StaticFiles(html=True) alone only serves index.html for the mount root —
# a deep link like /instrument (no such file on disk) 404s instead of
# reaching the client-side router. SPAStaticFiles falls back to index.html
# for any path that isn't a real file, so TanStack Router can take over.

class SPAStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code == 404:
                return await super().get_response("index.html", scope)
            raise


FRONTEND_DIST = Path(__file__).resolve().parent / "dist"

if FRONTEND_DIST.is_dir():
    app.mount("/", SPAStaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")
else:
    log.warning(f"Frontend build not found at {FRONTEND_DIST} — run `npm run build` in frontend/")


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=CONFIG.app.host, port=APP_PORT, reload=CONFIG.app.reload)
