"""
Scheduler
=========
Background daemon thread that:
  1. Reads all enabled scheduler_jobs from SQLite every POLL_INTERVAL seconds.
  2. For each job whose next_run_at <= now: acquires device lock, connects,
     runs the workflow graph, saves a run report, schedules the next run.
  3. Never runs two jobs for the same device concurrently (per-device lock).
  4. Is started once at app startup (lifespan) and stopped at shutdown.

DB tables added here (appended to database.init_db):
  scheduler_jobs   → job definitions (device, graph, schedule)
  scheduler_runs   → per-run records with full report
"""

import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from db.localDB import db_session, get_device, DB_PATH
from instrument.tsi_modbus import TSIClient
from backthread.workflow import WorkflowGraph, run_workflow
from config import CONFIG

log = logging.getLogger("scheduler")

POLL_INTERVAL = CONFIG.scheduler.poll_interval_seconds   # seconds between DB polls
MAX_DEVICE_TIMEOUT = 60.0   # socket timeout for scheduler connections


# ─── Additional DB schema (call init_scheduler_db after init_db) ──────────────

SCHEDULER_SCHEMA = """
CREATE TABLE IF NOT EXISTS scheduler_jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       INTEGER NOT NULL REFERENCES devices(id),
    name            TEXT NOT NULL,
    description     TEXT,
    graph_json      TEXT NOT NULL,          -- serialized WorkflowGraph
    enabled         INTEGER NOT NULL DEFAULT 1,
    -- schedule: cron-like but simplified
    -- interval_seconds: run every N seconds (>= 60)
    -- OR use cron_hour + cron_minute for daily scheduling
    interval_seconds INTEGER,               -- NULL = use cron fields
    cron_hour       INTEGER,                -- 0-23, NULL = any
    cron_minute     INTEGER DEFAULT 0,      -- 0-59
    -- state
    next_run_at     TEXT,                   -- ISO UTC datetime
    last_run_at     TEXT,
    last_run_id     INTEGER,
    total_runs      INTEGER DEFAULT 0,
    total_failures  INTEGER DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scheduler_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id          INTEGER NOT NULL REFERENCES scheduler_jobs(id),
    device_id       INTEGER NOT NULL REFERENCES devices(id),
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    outcome         TEXT DEFAULT 'running',   -- running | success | failure
    node_trace      TEXT,                     -- JSON array of executed node ids
    records_new     INTEGER DEFAULT 0,
    error_summary   TEXT,
    full_log        TEXT,                     -- JSON array of log lines
    report_json     TEXT                      -- full structured report
);

CREATE INDEX IF NOT EXISTS idx_runs_job    ON scheduler_runs(job_id);
CREATE INDEX IF NOT EXISTS idx_runs_device ON scheduler_runs(device_id);
CREATE INDEX IF NOT EXISTS idx_jobs_device ON scheduler_jobs(device_id);
"""


def init_scheduler_db(db_path: Path = DB_PATH):
    with db_session(db_path) as conn:
        conn.executescript(SCHEDULER_SCHEMA)


# ─── Schedule helpers ─────────────────────────────────────────────────────────

def _next_run(job: dict, after: datetime) -> datetime:
    """
    Compute next run datetime for a job dict.
    - interval_seconds: simple periodic
    - cron_hour + cron_minute: daily at that time
    """
    iv = job.get("interval_seconds")
    if iv and iv > 0:
        return after + timedelta(seconds=iv)

    ch = job.get("cron_hour")
    cm = job.get("cron_minute") or 0
    if ch is not None:
        base = after.replace(hour=int(ch), minute=int(cm), second=0, microsecond=0)
        if base <= after:
            base += timedelta(days=1)
        return base

    # fallback: 1 hour
    return after + timedelta(hours=1)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse_iso(s: str) -> datetime:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ─── Run report builder ───────────────────────────────────────────────────────

def _build_report(job: dict, ctx: dict, run_id: int) -> dict:
    """Build a structured JSON report from job metadata + execution context."""
    return {
        "run_id":       run_id,
        "job_id":       job["id"],
        "job_name":     job["name"],
        "device_id":    ctx["device_id"],
        "ip":           ctx["ip"],
        "started_at":   ctx["started_at"],
        "finished_at":  ctx.get("finished_at"),
        "outcome":      ctx.get("outcome", "unknown"),
        "node_trace":   ctx.get("node_trace", []),
        "records_new":  ctx.get("records_new", 0),
        "device_status": ctx.get("status"),
        "last_error":   ctx.get("error"),
        "log_lines":    ctx.get("log", []),
        "duration_sec": _duration_sec(ctx),
    }


def _duration_sec(ctx: dict) -> Optional[float]:
    try:
        a = _parse_iso(ctx["started_at"])
        b = _parse_iso(ctx.get("finished_at", ctx["started_at"]))
        return round((b - a).total_seconds(), 1)
    except Exception:
        return None


# ─── Core executor ────────────────────────────────────────────────────────────

def execute_job(job: dict, db_path: Path = DB_PATH) -> dict:
    """
    Run a single scheduler job:
      - parse graph
      - open a dedicated TCP connection
      - execute workflow
      - write run record to DB
      - update job stats + next_run_at
    Returns the run report dict.
    """
    now = _now_utc()
    device_id = job["device_id"]

    with db_session(db_path) as conn:
        dev = get_device(conn, device_id)
        if not dev:
            raise RuntimeError(f"Device {device_id} not found in DB")

    ip   = dev["ip"]
    port = dev["port"]

    graph_dict = json.loads(job["graph_json"])
    graph = WorkflowGraph.from_dict(graph_dict)
    errs = graph.validate()
    if errs:
        raise ValueError(f"Invalid graph: {'; '.join(errs)}")

    # Build execution context
    ctx: dict = {
        "device_id":  device_id,
        "ip":         ip,
        "port":       port,
        "log":        [],
        "started_at": _iso(now),
        "node_trace": [],
        "records_new": 0,
        "status":     None,
        "ok":         True,
        "error":      None,
        "outcome":    "unknown",
    }

    # Create run record (status = running)
    with db_session(db_path) as conn:
        cur = conn.execute("""
            INSERT INTO scheduler_runs
              (job_id, device_id, started_at, outcome)
            VALUES (?, ?, ?, 'running')
        """, (job["id"], device_id, ctx["started_at"]))
        run_id = cur.lastrowid

    log.info(f"[job={job['id']}][run={run_id}] starting on device {ip}")

    # Execute
    client = TSIClient(ip, port, MAX_DEVICE_TIMEOUT)
    try:
        client.connect()
        run_workflow(graph, ctx, client)
    except Exception as exc:
        ctx["ok"] = False
        ctx["error"] = str(exc)
        ctx["outcome"] = "failure"
        ctx["log"].append(f"[FATAL] {exc}")
        log.error(f"[run={run_id}] fatal error: {exc}", exc_info=True)
    finally:
        try:
            client.disconnect()
        except Exception:
            pass

    ctx["finished_at"] = _iso(_now_utc())
    outcome = ctx.get("outcome", "failure" if not ctx["ok"] else "success")
    if outcome == "unknown":
        outcome = "success" if ctx["ok"] else "failure"
    ctx["outcome"] = outcome

    report = _build_report(job, ctx, run_id)

    # Persist run record
    with db_session(db_path) as conn:
        conn.execute("""
            UPDATE scheduler_runs SET
                finished_at   = ?,
                outcome       = ?,
                node_trace    = ?,
                records_new   = ?,
                error_summary = ?,
                full_log      = ?,
                report_json   = ?
            WHERE id = ?
        """, (
            ctx["finished_at"],
            outcome,
            json.dumps(ctx.get("node_trace", [])),
            ctx.get("records_new", 0),
            ctx.get("error"),
            json.dumps(ctx.get("log", [])),
            json.dumps(report),
            run_id,
        ))
        # Update job stats
        next_run = _iso(_next_run(job, _now_utc()))
        conn.execute("""
            UPDATE scheduler_jobs SET
                last_run_at      = ?,
                last_run_id      = ?,
                next_run_at      = ?,
                total_runs       = total_runs + 1,
                total_failures   = total_failures + ?,
                updated_at       = ?
            WHERE id = ?
        """, (
            ctx["finished_at"],
            run_id,
            next_run,
            1 if outcome == "failure" else 0,
            _iso(_now_utc()),
            job["id"],
        ))

    log.info(f"[run={run_id}] outcome={outcome}, records_new={ctx.get('records_new',0)}, "
             f"duration={_duration_sec(ctx)}s")
    return report


# ─── Scheduler daemon ─────────────────────────────────────────────────────────

class Scheduler:
    """
    Background thread that polls the DB and runs due jobs.
    One thread per device (device_locks prevents concurrent runs on same device).
    """

    def __init__(self, db_path: Path = DB_PATH, poll_interval: int = POLL_INTERVAL):
        self.db_path = db_path
        self.poll_interval = poll_interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._device_locks: dict[int, threading.Lock] = {}
        self._lock_registry = threading.Lock()
        # in-memory run status for SSE / API polling
        self.recent_reports: list[dict] = []   # last 100 reports (newest first)
        self._reports_lock = threading.Lock()

    def _get_device_lock(self, device_id: int) -> threading.Lock:
        with self._lock_registry:
            if device_id not in self._device_locks:
                self._device_locks[device_id] = threading.Lock()
            return self._device_locks[device_id]

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="tsi-scheduler", daemon=True)
        self._thread.start()
        log.info("Scheduler started")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=30)
        log.info("Scheduler stopped")

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as exc:
                log.error(f"Scheduler tick error: {exc}", exc_info=True)
            self._stop.wait(self.poll_interval)

    def _tick(self):
        """One poll cycle: find due jobs and launch them."""
        now_iso = _iso(_now_utc())
        with db_session(self.db_path) as conn:
            due = conn.execute("""
                SELECT * FROM scheduler_jobs
                WHERE enabled = 1
                  AND (next_run_at IS NULL OR next_run_at <= ?)
                ORDER BY next_run_at ASC
            """, (now_iso,)).fetchall()

        for row in due:
            job = dict(row)
            device_id = job["device_id"]
            lock = self._get_device_lock(device_id)

            if not lock.acquire(blocking=False):
                log.debug(f"Job {job['id']}: device {device_id} busy, skipping this tick")
                continue

            # Mark job as running immediately (update next_run_at to avoid re-pick)
            with db_session(self.db_path) as conn:
                conn.execute("""
                    UPDATE scheduler_jobs
                    SET next_run_at = ?, updated_at = ?
                    WHERE id = ?
                """, (_iso(_now_utc() + timedelta(seconds=86400 * 365)),
                      _iso(_now_utc()), job["id"]))

            def _run(j=job, lk=lock):
                try:
                    report = execute_job(j, self.db_path)
                    with self._reports_lock:
                        self.recent_reports.insert(0, report)
                        self.recent_reports = self.recent_reports[:100]
                except Exception as exc:
                    log.error(f"Job {j['id']} execution error: {exc}", exc_info=True)
                finally:
                    lk.release()

            t = threading.Thread(target=_run, daemon=True,
                                 name=f"job-{job['id']}-dev{device_id}")
            t.start()

    def trigger_now(self, job_id: int) -> bool:
        """
        Immediately trigger a job bypassing the schedule.
        Returns False if device is already running a job.
        """
        with db_session(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM scheduler_jobs WHERE id=?", (job_id,)
            ).fetchone()
        if not row:
            return False
        job = dict(row)
        lock = self._get_device_lock(job["device_id"])
        if not lock.acquire(blocking=False):
            return False

        def _run(j=job, lk=lock):
            try:
                report = execute_job(j, self.db_path)
                with self._reports_lock:
                    self.recent_reports.insert(0, report)
                    self.recent_reports = self.recent_reports[:100]
            except Exception as exc:
                log.error(f"Trigger job {j['id']} error: {exc}", exc_info=True)
            finally:
                lk.release()

        t = threading.Thread(target=_run, daemon=True,
                             name=f"trigger-job-{job_id}")
        t.start()
        return True

    def is_device_busy(self, device_id: int) -> bool:
        lock = self._get_device_lock(device_id)
        acquired = lock.acquire(blocking=False)
        if acquired:
            lock.release()
        return not acquired

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


# ─── Singleton ────────────────────────────────────────────────────────────────

_scheduler: Optional[Scheduler] = None


def get_scheduler() -> Scheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = Scheduler()
    return _scheduler
