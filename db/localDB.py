"""
SQLite persistence layer per dati TSI.

Schema:
  devices      → info strumento (model, serial, ip, ...)
  records      → campioni (1 riga = 1 record di misurazione)
  channels     → canali particelle per ogni record (16 max)
  sync_log     → log delle sincronizzazioni
"""

import sqlite3
import json
from datetime import datetime
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, List

from instrument.tsi_modbus import TSIDevice, TSIRecord
from config import CONFIG

DB_PATH = CONFIG.db_path   # canonical path, imported by other modules


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def db_session(db_path: Path = DB_PATH):
    conn = get_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Path = DB_PATH):
    """Crea le tabelle se non esistono."""
    with db_session(db_path) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ip              TEXT NOT NULL,
            port            INTEGER NOT NULL DEFAULT 502,
            model           TEXT,
            serial          TEXT,
            firmware_version INTEGER,
            flow_unit       TEXT,
            nominal_flow    REAL,
            num_channels    INTEGER,
            num_locations   INTEGER,
            num_recipes     INTEGER,
            has_data_integrity INTEGER DEFAULT 0,
            viable_counts   INTEGER DEFAULT 0,
            channel_sizes   TEXT,       -- JSON array
            locations       TEXT,       -- JSON object {id: name}
            last_seen       TEXT,
            last_sync       TEXT,
            total_records   INTEGER DEFAULT 0,
            UNIQUE(ip, port)
        );

        CREATE TABLE IF NOT EXISTS records (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id           INTEGER NOT NULL REFERENCES devices(id),
            rec_num             INTEGER NOT NULL,
            timestamp           TEXT NOT NULL,
            location_id         INTEGER,
            location_name       TEXT,
            flow_rate           REAL,
            flow_type           TEXT,
            sample_time_sec     INTEGER,
            count_mode          TEXT,
            unit_mode           TEXT,
            temperature         REAL,
            temp_unit           TEXT,
            humidity            REAL,
            velocity            REAL,
            flow                REAL,
            co2                 REAL,
            device_status       INTEGER,
            data_valid          INTEGER,
            flow_ok             INTEGER,
            laser_ok            INTEGER,
            optics_dirty        INTEGER,
            scatter_alert       INTEGER,
            calibration_corrupt INTEGER,
            service_alert       INTEGER,
            precision_flow_rate REAL,
            measurement_enabled INTEGER,
            imported_at         TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(device_id, rec_num)
        );

        CREATE TABLE IF NOT EXISTS channels (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id   INTEGER NOT NULL REFERENCES records(id) ON DELETE CASCADE,
            channel_idx INTEGER NOT NULL,
            size_um     REAL,
            count       INTEGER,
            alarm       INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS sync_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id       INTEGER REFERENCES devices(id),
            started_at      TEXT NOT NULL,
            finished_at     TEXT,
            records_read    INTEGER DEFAULT 0,
            records_new     INTEGER DEFAULT 0,
            status          TEXT DEFAULT 'running',
            error_msg       TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_records_device  ON records(device_id);
        CREATE INDEX IF NOT EXISTS idx_records_ts      ON records(timestamp);
        CREATE INDEX IF NOT EXISTS idx_channels_record ON channels(record_id);
        """)


# ─── Device CRUD ─────────────────────────────────────────────────────────────

def upsert_device(conn: sqlite3.Connection, device: TSIDevice) -> int:
    """Inserisce o aggiorna il device, restituisce l'id."""
    now = datetime.utcnow().isoformat()
    conn.execute("""
        INSERT INTO devices (ip, port, model, serial, firmware_version, flow_unit,
            nominal_flow, num_channels, num_locations, num_recipes,
            has_data_integrity, viable_counts, channel_sizes, locations,
            last_seen, last_sync, total_records)
        VALUES (:ip, :port, :model, :serial, :fw, :fu, :nf, :nc, :nl, :nr,
                :hdi, :vc, :cs, :locs, :now, :now, :tr)
        ON CONFLICT(ip, port) DO UPDATE SET
            model=excluded.model,
            serial=excluded.serial,
            firmware_version=excluded.firmware_version,
            flow_unit=excluded.flow_unit,
            nominal_flow=excluded.nominal_flow,
            num_channels=excluded.num_channels,
            num_locations=excluded.num_locations,
            num_recipes=excluded.num_recipes,
            has_data_integrity=excluded.has_data_integrity,
            viable_counts=excluded.viable_counts,
            channel_sizes=excluded.channel_sizes,
            locations=excluded.locations,
            last_seen=excluded.last_seen,
            last_sync=excluded.last_sync,
            total_records=excluded.total_records
    """, {
        "ip": device.ip, "port": device.port,
        "model": device.model, "serial": device.serial,
        "fw": device.firmware_version, "fu": device.flow_unit,
        "nf": device.nominal_flow, "nc": device.num_channels,
        "nl": device.num_locations, "nr": device.num_recipes,
        "hdi": int(device.has_data_integrity), "vc": int(device.viable_counts),
        "cs": json.dumps(device.channel_sizes),
        "locs": json.dumps(device.locations),
        "now": now, "tr": device.num_records,
    })
    row = conn.execute("SELECT id FROM devices WHERE ip=? AND port=?",
                       (device.ip, device.port)).fetchone()
    return row["id"]


def get_device(conn: sqlite3.Connection, device_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()


def list_devices(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    return conn.execute("SELECT * FROM devices ORDER BY id").fetchall()


# ─── Record CRUD ─────────────────────────────────────────────────────────────

def insert_record(conn: sqlite3.Connection, device_id: int, rec: TSIRecord) -> Optional[int]:
    """
    Inserisce un record di campione.
    Restituisce None se il record esiste già (UNIQUE device_id+rec_num).
    """
    try:
        cur = conn.execute("""
            INSERT OR IGNORE INTO records (
                device_id, rec_num, timestamp, location_id, location_name,
                flow_rate, flow_type, sample_time_sec, count_mode, unit_mode,
                temperature, temp_unit, humidity, velocity, flow, co2,
                device_status, data_valid, flow_ok, laser_ok, optics_dirty,
                scatter_alert, calibration_corrupt, service_alert,
                precision_flow_rate, measurement_enabled
            ) VALUES (
                :did, :rn, :ts, :lid, :lname,
                :fr, :ft, :st, :cm, :um,
                :temp, :tu, :hum, :vel, :fl, :co2,
                :ds, :dv, :fo, :lo, :od,
                :sa, :cc, :sva,
                :pfr, :me
            )
        """, {
            "did": device_id, "rn": rec.rec_num, "ts": rec.timestamp.isoformat(),
            "lid": rec.location_id, "lname": rec.location_name,
            "fr": rec.flow_rate, "ft": rec.flow_type, "st": rec.sample_time_sec,
            "cm": rec.count_mode, "um": rec.unit_mode,
            "temp": rec.temperature, "tu": rec.temp_unit,
            "hum": rec.humidity, "vel": rec.velocity,
            "fl": rec.flow, "co2": rec.co2,
            "ds": rec.device_status, "dv": int(rec.data_valid),
            "fo": int(rec.flow_ok), "lo": int(rec.laser_ok),
            "od": int(rec.optics_dirty), "sa": int(rec.scatter_alert),
            "cc": int(rec.calibration_corrupt), "sva": int(rec.service_alert),
            "pfr": rec.precision_flow_rate, "me": rec.measurement_enabled,
        })
        if cur.lastrowid == 0:
            return None
        record_id = cur.lastrowid
        # inserisci canali
        for idx, ch in enumerate(rec.channels):
            conn.execute("""
                INSERT INTO channels (record_id, channel_idx, size_um, count, alarm)
                VALUES (?, ?, ?, ?, ?)
            """, (record_id, idx, ch.size_um, ch.count, int(ch.alarm)))
        return record_id
    except sqlite3.IntegrityError:
        return None


def save_device_data(device: TSIDevice, db_path: Path = DB_PATH) -> dict:
    """Salva tutto il contenuto di un TSIDevice nel DB. Restituisce statistiche."""
    with db_session(db_path) as conn:
        device_id = upsert_device(conn, device)
        new_records = 0
        for rec in device.records:
            rid = insert_record(conn, device_id, rec)
            if rid is not None:
                new_records += 1
        return {
            "device_id": device_id,
            "records_read": len(device.records),
            "records_new": new_records,
            "records_duplicate": len(device.records) - new_records,
        }


# ─── Query helpers ────────────────────────────────────────────────────────────

def get_records_page(conn: sqlite3.Connection, device_id: int,
                     skip: int = 0, limit: int = 100,
                     from_ts: Optional[str] = None,
                     to_ts: Optional[str] = None) -> List[sqlite3.Row]:
    q = "SELECT * FROM records WHERE device_id=?"
    params: list = [device_id]
    if from_ts:
        q += " AND timestamp >= ?"; params.append(from_ts)
    if to_ts:
        q += " AND timestamp <= ?"; params.append(to_ts)
    q += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params += [limit, skip]
    return conn.execute(q, params).fetchall()


def get_channels_for_record(conn: sqlite3.Connection, record_id: int) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM channels WHERE record_id=? ORDER BY channel_idx",
        (record_id,)
    ).fetchall()


def get_record_count(conn: sqlite3.Connection, device_id: int) -> int:
    row = conn.execute("SELECT COUNT(*) as c FROM records WHERE device_id=?",
                       (device_id,)).fetchone()
    return row["c"] if row else 0


# ─── Misc helpers used by the API layer ───────────────────────────────────────

def get_or_create_device(conn: sqlite3.Connection, ip: str, port: int) -> int:
    """Ensures a devices row exists for (ip, port) and returns its id."""
    conn.execute(
        "INSERT OR IGNORE INTO devices (ip, port, last_seen) VALUES (?, ?, ?)",
        (ip, port, datetime.utcnow().isoformat()),
    )
    row = conn.execute("SELECT id FROM devices WHERE ip=? AND port=?", (ip, port)).fetchone()
    return row["id"]


def reset_device_records(conn: sqlite3.Connection, device_id: int):
    """Zeroes total_records after a clear_all_data() maintenance command."""
    conn.execute(
        "UPDATE devices SET total_records=0, last_sync=? WHERE id=?",
        (datetime.utcnow().isoformat(), device_id),
    )


def get_channel_stats(conn: sqlite3.Connection, device_id: int,
                      from_ts: Optional[str] = None, to_ts: Optional[str] = None) -> List[sqlite3.Row]:
    q = """
        SELECT ch.channel_idx, ch.size_um,
               COUNT(ch.id) AS samples, SUM(ch.count) AS total_count,
               AVG(ch.count) AS avg_count, MAX(ch.count) AS max_count,
               MIN(ch.count) AS min_count, SUM(ch.alarm) AS alarm_events
        FROM channels ch JOIN records r ON r.id=ch.record_id
        WHERE r.device_id=?"""
    params: list = [device_id]
    if from_ts:
        q += " AND r.timestamp>=?"; params.append(from_ts)
    if to_ts:
        q += " AND r.timestamp<=?"; params.append(to_ts)
    q += " GROUP BY ch.channel_idx, ch.size_um ORDER BY ch.channel_idx"
    return conn.execute(q, params).fetchall()


def get_sync_log(conn: sqlite3.Connection, limit: int = 50) -> List[sqlite3.Row]:
    return conn.execute("""
        SELECT sl.*, d.ip, d.model FROM sync_log sl
        LEFT JOIN devices d ON d.id=sl.device_id
        ORDER BY sl.started_at DESC LIMIT ?
    """, (limit,)).fetchall()


def record_belongs_to_device(conn: sqlite3.Connection, record_id: int, device_id: int) -> bool:
    row = conn.execute(
        "SELECT id FROM records WHERE id=? AND device_id=?", (record_id, device_id)
    ).fetchone()
    return row is not None


# ─── Sync log ─────────────────────────────────────────────────────────────────

def start_sync_log(conn: sqlite3.Connection, device_id: int) -> int:
    cur = conn.execute("""
        INSERT INTO sync_log (device_id, started_at, status)
        VALUES (?, ?, 'running')
    """, (device_id, datetime.utcnow().isoformat()))
    conn.commit()
    return cur.lastrowid


def finish_sync_log(conn: sqlite3.Connection, log_id: int,
                    records_read: int, records_new: int,
                    status: str = "ok", error_msg: str = None):
    conn.execute("""
        UPDATE sync_log
        SET finished_at=?, records_read=?, records_new=?, status=?, error_msg=?
        WHERE id=?
    """, (datetime.utcnow().isoformat(), records_read, records_new,
          status, error_msg, log_id))
    conn.commit()
