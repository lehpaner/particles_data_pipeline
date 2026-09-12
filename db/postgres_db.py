"""
PostgreSQL persistence layer per dati TSI.

Mirrors db.localDB's public API (same function names/signatures) so
db.database can dispatch to either backend based on config.yaml's
`database.driver` setting. Only imported when driver = "postgresql" —
psycopg2 is not a hard dependency for SQLite-only installs.

Tables are equivalent to db.localDB's (see that module's docstring),
adapted to PostgreSQL syntax (SERIAL keys, NOW() defaults, ON CONFLICT
... DO NOTHING/DO UPDATE with RETURNING instead of sqlite's
INSERT OR IGNORE + lastrowid), and created under a dedicated schema
(config.yaml's database.postgres.schema, default "bpfc") rather than
the default "public" schema.
"""

import json
from contextlib import contextmanager
from datetime import datetime
from typing import Optional, List

from instrument.tsi_modbus import TSIDevice, TSIRecord
from config import CONFIG

try:
    import psycopg2
    import psycopg2.extras
    _IMPORT_ERROR = None
except ImportError as exc:  # pragma: no cover - exercised only when driver=postgresql without the package
    psycopg2 = None
    _IMPORT_ERROR = exc


def _require_psycopg2():
    if psycopg2 is None:
        raise RuntimeError(
            "config.yaml sets database.driver: postgresql but the 'psycopg2-binary' "
            "package is not installed. Run: pip install psycopg2-binary"
        ) from _IMPORT_ERROR


# All tables live under this schema (config.yaml: database.postgres.schema).
SCHEMA   = CONFIG.database.postgres.schema
DEVICES  = f"{SCHEMA}.devices"
RECORDS  = f"{SCHEMA}.records"
CHANNELS = f"{SCHEMA}.channels"
SYNC_LOG = f"{SCHEMA}.sync_log"


def get_connection(_unused=None):
    """
    Opens a new PostgreSQL connection using config.yaml's database.postgres
    settings. The positional argument is accepted (and ignored) so callers
    written for db.localDB's `db_session(DB_PATH)` convention work unchanged.
    """
    _require_psycopg2()
    conn = psycopg2.connect(CONFIG.postgres_dsn, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn


@contextmanager
def db_session(_unused=None):
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(_unused=None):
    """Crea lo schema e le tabelle se non esistono."""
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute(f"""
        CREATE SCHEMA IF NOT EXISTS {SCHEMA};

        CREATE TABLE IF NOT EXISTS {DEVICES} (
            id              SERIAL PRIMARY KEY,
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
            locations       TEXT,       -- JSON object {{id: name}}
            last_seen       TEXT,
            last_sync       TEXT,
            total_records   INTEGER DEFAULT 0,
            UNIQUE(ip, port)
        );

        CREATE TABLE IF NOT EXISTS {RECORDS} (
            id                  SERIAL PRIMARY KEY,
            device_id           INTEGER NOT NULL REFERENCES {DEVICES}(id),
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
            imported_at         TEXT NOT NULL DEFAULT NOW()::text,
            UNIQUE(device_id, rec_num)
        );

        CREATE TABLE IF NOT EXISTS {CHANNELS} (
            id          SERIAL PRIMARY KEY,
            record_id   INTEGER NOT NULL REFERENCES {RECORDS}(id) ON DELETE CASCADE,
            channel_idx INTEGER NOT NULL,
            size_um     REAL,
            count       INTEGER,
            alarm       INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS {SYNC_LOG} (
            id              SERIAL PRIMARY KEY,
            device_id       INTEGER REFERENCES {DEVICES}(id),
            started_at      TEXT NOT NULL,
            finished_at     TEXT,
            records_read    INTEGER DEFAULT 0,
            records_new     INTEGER DEFAULT 0,
            status          TEXT DEFAULT 'running',
            error_msg       TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_records_device  ON {RECORDS}(device_id);
        CREATE INDEX IF NOT EXISTS idx_records_ts      ON {RECORDS}(timestamp);
        CREATE INDEX IF NOT EXISTS idx_channels_record ON {CHANNELS}(record_id);
        """)
        cur.close()


# ─── Device CRUD ─────────────────────────────────────────────────────────────

def upsert_device(conn, device: TSIDevice) -> int:
    """Inserisce o aggiorna il device, restituisce l'id."""
    now = datetime.utcnow().isoformat()
    cur = conn.cursor()
    cur.execute(f"""
        INSERT INTO {DEVICES} (ip, port, model, serial, firmware_version, flow_unit,
            nominal_flow, num_channels, num_locations, num_recipes,
            has_data_integrity, viable_counts, channel_sizes, locations,
            last_seen, last_sync, total_records)
        VALUES (%(ip)s, %(port)s, %(model)s, %(serial)s, %(fw)s, %(fu)s, %(nf)s, %(nc)s, %(nl)s, %(nr)s,
                %(hdi)s, %(vc)s, %(cs)s, %(locs)s, %(now)s, %(now)s, %(tr)s)
        ON CONFLICT (ip, port) DO UPDATE SET
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
        RETURNING id
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
    return cur.fetchone()["id"]


def get_device(conn, device_id: int):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM {DEVICES} WHERE id=%s", (device_id,))
    return cur.fetchone()


def list_devices(conn) -> List[dict]:
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM {DEVICES} ORDER BY id")
    return cur.fetchall()


# ─── Record CRUD ─────────────────────────────────────────────────────────────

def insert_record(conn, device_id: int, rec: TSIRecord) -> Optional[int]:
    """
    Inserisce un record di campione.
    Restituisce None se il record esiste già (UNIQUE device_id+rec_num).
    """
    cur = conn.cursor()
    cur.execute(f"""
        INSERT INTO {RECORDS} (
            device_id, rec_num, timestamp, location_id, location_name,
            flow_rate, flow_type, sample_time_sec, count_mode, unit_mode,
            temperature, temp_unit, humidity, velocity, flow, co2,
            device_status, data_valid, flow_ok, laser_ok, optics_dirty,
            scatter_alert, calibration_corrupt, service_alert,
            precision_flow_rate, measurement_enabled
        ) VALUES (
            %(did)s, %(rn)s, %(ts)s, %(lid)s, %(lname)s,
            %(fr)s, %(ft)s, %(st)s, %(cm)s, %(um)s,
            %(temp)s, %(tu)s, %(hum)s, %(vel)s, %(fl)s, %(co2)s,
            %(ds)s, %(dv)s, %(fo)s, %(lo)s, %(od)s,
            %(sa)s, %(cc)s, %(sva)s,
            %(pfr)s, %(me)s
        )
        ON CONFLICT (device_id, rec_num) DO NOTHING
        RETURNING id
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
    row = cur.fetchone()
    if row is None:
        return None
    record_id = row["id"]
    for idx, ch in enumerate(rec.channels):
        cur.execute(f"""
            INSERT INTO {CHANNELS} (record_id, channel_idx, size_um, count, alarm)
            VALUES (%s, %s, %s, %s, %s)
        """, (record_id, idx, ch.size_um, ch.count, int(ch.alarm)))
    return record_id


def save_device_data(device: TSIDevice, _unused=None) -> dict:
    """Salva tutto il contenuto di un TSIDevice nel DB. Restituisce statistiche."""
    with db_session() as conn:
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

def get_records_page(conn, device_id: int,
                     skip: int = 0, limit: int = 100,
                     from_ts: Optional[str] = None,
                     to_ts: Optional[str] = None) -> List[dict]:
    q = f"SELECT * FROM {RECORDS} WHERE device_id=%s"
    params: list = [device_id]
    if from_ts:
        q += " AND timestamp >= %s"; params.append(from_ts)
    if to_ts:
        q += " AND timestamp <= %s"; params.append(to_ts)
    q += " ORDER BY timestamp DESC LIMIT %s OFFSET %s"
    params += [limit, skip]
    cur = conn.cursor()
    cur.execute(q, params)
    return cur.fetchall()


def get_channels_for_record(conn, record_id: int) -> List[dict]:
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM {CHANNELS} WHERE record_id=%s ORDER BY channel_idx", (record_id,))
    return cur.fetchall()


def get_record_count(conn, device_id: int) -> int:
    cur = conn.cursor()
    cur.execute(f"SELECT COUNT(*) as c FROM {RECORDS} WHERE device_id=%s", (device_id,))
    row = cur.fetchone()
    return row["c"] if row else 0


# ─── Misc helpers used by the API layer ───────────────────────────────────────

def get_or_create_device(conn, ip: str, port: int) -> int:
    """Ensures a devices row exists for (ip, port) and returns its id."""
    cur = conn.cursor()
    cur.execute(f"""
        INSERT INTO {DEVICES} (ip, port, last_seen) VALUES (%s, %s, %s)
        ON CONFLICT (ip, port) DO NOTHING
    """, (ip, port, datetime.utcnow().isoformat()))
    cur.execute(f"SELECT id FROM {DEVICES} WHERE ip=%s AND port=%s", (ip, port))
    return cur.fetchone()["id"]


def reset_device_records(conn, device_id: int):
    """Zeroes total_records after a clear_all_data() maintenance command."""
    cur = conn.cursor()
    cur.execute(
        f"UPDATE {DEVICES} SET total_records=0, last_sync=%s WHERE id=%s",
        (datetime.utcnow().isoformat(), device_id),
    )


def get_channel_stats(conn, device_id: int,
                      from_ts: Optional[str] = None, to_ts: Optional[str] = None) -> List[dict]:
    q = f"""
        SELECT ch.channel_idx, ch.size_um,
               COUNT(ch.id) AS samples, SUM(ch.count) AS total_count,
               AVG(ch.count) AS avg_count, MAX(ch.count) AS max_count,
               MIN(ch.count) AS min_count, SUM(ch.alarm) AS alarm_events
        FROM {CHANNELS} ch JOIN {RECORDS} r ON r.id=ch.record_id
        WHERE r.device_id=%s"""
    params: list = [device_id]
    if from_ts:
        q += " AND r.timestamp>=%s"; params.append(from_ts)
    if to_ts:
        q += " AND r.timestamp<=%s"; params.append(to_ts)
    q += " GROUP BY ch.channel_idx, ch.size_um ORDER BY ch.channel_idx"
    cur = conn.cursor()
    cur.execute(q, params)
    return cur.fetchall()


def get_sync_log(conn, limit: int = 50) -> List[dict]:
    cur = conn.cursor()
    cur.execute(f"""
        SELECT sl.*, d.ip, d.model FROM {SYNC_LOG} sl
        LEFT JOIN {DEVICES} d ON d.id=sl.device_id
        ORDER BY sl.started_at DESC LIMIT %s
    """, (limit,))
    return cur.fetchall()


def record_belongs_to_device(conn, record_id: int, device_id: int) -> bool:
    cur = conn.cursor()
    cur.execute(f"SELECT id FROM {RECORDS} WHERE id=%s AND device_id=%s", (record_id, device_id))
    return cur.fetchone() is not None


# ─── Sync log ─────────────────────────────────────────────────────────────────

def start_sync_log(conn, device_id: int) -> int:
    cur = conn.cursor()
    cur.execute(f"""
        INSERT INTO {SYNC_LOG} (device_id, started_at, status)
        VALUES (%s, %s, 'running')
        RETURNING id
    """, (device_id, datetime.utcnow().isoformat()))
    row = cur.fetchone()
    conn.commit()
    return row["id"]


def finish_sync_log(conn, log_id: int,
                    records_read: int, records_new: int,
                    status: str = "ok", error_msg: str = None):
    cur = conn.cursor()
    cur.execute(f"""
        UPDATE {SYNC_LOG}
        SET finished_at=%s, records_read=%s, records_new=%s, status=%s, error_msg=%s
        WHERE id=%s
    """, (datetime.utcnow().isoformat(), records_read, records_new,
          status, error_msg, log_id))
    conn.commit()
