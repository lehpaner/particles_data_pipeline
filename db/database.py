"""
Database driver dispatcher.

Selects the SQLite (db.localDB, the original/default implementation) or
PostgreSQL (db.postgres_db) backend based on config.yaml's
`database.driver` setting, and re-exports one driver-agnostic API.

Application code should import persistence functions from here — not from
db.localDB or db.postgres_db directly — so that switching drivers is a
config.yaml change only. psycopg2 is imported lazily (only when
driver = "postgresql") so a SQLite-only install has no extra dependency.
"""

import logging

from config import CONFIG

log = logging.getLogger("db")

DRIVER = CONFIG.database.driver.strip().lower()

if DRIVER == "postgresql":
    from db.postgres_db import (
        get_connection, db_session, init_db,
        upsert_device, get_device, list_devices,
        insert_record, save_device_data,
        get_records_page, get_channels_for_record, get_record_count,
        start_sync_log, finish_sync_log,
        get_or_create_device, reset_device_records,
        get_channel_stats, get_sync_log, record_belongs_to_device,
    )
    DB_PATH = None  # not applicable — connection params come from config.database.postgres

elif DRIVER == "sqlite":
    from db.localDB import (
        get_connection, db_session, init_db,
        upsert_device, get_device, list_devices,
        insert_record, save_device_data,
        get_records_page, get_channels_for_record, get_record_count,
        start_sync_log, finish_sync_log,
        get_or_create_device, reset_device_records,
        get_channel_stats, get_sync_log, record_belongs_to_device,
        DB_PATH,
    )

else:
    raise ValueError(
        f"Unknown database.driver '{DRIVER}' in config.yaml — expected 'sqlite' or 'postgresql'"
    )

log.info(f"Database driver: {DRIVER}")
