"""Loader for the L1 schema DDL.

The schema lives in `schema.sql` (per DIRECTIONS.md § Phase 2) and is
exposed here as a module-level constant so `diagnostic.py` can apply
it via `conn.executescript(rig.alert.schema.SCHEMA_SQL)`.

Single source of truth: editing `schema.sql` is sufficient; the
Python re-reads the file at import time.
"""

from importlib import resources

with resources.files("rig.alert").joinpath("schema.sql").open("r", encoding="utf-8") as fh:
    SCHEMA_SQL = fh.read()
