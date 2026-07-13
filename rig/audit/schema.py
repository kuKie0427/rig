"""Loader for the audit-log DDL.

Schema is defined in `schema.sql` (per DIRECTIONS.md § Phase 3); this
module exposes it as a `SCHEMA_SQL` constant for `writer.py`.

Editing `schema.sql` is the single source of truth; alembic
migrations (in `rig/audit/migrations/`) MUST be kept consistent.
"""

from importlib import resources

with resources.files("rig.audit").joinpath("schema.sql").open("r", encoding="utf-8") as fh:
    SCHEMA_SQL = fh.read()
