from __future__ import annotations
import os
from psycopg import Connection
from psycopg.rows import dict_row

def get_conn() -> Connection:
    dsn = os.environ["DATABASE_URL"]
    return Connection.connect(dsn, row_factory=dict_row)

