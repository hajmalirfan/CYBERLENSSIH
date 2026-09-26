"""Initialize local securix_db in PostgreSQL if possible."""
import os
import sys
import psycopg2

URL_ROOT = "postgresql://postgres:venkat%402007VK@localhost:5432/postgres"
URL_SECURIX = "postgresql://postgres:venkat%402007VK@localhost:5432/securix_db"

print("Checking PostgreSQL connection...")
try:
    conn = psycopg2.connect(URL_ROOT)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM pg_database WHERE datname='securix_db'")
    exists = cur.fetchone()
    print("securix_db exists:", bool(exists))
    if not exists:
        cur.execute("CREATE DATABASE securix_db")
        print("Created securix_db database successfully!")
    cur.close()
    conn.close()
except Exception as e:
    print("Postgres root connection error:", e)
