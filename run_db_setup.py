"""Run securix_db_setup.sql against local PostgreSQL securix_db."""
import os
import psycopg2

URL_SECURIX = "postgresql://postgres:venkat%402007VK@localhost:5432/securix_db"
SQL_FILE = os.path.join(os.path.dirname(__file__), "securix_db_setup.sql")

print("Executing securix_db_setup.sql...")
with open(SQL_FILE, "r", encoding="utf-8") as f:
    sql_script = f.read()

conn = psycopg2.connect(URL_SECURIX)
conn.autocommit = True
cur = conn.cursor()

# Split by statements or execute in blocks
try:
    cur.execute(sql_script)
    print("securix_db_setup.sql executed successfully!")
except Exception as e:
    print("Error executing full script, trying line-by-line or statement:", e)

# Check tables created
cur.execute("""
    SELECT table_name FROM information_schema.tables 
    WHERE table_schema = 'public' ORDER BY table_name;
""")
tables = [r[0] for r in cur.fetchall()]
print(f"Tables in securix_db ({len(tables)}):", tables)

for t in ["assets", "findings", "compliance_verdicts", "workflow_runs", "scans", "risk_queue"]:
    if t in tables:
        cur.execute(f"SELECT COUNT(*) FROM {t}")
        count = cur.fetchone()[0]
        print(f"  {t} rows: {count}")

cur.close()
conn.close()
