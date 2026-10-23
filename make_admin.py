import sqlite3
import sys
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit("Usage: python make_admin.py email@example.com")
db_path = Path(__file__).resolve().parent / "trustvault.db"
if not db_path.exists():
    raise SystemExit("Database not found. Start the app and register the user first.")
with sqlite3.connect(db_path) as con:
    cur = con.execute("UPDATE users SET role='admin' WHERE email=? COLLATE NOCASE", (sys.argv[1].strip(),))
    if cur.rowcount != 1:
        raise SystemExit("No matching user found.")
print("User promoted to admin. Restart the app if it is running.")
