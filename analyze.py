"""
analyze.py

Runs SQL queries against logs.db to produce a summary report and
flag potential brute-force login attempts.
"""

import sqlite3

DB_PATH = "logs.db"


def run_report():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    print("=" * 50)
    print("LOG ANALYSIS REPORT")
    print("=" * 50)

    print("\n-- Events by level --")
    for level, count in cur.execute(
        "SELECT level, COUNT(*) FROM logs GROUP BY level ORDER BY COUNT(*) DESC"
    ):
        print(f"{level:10} {count}")

    print("\n-- Events by type --")
    for event_type, count in cur.execute(
        "SELECT event_type, COUNT(*) FROM logs GROUP BY event_type ORDER BY COUNT(*) DESC"
    ):
        print(f"{event_type:20} {count}")

    print("\n-- Top source IPs by failed logins --")
    for ip, count in cur.execute("""
        SELECT source_ip, COUNT(*) as attempts
        FROM logs
        WHERE event_type = 'failed_login' AND source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY attempts DESC
        LIMIT 5
    """):
        flag = "  <-- possible brute force" if count >= 10 else ""
        print(f"{ip:18} {count} failed attempts{flag}")

    print("\n-- HTTP server errors --")
    cur.execute("""
        SELECT COUNT(*) FROM logs
        WHERE event_type = 'http_request' AND level = 'ERROR'
    """)
    print(f"Total server errors: {cur.fetchone()[0]}")

    print("\n-- Disk / system warnings --")
    cur.execute("SELECT COUNT(*) FROM logs WHERE event_type = 'system_warning'")
    print(f"Total system warnings: {cur.fetchone()[0]}")

    conn.close()


if __name__ == "__main__":
    run_report()
