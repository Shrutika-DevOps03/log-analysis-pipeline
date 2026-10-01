"""
parse_and_load.py

Parses logs/server.log into structured fields and loads them into a SQLite
database (logs.db). Run generate_sample_logs.py first.
"""

import re
import sqlite3

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w\-.]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def classify(process, message):
    msg_lower = message.lower()
    if "failed password" in msg_lower:
        return "ERROR", "failed_login"
    if "accepted password" in msg_lower:
        return "INFO", "successful_login"
    if "warning" in msg_lower or "out of memory" in msg_lower:
        return "WARNING", "system_warning"
    if process == "nginx":
        if " 500 " in message or message.strip().endswith("500"):
            return "ERROR", "http_request"
        if " 404 " in message or message.strip().endswith("404"):
            return "WARNING", "http_request"
        return "INFO", "http_request"
    if process == "CRON":
        return "INFO", "cron_job"
    return "INFO", "other"


def parse_line(line):
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None
    data = match.groupdict()
    level, event_type = classify(data["process"], data["message"])
    ip_match = IP_PATTERN.search(data["message"])
    data["level"] = level
    data["event_type"] = event_type
    data["source_ip"] = ip_match.group(0) if ip_match else None
    return data


def create_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            host TEXT,
            process TEXT,
            pid TEXT,
            level TEXT,
            event_type TEXT,
            source_ip TEXT,
            message TEXT
        )
    """)
    conn.commit()


def load_logs(log_path="logs/server.log", db_path="logs.db"):
    conn = sqlite3.connect(db_path)
    create_table(conn)
    conn.execute("DELETE FROM logs")  # start fresh each run

    rows = []
    skipped = 0
    with open(log_path) as f:
        for line in f:
            parsed = parse_line(line)
            if parsed:
                rows.append((
                    parsed["timestamp"], parsed["host"], parsed["process"],
                    parsed["pid"], parsed["level"], parsed["event_type"],
                    parsed["source_ip"], parsed["message"],
                ))
            else:
                skipped += 1

    conn.executemany(
        """INSERT INTO logs (timestamp, host, process, pid, level, event_type, source_ip, message)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )
    conn.commit()
    conn.close()
    print(f"Loaded {len(rows)} rows into {db_path} ({skipped} lines skipped)")


if __name__ == "__main__":
    load_logs()
