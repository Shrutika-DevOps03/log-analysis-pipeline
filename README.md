# Server Log Analysis Pipeline

A beginner-friendly project showing the full pipeline: **Linux logs → Python parsing → SQL storage → SQL analysis**.

## What it does
1. `generate_sample_logs.py` creates a realistic Linux-style log file (SSH logins, nginx requests, cron jobs, kernel/disk warnings) — including a simulated brute-force SSH attack.
2. `parse_and_load.py` reads the log file, extracts fields (timestamp, process, level, event type, source IP) with regex, and loads them into a SQLite database.
3. `analyze.py` runs SQL queries to produce a report: event counts by level/type, top offending IPs, HTTP error counts, and a brute-force alert.

## Requirements
Python 3.8+. No external packages — `re`, `sqlite3`, `datetime`, and `random` are all in the standard library, so there's nothing to `pip install`.

## How to run
```bash
python3 generate_sample_logs.py   # creates logs/server.log
python3 parse_and_load.py         # creates logs.db
python3 analyze.py                # prints the report
```
Run them in that order, in the same folder.

## Using it on a real Linux server
Skip step 1. Point `parse_and_load.py` at a real log file instead:
```bash
mkdir -p logs
sudo cp /var/log/auth.log ./logs/server.log
python3 parse_and_load.py
python3 analyze.py
```
You may need to tweak `LOG_PATTERN` in `parse_and_load.py`, since real log formats vary slightly by Linux distro.

## How this maps to job skills
- **Linux** — log file formats, syslog conventions, reading logs from `/var/log/`, terminal commands (`tail -f`, `grep`, `cat`)
- **Python** — regex parsing, file I/O, `sqlite3`, writing a small data pipeline
- **SQL** — schema design, `GROUP BY`, aggregate functions, filtering — the kind of queries a Data Analyst/Engineer writes daily

## Ideas to extend later
- Upload `logs.db` or a CSV export to an **S3 bucket** with `boto3` — brings AWS into the story
- Turn `analyze.py` into a cron job that alerts when brute-force attempts are detected
- Swap SQLite for **PostgreSQL** running in Docker
- Add a small Flask page to view the report in a browser

## For your resume/portfolio
Push this to GitHub with this README as-is. In interviews: *"I built a pipeline that parses raw Linux server logs, structures them into a SQL database, and flags security/performance issues — the same pattern used in production log monitoring."*
