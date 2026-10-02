"""
generate_sample_logs.py

Creates a realistic sample Linux server log file (similar to /var/log/auth.log
and /var/log/syslog combined) so you can practice log analysis without needing
access to a real server.

On a REAL Linux machine, you'd skip this script entirely and instead read
actual logs, e.g.:
    sudo cat /var/log/auth.log
    sudo tail -f /var/log/syslog
"""

import os
import random
from datetime import datetime, timedelta

HOST = "web01"

SUSPICIOUS_IPS = ["203.0.113.9", "198.51.100.23", "192.0.2.77"]
NORMAL_IPS = ["192.168.1.10", "192.168.1.22", "10.0.0.5", "192.168.1.45"]
USERS = ["admin", "root", "deploy", "ubuntu", "test"]

ADMIN_USERS = ["deploy", "ubuntu"]
NON_ADMIN_USERS = ["test", "guest", "intern"]
NORMAL_SUDO_COMMANDS = ["/usr/bin/systemctl restart nginx", "/usr/bin/apt-get update", "/bin/journalctl -xe"]
SUSPICIOUS_SUDO_COMMANDS = ["/bin/bash", "/bin/su -", "/usr/bin/passwd root", "/usr/sbin/visudo"]


def ssh_failed(ip, user, pid):
    port = random.randint(30000, 60000)
    return f"sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2"


def ssh_success(ip, user, pid):
    port = random.randint(30000, 60000)
    return f"sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"


def sudo_command(pid):
    # most sudo use is routine admin work; occasionally simulate a
    # non-admin user attempting to escalate privileges
    if random.random() < 0.3:
        user = random.choice(NON_ADMIN_USERS)
        command = random.choice(SUSPICIOUS_SUDO_COMMANDS)
    else:
        user = random.choice(ADMIN_USERS)
        command = random.choice(NORMAL_SUDO_COMMANDS)
    tty = f"pts/{random.randint(0, 3)}"
    return f"sudo[{pid}]: {user} : TTY={tty} ; PWD=/home/{user} ; USER=root ; COMMAND={command}"


def cron_job(pid):
    jobs = ["/usr/lib/php/sessionclean", "/usr/local/bin/backup.sh", "/usr/bin/certbot renew"]
    return f"CRON[{pid}]: (root) CMD ({random.choice(jobs)})"


def nginx_request(ip):
    paths = ["/", "/index.html", "/login", "/admin", "/api/users", "/favicon.ico"]
    statuses = [200, 200, 200, 404, 500, 301]
    path = random.choice(paths)
    status = random.choice(statuses)
    size = random.randint(150, 5000)
    return f'nginx: {ip} - - "GET {path} HTTP/1.1" {status} {size}'


def kernel_warning():
    msgs = [
        "CPU0: Core temperature above threshold, cpu clock throttled",
        "Out of memory: Kill process 4821 (python3) score 900",
        "EXT4-fs warning: mounted filesystem without journal",
    ]
    return f"kernel: [{random.randint(10000, 99999)}.{random.randint(0, 999)}] {random.choice(msgs)}"


def disk_warning():
    pct = random.randint(85, 99)
    return f"diskmonitor[{random.randint(1000, 9999)}]: WARNING disk usage at {pct}% on /dev/sda1"


def generate_logs(num_entries=400, out_path="logs/server.log"):
    start_time = datetime(2026, 9, 10, 0, 0, 0)
    entries = []
    pid = 1000

    for _ in range(num_entries):
        pid += 1
        timestamp = start_time + timedelta(minutes=random.randint(0, 6 * 24 * 60))

        roll = random.random()
        if roll < 0.14:
            # simulated brute-force bursts from suspicious IPs
            msg = ssh_failed(random.choice(SUSPICIOUS_IPS), random.choice(USERS), pid)
        elif roll < 0.19:
            msg = ssh_success(random.choice(NORMAL_IPS), random.choice(ADMIN_USERS), pid)
        elif roll < 0.26:
            msg = sudo_command(pid)
        elif roll < 0.50:
            msg = nginx_request(random.choice(NORMAL_IPS + SUSPICIOUS_IPS))
        elif roll < 0.68:
            msg = cron_job(pid)
        elif roll < 0.81:
            msg = kernel_warning()
        else:
            msg = disk_warning()

        entries.append((timestamp, msg))

    # sort on the real datetime objects (they carry a year) instead of
    # re-parsing a formatted, yearless string
    entries.sort(key=lambda e: e[0])
    lines = [f"{ts.strftime('%b %d %H:%M:%S')} {HOST} {msg}" for ts, msg in entries]

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Generated {num_entries} log lines -> {out_path}")


if __name__ == "__main__":
    generate_logs()
