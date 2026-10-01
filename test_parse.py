"""
test_parse.py

Unit tests for parse_and_load.py. These check known log lines produce the
expected classification, independent of the randomly generated sample data.

Run with:
    python3 -m unittest test_parse.py -v
"""

import unittest

from parse_and_load import parse_line, classify, extract_actor


class TestClassify(unittest.TestCase):

    def test_failed_login_is_error(self):
        level, event_type = classify(
            "sshd", "Failed password for invalid user admin from 1.2.3.4 port 1000 ssh2"
        )
        self.assertEqual(level, "ERROR")
        self.assertEqual(event_type, "failed_login")

    def test_successful_login_is_info(self):
        level, event_type = classify(
            "sshd", "Accepted password for deploy from 1.2.3.4 port 1000 ssh2"
        )
        self.assertEqual(level, "INFO")
        self.assertEqual(event_type, "successful_login")

    def test_sudo_by_admin_is_normal(self):
        level, event_type = classify(
            "sudo", "deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/apt-get update"
        )
        self.assertEqual(event_type, "sudo_command")

    def test_sudo_by_non_admin_is_privilege_escalation(self):
        level, event_type = classify(
            "sudo", "guest : TTY=pts/0 ; PWD=/home/guest ; USER=root ; COMMAND=/bin/bash"
        )
        self.assertEqual(level, "ERROR")
        self.assertEqual(event_type, "privilege_escalation")

    def test_nginx_404_is_warning(self):
        level, _ = classify("nginx", '192.168.1.1 - - "GET /admin HTTP/1.1" 404 162')
        self.assertEqual(level, "WARNING")

    def test_nginx_500_is_error(self):
        level, _ = classify("nginx", '192.168.1.1 - - "GET /api HTTP/1.1" 500 162')
        self.assertEqual(level, "ERROR")


class TestParseLine(unittest.TestCase):

    def test_parses_full_line_correctly(self):
        line = (
            "Sep 10 03:14:22 web01 sshd[1050]: Failed password for invalid "
            "user admin from 198.51.100.23 port 51232 ssh2"
        )
        data = parse_line(line)
        self.assertIsNotNone(data)
        self.assertEqual(data["host"], "web01")
        self.assertEqual(data["process"], "sshd")
        self.assertEqual(data["source_ip"], "198.51.100.23")
        self.assertEqual(data["event_type"], "failed_login")
        self.assertEqual(data["actor_user"], "admin")

    def test_garbage_line_returns_none(self):
        self.assertIsNone(parse_line("this is not a valid log line"))


class TestExtractActor(unittest.TestCase):

    def test_sudo_actor(self):
        actor = extract_actor(
            "sudo", "guest : TTY=pts/0 ; PWD=/home/guest ; USER=root ; COMMAND=/bin/bash"
        )
        self.assertEqual(actor, "guest")

    def test_ssh_actor(self):
        actor = extract_actor("sshd", "Accepted password for deploy from 1.2.3.4 port 1000 ssh2")
        self.assertEqual(actor, "deploy")


if __name__ == "__main__":
    unittest.main()
