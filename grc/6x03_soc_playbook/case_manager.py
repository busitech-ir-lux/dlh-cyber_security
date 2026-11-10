#!/usr/bin/env python3
"""Persistent local case store; import initializes cases.db in the working directory."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

DB_PATH = Path("cases.db")
SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolution TEXT
);
CREATE TABLE IF NOT EXISTS case_notes (
    note_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);
CREATE TABLE IF NOT EXISTS case_iocs (
    ioc_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    verdict TEXT NOT NULL,
    score INTEGER NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);
"""
STATUSES = {"open", "investigating", "escalated", "closed"}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _connect():
    connection = sqlite3.connect(str(DB_PATH), timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db(db_path: str = "cases.db") -> None:
    global DB_PATH
    DB_PATH = Path(db_path)
    connection = _connect()
    try:
        with connection:
            connection.executescript(SCHEMA)
    finally:
        connection.close()


def _next_case_id(connection, day: str) -> str:
    prefix = "CASE-" + day + "-"
    number = connection.execute(
        "SELECT COUNT(*) FROM cases WHERE case_id LIKE ?", (prefix + "%",)).fetchone()[0] + 1
    # Keep count-based task semantics, but do not collide if a row was deleted.
    while connection.execute("SELECT 1 FROM cases WHERE case_id = ?", (prefix + format(number, "03d"),)).fetchone():
        number += 1
    return prefix + format(number, "03d")


def generate_case_id() -> str:
    connection = _connect()
    try:
        return _next_case_id(connection, datetime.now(timezone.utc).strftime("%Y%m%d"))
    finally:
        connection.close()


def create_case(alert_id: str, severity: str, title: str, description: str, iocs: list[dict]) -> str:
    if not alert_id or not title or severity not in {"Critical", "High", "Medium", "Low"}:
        raise ValueError("Case needs alert ID, title and valid severity")
    connection = _connect()
    try:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            timestamp = utc_now()
            case_id = _next_case_id(connection, timestamp[:10].replace("-", ""))
            connection.execute(
                "INSERT INTO cases(case_id,alert_id,severity,title,description,status,created_at,updated_at) "
                "VALUES(?,?,?,?,?,'open',?,?)",
                (case_id, alert_id, severity, title, description, timestamp, timestamp))
            for ioc in iocs:
                connection.execute(
                    "INSERT INTO case_iocs(case_id,ioc_value,ioc_type,verdict,score) VALUES(?,?,?,?,?)",
                    (case_id, ioc["ioc_value"], ioc["ioc_type"], ioc["verdict"], ioc["score"]))
        return case_id
    finally:
        connection.close()


def add_case_note(case_id: str, note: str) -> bool:
    connection = _connect()
    try:
        with connection:
            if not connection.execute("SELECT 1 FROM cases WHERE case_id=?", (case_id,)).fetchone():
                return False
            now = utc_now()
            connection.execute("INSERT INTO case_notes(case_id,note,created_at) VALUES(?,?,?)", (case_id, note, now))
            connection.execute("UPDATE cases SET updated_at=? WHERE case_id=?", (now, case_id))
        return True
    finally:
        connection.close()


def update_case_status(case_id: str, status: str) -> bool:
    if status not in STATUSES:
        return False
    connection = _connect()
    try:
        with connection:
            cursor = connection.execute(
                "UPDATE cases SET status=?,updated_at=?,resolution=CASE WHEN ?='closed' THEN resolution ELSE NULL END "
                "WHERE case_id=?", (status, utc_now(), status, case_id))
        return cursor.rowcount == 1
    finally:
        connection.close()


def close_case(case_id: str, resolution: str) -> bool:
    if not isinstance(resolution, str) or not resolution.strip():
        return False
    connection = _connect()
    try:
        with connection:
            cursor = connection.execute("UPDATE cases SET status='closed',resolution=?,updated_at=? WHERE case_id=?",
                                        (resolution, utc_now(), case_id))
        return cursor.rowcount == 1
    finally:
        connection.close()


def get_case(case_id: str) -> dict:
    connection = _connect()
    try:
        row = connection.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["notes"] = [dict(row) for row in connection.execute(
            "SELECT note,created_at FROM case_notes WHERE case_id=? ORDER BY note_id", (case_id,))]
        result["iocs"] = [dict(row) for row in connection.execute(
            "SELECT ioc_value,ioc_type,verdict,score FROM case_iocs WHERE case_id=? ORDER BY ioc_id", (case_id,))]
        return result
    finally:
        connection.close()


def list_cases(status: str = None) -> list[dict]:
    connection = _connect()
    try:
        sql = "SELECT case_id,alert_id,severity,title,status,created_at FROM cases"
        params = ()
        if status is not None:
            sql += " WHERE status=?"
            params = (status,)
        return [dict(row) for row in connection.execute(sql + " ORDER BY case_id", params)]
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    listing = sub.add_parser("list")
    listing.add_argument("--status", choices=sorted(STATUSES))
    get = sub.add_parser("get")
    get.add_argument("case_id")
    close = sub.add_parser("close")
    close.add_argument("case_id")
    close.add_argument("resolution")
    args = parser.parse_args()
    try:
        if args.command == "get":
            result = get_case(args.case_id)
            print(json.dumps(result, indent=2))
            return 0 if result else 1
        if args.command == "close":
            ok = close_case(args.case_id, args.resolution)
            print("Case closed" if ok else "Case not found or invalid resolution")
            return 0 if ok else 1
        rows = list_cases(args.status)
        if args.status is None:
            rows = [row for row in rows if row["status"] in ("open", "escalated", "investigating")]
        columns = ("case_id", "alert_id", "severity", "title", "status")
        headers = ("Case ID", "Alert ID", "Severity", "Title", "Status")
        widths = [max([len(header)] + [len(str(row[col])) for row in rows]) for col, header in zip(columns, headers)]
        border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"
        print(border)
        print("| " + " | ".join(header.ljust(width) for header, width in zip(headers, widths)) + " |")
        print(border)
        for row in rows:
            print("| " + " | ".join(str(row[col]).ljust(width) for col, width in zip(columns, widths)) + " |")
        print(border)
        print("{} cases (filter: {})".format(len(rows), args.status or "open + escalated + investigating"))
        return 0
    except (sqlite3.Error, OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1


init_db()

if __name__ == "__main__":
    raise SystemExit(main())
