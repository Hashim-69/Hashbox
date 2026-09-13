"""
Canned reads over blackbox.db. Run with no arguments for usage.
"""

import json
import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "blackbox.db"


def fetch(sql, params=()):
    # Read-only URI so a query can never block or corrupt the recorder.
    conn = sqlite3.connect(f"file:{DB_PATH.as_posix()}?mode=ro", uri=True)
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def show(title, rows):
    print(f"=== {title} ===\n")
    if not rows:
        print("no events found\n")
        return

    for event_id, timestamp, kind, detail in rows:
        print(f"[{event_id}] {timestamp} | {kind}")
        print(json.dumps(json.loads(detail), indent=2))
        print()


def last_n_events(n):
    # Ordered by id, not timestamp: timestamps can tie, ids cannot.
    rows = fetch(
        "SELECT id, timestamp, kind, detail FROM events ORDER BY id DESC LIMIT ?",
        (n,),
    )
    show(f"last {n} events", list(reversed(rows)))


def events_by_process(process_name):
    # Exact match on the name field so a path or IP containing the same text
    # does not come back as a hit.
    rows = fetch(
        """
        SELECT id, timestamp, kind, detail FROM events
        WHERE lower(coalesce(json_extract(detail, '$.image_name'),
                             json_extract(detail, '$.process_name'), '')) = lower(?)
        ORDER BY id DESC
        """,
        (process_name,),
    )
    show(f"events for process {process_name}", rows)


def usb_events():
    rows = fetch(
        "SELECT id, timestamp, kind, detail FROM events WHERE kind = 'usb_volume' ORDER BY id DESC"
    )
    show("usb volume events", rows)


def connections_to_ip(ip_address):
    rows = fetch(
        """
        SELECT id, timestamp, kind, detail FROM events
        WHERE kind = 'network_connection' AND json_extract(detail, '$.remote_ip') = ?
        ORDER BY id DESC
        """,
        (ip_address,),
    )
    show(f"connections to {ip_address}", rows)


USAGE = """blackbox query tool

  python query.py last [N]         last N events (default 50)
  python query.py process <name>   events for an exact image/process name
  python query.py usb              usb volume insert/remove events
  python query.py ip <address>     connections to an exact remote IP

  python query.py process chrome.exe
  python query.py ip 142.250.185.46
"""


def main():
    if not DB_PATH.exists():
        sys.exit(f"no database at {DB_PATH} - run blackbox.py first")

    args = sys.argv[1:]
    if not args:
        sys.exit(USAGE)

    command = args[0].lower()

    if command == "last":
        last_n_events(int(args[1]) if len(args) > 1 else 50)
        return

    if command == "usb":
        usb_events()
        return

    if command == "process":
        if len(args) < 2:
            sys.exit("process name required")
        events_by_process(args[1])
        return

    if command == "ip":
        if len(args) < 2:
            sys.exit("ip address required")
        connections_to_ip(args[1])
        return

    sys.exit(f"unknown command '{command}'\n\n{USAGE}")


if __name__ == "__main__":
    main()
