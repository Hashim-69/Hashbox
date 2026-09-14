"""
Windows event recorder - processes, outbound network, file changes, USB volumes.
Everything lands in one SQLite DB next to this script.
Run with pythonw.exe at boot via Task Scheduler, elevated. See SETUP.md.
"""

import json
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psutil
import pythoncom
import wmi
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# ============================================================================
# Configuration - edit these constants
# ============================================================================

SCRIPT_DIR = Path(__file__).resolve().parent
DB_PATH = SCRIPT_DIR / "blackbox.db"

# Path.home() resolves to whatever account the scheduled task runs as. If the
# task runs as SYSTEM this becomes C:\Windows\system32\config\systemprofile and
# monitors nothing useful - run the task as your own user (see SETUP.md).
HOME = Path.home()
MONITORED_FOLDERS = [
    HOME / "Desktop",
    HOME / "Documents",
    HOME / "Downloads",
]

PRUNE_INTERVAL_HOURS = 1
PRUNE_OLDER_THAN_DAYS = 30

# The only continuously running cost in the whole recorder. One poll measures
# ~2.1ms, so 5s is ~0.04% of a core; drop to 2s for finer resolution at ~0.11%.
NETWORK_POLL_INTERVAL_SECONDS = 5
# UDP sockets always report a status of NONE, so the status filter below drops
# every one of them regardless of this setting. "inet" therefore costs ~72%
# more per poll than "tcp" while producing identical events. To genuinely
# record UDP (and with it QUIC/HTTP-3), set this to "inet" *and* add
# psutil.CONN_NONE to the statuses - changing one without the other does
# nothing but burn CPU.
NETWORK_CONNECTION_KIND = "tcp"
WATCHED_CONNECTION_STATUSES = ("ESTABLISHED", "SYN_SENT")

# Both WMI watchers block in the kernel until an event arrives, costing nothing
# while they wait. This only controls how often that wait is interrupted to loop,
# so keep it long - a short timeout wakes the CPU for no reason.
WMI_TIMEOUT_MS = 30_000

# Windows apps emit a burst of modify events per single save; collapse repeats
# on the same path inside this window.
MODIFY_DEBOUNCE_SECONDS = 1.0

# Churn that costs write volume without telling you anything. Editors and
# browsers touch these constantly; the meaningful event is the final file
# appearing, which still gets recorded.
IGNORED_FILE_SUFFIXES = (".tmp", ".temp", ".crdownload", ".part", ".partial", ".swp", ".lock")
IGNORED_PATH_FRAGMENTS = ("\\~$", "\\.git\\", "\\node_modules\\", "\\__pycache__\\", "\\.venv\\")

# Console writes on Windows cost more than the DB insert they accompany. Leave
# this off for the scheduled task; turn it on to watch events live.
ECHO_EVENTS = False

# Run below normal CPU and I/O priority so the recorder never competes with
# whatever you are actually doing.
LOWER_OWN_PRIORITY = True

# ============================================================================
# Database
# ============================================================================

db_lock = threading.Lock()
db_conn = None


def utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def init_database():
    global db_conn
    db_conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)

    # WAL lets query.py read while this process is writing.
    db_conn.execute("PRAGMA journal_mode=WAL")
    db_conn.execute("PRAGMA synchronous=NORMAL")
    db_conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            kind TEXT NOT NULL,
            detail TEXT NOT NULL
        )
    """)
    db_conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
    db_conn.commit()


def log_event(kind, detail):
    timestamp = utc_now_iso()
    detail_json = json.dumps(detail, ensure_ascii=False)

    with db_lock:
        db_conn.execute(
            "INSERT INTO events (timestamp, kind, detail) VALUES (?, ?, ?)",
            (timestamp, kind, detail_json),
        )
        db_conn.commit()

    # Under pythonw.exe sys.stdout is None and print() is a silent no-op anyway.
    if ECHO_EVENTS:
        print(f"[{timestamp}] {kind}: {detail_json}")


def prune_old_events():
    cutoff = datetime.now(timezone.utc) - timedelta(days=PRUNE_OLDER_THAN_DAYS)
    cutoff_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    with db_lock:
        cursor = db_conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff_iso,))
        deleted = cursor.rowcount
        db_conn.commit()

    if deleted > 0:
        print(f"[{utc_now_iso()}] pruned {deleted} events older than {PRUNE_OLDER_THAN_DAYS}d")


# ============================================================================
# Process creation - WMI extrinsic event, needs elevation
# ============================================================================

def monitor_processes():
    pythoncom.CoInitialize()
    try:
        watcher = start_watcher("process_create", "Win32_ProcessStartTrace")
        if watcher is None:
            return

        while True:
            event = next_wmi_event(watcher)
            if event is None:
                continue

            # PID/PPID/name come from the trace itself so they survive the
            # process exiting; only the command line needs a live handle.
            log_event("process_create", {
                "pid": event.ProcessID,
                "parent_pid": event.ParentProcessID,
                "image_name": event.ProcessName,
                "cmdline": read_cmdline(event.ProcessID),
            })
    finally:
        pythoncom.CoUninitialize()


def read_cmdline(pid):
    try:
        return " ".join(psutil.Process(pid).cmdline())
    except psutil.NoSuchProcess:
        return None
    except psutil.AccessDenied:
        return None


def next_wmi_event(watcher, timeout_ms=WMI_TIMEOUT_MS):
    try:
        return watcher(timeout_ms=timeout_ms)
    except wmi.x_wmi_timed_out:
        return None


def start_watcher(source, wmi_class):
    # Win32_ProcessStartTrace needs elevation, so this fails on a normally
    # launched run. The thread would then die mute - print() is a no-op under
    # pythonw - and the gap only surfaces when a query comes back empty, so
    # the failure goes in the DB where it can actually be found.
    try:
        return getattr(wmi.WMI(), wmi_class).watch_for()
    except wmi.x_wmi as error:
        log_event("monitor_error", {"source": source, "error": str(error)})
        return None


# ============================================================================
# Outbound network connections - poll psutil, diff against last poll
# ============================================================================

def monitor_network():
    # Sockets already open at startup form the baseline and are never logged;
    # only transitions after this point are events.
    seen = current_connections() or {}

    while True:
        time.sleep(NETWORK_POLL_INTERVAL_SECONDS)
        current = current_connections()

        # Keep the previous baseline on a failed read. Replacing it with an
        # empty one would make every live socket look new on the next poll.
        if current is None:
            continue

        new_keys = current.keys() - seen.keys()
        seen = current

        # One name lookup per pid per poll rather than per connection - a browser
        # can open dozens of sockets at once. Deliberately not cached across
        # polls: Windows recycles PIDs, and a wrong name is worse than a lookup.
        names = {}
        for key in new_keys:
            pid, remote_ip, remote_port, local_port = key
            if pid not in names:
                names[pid] = read_process_name(pid)

            log_event("network_connection", {
                "pid": pid,
                "process_name": names[pid],
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "local_port": local_port,
                "status": current[key],
            })


def current_connections():
    # None rather than an empty mapping: the caller has to tell "nothing is
    # connected" apart from "we were not allowed to look".
    try:
        connections = psutil.net_connections(kind=NETWORK_CONNECTION_KIND)
    except psutil.AccessDenied:
        return None

    # Status stays out of the key and rides along as the value, so a SYN_SENT
    # that later becomes ESTABLISHED is one event rather than two.
    return {
        (conn.pid, conn.raddr.ip, conn.raddr.port, conn.laddr.port): conn.status
        for conn in connections
        if conn.raddr and conn.status in WATCHED_CONNECTION_STATUSES
    }


def read_process_name(pid):
    if pid is None:
        return None
    try:
        return psutil.Process(pid).name()
    except psutil.NoSuchProcess:
        return None
    except psutil.AccessDenied:
        return None


# ============================================================================
# File activity - watchdog
# ============================================================================

class FileEventHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_modify = {}

    def on_created(self, event):
        if event.is_directory or is_ignored(event.src_path):
            return
        log_event("file_create", {"path": event.src_path})

    def on_deleted(self, event):
        if event.is_directory or is_ignored(event.src_path):
            return
        log_event("file_delete", {"path": event.src_path})

    def on_moved(self, event):
        if event.is_directory or is_ignored(event.src_path):
            return
        log_event("file_move", {"from_path": event.src_path, "to_path": event.dest_path})

    def on_modified(self, event):
        if event.is_directory or is_ignored(event.src_path):
            return

        now = time.monotonic()
        previous = self.last_modify.get(event.src_path)
        if previous is not None and now - previous < MODIFY_DEBOUNCE_SECONDS:
            return

        # Bound the debounce table rather than tracking every path ever touched.
        if len(self.last_modify) > 4096:
            self.last_modify.clear()

        self.last_modify[event.src_path] = now
        log_event("file_modify", {"path": event.src_path})


# The DB usually lives under a monitored folder, so its own writes would be
# recorded as file events, which would write again - an endless loop.
OWN_PATH_PREFIX = str(SCRIPT_DIR).lower()


def is_ignored(path):
    lowered = path.lower()
    if lowered.startswith(OWN_PATH_PREFIX):
        return True
    if lowered.endswith(IGNORED_FILE_SUFFIXES):
        return True
    return any(fragment in lowered for fragment in IGNORED_PATH_FRAGMENTS)


def start_file_observer():
    observer = Observer()
    handler = FileEventHandler()

    for folder in MONITORED_FOLDERS:
        if not folder.is_dir():
            print(f"skipping missing folder: {folder}")
            continue
        observer.schedule(handler, str(folder), recursive=True)

    observer.start()
    return observer


# ============================================================================
# USB volumes - WMI extrinsic event
# ============================================================================

VOLUME_EVENT_ACTIONS = {2: "insert", 3: "remove"}


def monitor_usb():
    pythoncom.CoInitialize()
    try:
        watcher = start_watcher("usb_volume", "Win32_VolumeChangeEvent")
        if watcher is None:
            return

        while True:
            event = next_wmi_event(watcher)
            if event is None:
                continue

            # Other EventTypes are config-change and docking noise.
            action = VOLUME_EVENT_ACTIONS.get(event.EventType)
            if action is None:
                continue

            log_event("usb_volume", {"action": action, "drive_letter": event.DriveName})
    finally:
        pythoncom.CoUninitialize()


# ============================================================================
# Main
# ============================================================================

def lower_own_priority():
    own = psutil.Process()
    try:
        own.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
        own.ionice(psutil.IOPRIO_LOW)
    except psutil.AccessDenied:
        print("could not lower own priority")


def main():
    print(f"blackbox starting - db: {DB_PATH}")
    if LOWER_OWN_PRIORITY:
        lower_own_priority()
    init_database()

    observer = start_file_observer()
    for target in (monitor_processes, monitor_network, monitor_usb):
        thread = threading.Thread(target=target, name=target.__name__, daemon=True)
        thread.start()
        print(f"started {thread.name}")

    try:
        while True:
            prune_old_events()
            time.sleep(PRUNE_INTERVAL_HOURS * 3600)
    except KeyboardInterrupt:
        print("shutting down")
    finally:
        observer.stop()
        observer.join()


if __name__ == "__main__":
    main()
