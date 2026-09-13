# Hashbox

A single-file event recorder for your own Windows machine. It watches four
things — process launches, outbound network connections, file activity in your
user folders, and USB volumes — and appends them all to one local SQLite
database. Nothing is sent anywhere; the DB sits next to the script.

Think of it as a flight recorder for a laptop: when something weird happened
last Tuesday, you have a timeline instead of a guess.

```
pip install -r requirements.txt
python blackbox.py          # run elevated
python query.py last 20     # in another terminal
```

No CLI framework, no config file, no plugins. Behaviour lives in constants at
the top of `blackbox.py`.

## How it works

One process, four daemon threads, one writer lock. Each thread turns its own
source of raw Windows events into a row.

### Threads

| Thread | Source | Emits |
| --- | --- | --- |
| `monitor_processes` | WMI `Win32_ProcessStartTrace` | `process_create` |
| `monitor_network` | `psutil.net_connections` polled every 2s | `network_connection` |
| watchdog `Observer` | filesystem notifications | `file_create` / `file_modify` / `file_delete` / `file_move` |
| `monitor_usb` | WMI `Win32_VolumeChangeEvent` | `usb_volume` |

The main thread does nothing but prune and sleep.

**Processes.** `Win32_ProcessStartTrace` is an *extrinsic* WMI event, meaning
Windows pushes it the instant a process starts — unlike polling
`Win32_Process`, it cannot miss something that lives for 40ms. The trace itself
carries PID, parent PID and image name, so those are always recorded. It does
not carry the command line, so that one field is read back with psutil; if the
process already exited or is protected, `cmdline` is `null` and the rest of the
row is still intact. This class requires elevation, which is why the task runs
with highest privileges.

**Network.** psutil has no event API, so this polls — the one continuously
running cost in the program, measured at ~2.9 ms per poll, or about 0.06 % of a
core at the default 5 s interval. Each poll builds a set of
`(pid, remote_ip, remote_port, local_port, status)` for every socket with a
remote address in `ESTABLISHED` or `SYN_SENT`, then logs the set difference
against the previous poll — new connections only. `SYN_SENT` is included so an
outbound attempt to a host that never answers still leaves a trace. The
baseline is primed on the very first poll, so starting the recorder does not
dump every socket that was already open. Connection status is deliberately
left out of the dedup key, otherwise one connection would be logged twice as it
moves from `SYN_SENT` to `ESTABLISHED`. Process names are resolved once per PID
per poll instead of once per connection, because a browser can open dozens of
sockets at once; that cache is dropped each poll, since Windows recycles PIDs
and a stale name would be worse than the 0.16 ms lookup.

**Files.** A single watchdog `Observer` is scheduled recursively on Desktop,
Documents and Downloads. Watchdog is event-driven here (`ReadDirectoryChangesW`),
so an idle filesystem costs nothing. Three things are filtered out:

- Directory events, since the interesting unit is a file.
- Anything under the script's own folder. Without this, writing an event to the
  DB produces a file event, which writes another event, forever.
- Known churn — `.tmp`, `.crdownload`, `.part`, Office `~$` lock files, `.git/`,
  `node_modules/`, `__pycache__/`. These are the bulk of raw filesystem noise
  and recording them costs write volume without telling you anything; the
  meaningful event, the finished file appearing, is still captured.

Windows apps also emit a burst of modify notifications for a single save, so
repeat modifications to the same path inside one second collapse into one row.

**USB.** `Win32_VolumeChangeEvent` is also extrinsic. `EventType` 2 is arrival
and 3 is removal; configuration-change and docking types are ignored. The drive
letter comes through as `DriveName`.

### Storage

One table, one shape for everything:

```sql
CREATE TABLE events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,   -- UTC ISO8601, e.g. 2026-09-13T14:02:11.481920Z
    kind      TEXT NOT NULL,   -- process_create, network_connection, file_modify, ...
    detail    TEXT NOT NULL    -- JSON, fields vary by kind
);
CREATE INDEX idx_events_timestamp ON events(timestamp);
```

Keeping the per-kind fields in a JSON `detail` blob means a new event source
never needs a migration, and SQLite's `json_extract` still gives exact field
matching at query time.

All four threads share one `sqlite3` connection opened with
`check_same_thread=False`, and every write goes through a single
`threading.Lock`. The DB runs in WAL mode so `query.py` can read a live
database without hitting `database is locked`. Each event is committed
immediately rather than batched — for a recorder, losing the last few seconds
to a hard power-off defeats the purpose.

Set `ECHO_EVENTS = True` to also print every event to stdout when running under
`python.exe`. It is off by default because a console write on Windows costs more
than the database insert it accompanies, and under `pythonw.exe` there is no
console anyway — `sys.stdout` is `None` and `print` becomes a silent no-op.

## Footprint

Measured on a Windows 11 laptop, Python 3.12:

| | |
| --- | --- |
| CPU, idle | ~0.06 % of one core (one 2.9 ms network poll per 5 s) |
| Memory | ~28 MB RSS, of which ~20 MB is the interpreter plus psutil |
| Write ceiling | ~9,100 events/sec (0.109 ms per insert+commit) |
| Disk | 211 bytes/row — ~32 MB for 30 days at 5,000 events/day |

Nothing else runs on a timer: both WMI watchers block in the kernel until
Windows pushes an event, and watchdog is notification-driven. `WMI_TIMEOUT_MS`
is set to 30 s so those waits are interrupted twice a minute rather than once a
second, which keeps the CPU out of the way of deeper idle states on battery.

The recorder also drops itself to `BELOW_NORMAL_PRIORITY_CLASS` and low I/O
priority at startup, so it yields to whatever you are actually doing. Set
`LOWER_OWN_PRIORITY = False` to disable.

If you need it lighter still, in order of effect: raise
`NETWORK_POLL_INTERVAL_SECONDS`, or set `NETWORK_CONNECTION_KIND = "tcp"` to
halve the poll cost at the price of no longer seeing QUIC/UDP traffic. Batching
writes is not worth it — the DB is already three orders of magnitude faster than
any realistic event rate.

### Retention

The main thread prunes rows older than 30 days, then sleeps an hour, forever.
Pruning runs once at startup too, so a machine that was off for a month cleans
up on the next boot rather than an hour into it.

### Sample rows

```json
{"pid": 17384, "parent_pid": 9012, "image_name": "powershell.exe",
 "cmdline": "powershell.exe -NoProfile -File C:\\tmp\\a.ps1"}

{"pid": 4820, "process_name": "chrome.exe", "remote_ip": "142.250.185.46",
 "remote_port": 443, "local_port": 55214, "status": "ESTABLISHED"}

{"action": "insert", "drive_letter": "E:"}
```

## Reading the data

`query.py` has four canned reads:

```
python query.py last [N]         last N events (default 50)
python query.py process <name>   every event for an exact image/process name
python query.py usb              usb insert/remove history
python query.py ip <address>     connections to an exact remote IP
```

Name and IP lookups use `json_extract` with exact comparison rather than
`LIKE '%…%'`, so searching `1.2.3.4` does not also return `1.2.3.40`, and a
process name does not match because it appeared inside a file path. It opens
the DB read-only, so a query can never interfere with the recorder.

## Running at boot

See [SETUP.md](SETUP.md) for the Task Scheduler steps. Two things matter: the
task must **run with highest privileges** (or process tracing silently yields
nothing), and it must run **as your own user account, not SYSTEM** (or
`Path.home()` resolves to the system profile and it watches empty folders).

## Scope

This is a local, self-auditing tool for a machine you own. It records metadata
only — no file contents, no keystrokes, no screen capture — and has no network
or remote-reporting code of any kind. On a shared or work machine, get
permission before recording; on any machine, `blackbox.db` is a detailed log of
your own activity, so treat it as sensitive and don't commit it.

## Requirements

Windows, Python 3.9+, and `psutil`, `pywin32`, `wmi`, `watchdog`.
