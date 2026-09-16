# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Hashbox (a.k.a. blackbox) is a single-file Windows event recorder: it watches process
launches, outbound network connections, file activity in the user's folders, and USB
volume changes, and appends every one of them as a row in a local SQLite DB at
`C:\ProgramData\Hashbox\blackbox.db`. There is no network or reporting code of any kind,
no CLI framework, no config file, and no plugin system — all behaviour lives in constants
at the top of `blackbox.py`.

## Commands

```
pip install -r requirements.txt       # Windows only; needs psutil, pywin32, wmi, watchdog
python blackbox.py                    # run the recorder (elevated)
python query.py last 20               # read the DB (elevated too - it is admin-only)
```

Everything must run from an **elevated** terminal: `Win32_ProcessStartTrace` fails without
elevation, `psutil.net_connections` cannot see other accounts' sockets, and the data
directory's ACL restricts it to Administrators and SYSTEM.

`query.py` subcommands: `last [N]`, `process <name>`, `usb`, `ip <address>`.

There is no test suite, linter, or build step. Verification is manual — SETUP.md's
"Verifying" table pairs each event source with an action and the query that should show it
(e.g. launch notepad, then `python query.py process notepad.exe`).

To watch events live while developing, set `ECHO_EVENTS = True` and run under `python.exe`
rather than `pythonw.exe`; under `pythonw.exe` `sys.stdout` is `None` and every `print` is
a silent no-op.

## Architecture

One process, four concurrent sources, one writer lock, one table.

| Source | Mechanism | Event kinds |
| --- | --- | --- |
| `monitor_processes` thread | WMI `Win32_ProcessStartTrace` (extrinsic, elevation required) | `process_create` |
| `monitor_network` thread | `psutil.net_connections` polled every 5s, diffed against last poll | `network_connection` |
| watchdog `Observer` | `ReadDirectoryChangesW` notifications on Desktop/Documents/Downloads | `file_create`, `file_modify`, `file_delete`, `file_move` |
| `monitor_usb` thread | WMI `Win32_VolumeChangeEvent` (extrinsic) | `usb_volume` |
| any of the above failing | `start_watcher` (setup) and `next_wmi_event` (mid-life) log the exception instead of dying mute | `monitor_error` |

The main thread only prunes rows older than `PRUNE_OLDER_THAN_DAYS` and sleeps. Both WMI
threads must `pythoncom.CoInitialize()` before touching WMI — they run `CoUninitialize()` in
a `finally`. `next_wmi_event` distinguishes three outcomes: an event, `None` for a routine
timeout (loop again), and the `WATCHER_DEAD` sentinel for a watcher that died mid-life
(record a `monitor_error` and return, so the `finally` still runs).

Storage is deliberately one shape for everything: `events(id, timestamp, kind, detail)`
where `detail` is a JSON blob whose fields vary by `kind`. A new event source therefore
never needs a schema migration, and `json_extract` still gives exact field matching at
query time. All threads share one `sqlite3` connection (`check_same_thread=False`) guarded
by a single `threading.Lock`; WAL mode lets `query.py` read a live DB; each event commits
immediately rather than batching, because a recorder that loses the last few seconds to a
hard power-off defeats its own purpose.

`query.py` intentionally duplicates `DB_PATH` rather than importing `blackbox.py` —
importing would pull in `wmi` and start nothing useful. **If you change `DATA_DIR` or
`DB_PATH`, change it in both files.**

## Constraints to preserve when editing

These are load-bearing decisions, each with a comment in the source explaining it. Don't
"simplify" them away:

- **`redact_secrets` runs on every command line before storage.** It is the only security
  logic in the file, kept separate from its single caller so it stays readable and
  testable. It is damage reduction, not a guarantee — the directory ACL is the real
  control. Adding an ambiguous flag (`-u`, `-h`) to the denylist destroys forensic value
  by firing on benign arguments.
- **The `-p` and token rules are narrow on purpose, and the bias runs toward keeping data.**
  `redact_short_flag` skips `-p` values that could be a long-form flag name or that start
  with a colon, so `powershell -psconsolefile`, `msbuild -p:Config=Release`, `tar -pxvf`
  and `node -print` survive intact; `sk-`/`AKIA`/`ASIA` require full real-world key length
  so a path like `sk-experiments-01` is not eaten. Widening either rule to catch more
  secrets will blind the recorder to real execution vectors — `-psconsolefile` is one — which
  costs more than the secret it saves. Short flags in `SECRET_SHORT_FLAGS` get standalone
  and attached coverage from one code path, so a new entry cannot silently leak the
  attached spelling.
- **Network connection status is the diff map's *value*, never part of its key.** In the
  key, one connection would be logged twice as it moves `SYN_SENT` → `ESTABLISHED`.
- **`current_connections()` returns `None`, not `{}`, on `AccessDenied`,** and
  `monitor_network` keeps the previous baseline in that case — replacing it with an empty
  map would make every live socket look new on the next poll.
- **`NETWORK_CONNECTION_KIND = "tcp"` and `WATCHED_CONNECTION_STATUSES` are coupled.**
  psutil reports UDP sockets with status `NONE`, so the status filter drops them all;
  switching to `"inet"` alone costs ~72% more per poll for byte-identical output. Capturing
  UDP requires `"inet"` *and* `psutil.CONN_NONE` in the statuses.
- **`EXCLUDED_PREFIXES` keeps both `SCRIPT_DIR` and `DATA_DIR` out of file monitoring.**
  A DB write inside a watched folder produces a file event, which writes another event,
  forever. The DB now lives outside the watched folders, but both stay excluded so that
  repointing `DB_PATH` cannot silently reintroduce the loop.
- **`query.py`'s `show()` re-serialises `detail` with `json.dumps`.** Recorded values are
  attacker-controlled (a process picks its own command line); re-escaping neutralises ANSI
  escapes and bidi overrides. Printing the fields directly would undo that.
- **`query.py` opens the DB read-only (`?mode=ro`) and orders by `id`, not `timestamp`**
  (timestamps can tie, ids cannot), and rejects counts below 1 because SQLite treats a
  negative `LIMIT` as unlimited.
- **`requirements.txt` is pinned to exact versions** because this process runs elevated at
  boot; bump versions deliberately, not incidentally.

## Deployment shape

The recorder is meant to run at boot via Task Scheduler with **highest privileges** and as
**the user's own account, not SYSTEM** — as SYSTEM, `Path.home()` resolves to
`C:\Windows\system32\config\systemprofile` and `MONITORED_FOLDERS` watches nothing. The
code lives somewhere non-administrators cannot write (e.g. `C:\Program Files\Hashbox`),
because a user-writable script running elevated at boot is a privilege escalation. SETUP.md
has the full Task Scheduler walkthrough, the `icacls` invocation for the data directory, and
a troubleshooting table keyed by symptom.
