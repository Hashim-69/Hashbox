# BlackBox Event Recorder

Records process creation, outbound network connections, file activity in
Desktop/Documents/Downloads, and USB volume insert/remove into `blackbox.db`
next to the script. Rows older than 30 days are pruned hourly.

Edit the constants at the top of `blackbox.py` to change folders, poll
interval, or retention.

## Install

```
pip install -r requirements.txt
python blackbox.py
```

Ctrl+C to stop. Run this from an **elevated** terminal first — without
elevation `Win32_ProcessStartTrace` fails and `psutil.net_connections` cannot
see other accounts' sockets.

Query it:

```
python query.py last 20
```

## Task Scheduler: run at boot

1. **Open Task Scheduler** — `Win + R`, type `taskschd.msc`, Enter.

2. Right panel → **Create Task...** (not "Create Basic Task").

3. **General tab**
   - **Name:** `BlackBox Event Recorder`
   - **When running the task, use the following user account:** leave this as
     **your own user account**. Do not change it to `SYSTEM` — `Path.home()`
     would resolve to `C:\Windows\system32\config\systemprofile` and none of
     your real folders would be watched.
   - Select **Run whether user is logged on or not**
   - Check **Run with highest privileges** (required for process-start tracing)
   - **Configure for:** `Windows 10`

4. **Triggers tab** → **New...**
   - **Begin the task:** `At startup`
   - **Delay task for:** `30 seconds` (lets WMI and the profile finish loading)
   - **Enabled:** checked → **OK**

5. **Actions tab** → **New...**
   - **Action:** `Start a program`
   - **Program/script:** your `pythonw.exe` full path, e.g.
     ```
     C:\Users\<you>\AppData\Local\Programs\Python\Python312\pythonw.exe
     ```
     Find it with `where pythonw` in cmd. Use the interpreter you ran
     `pip install` against, or the imports will fail.
   - **Add arguments:** (keep the quotes)
     ```
     "C:\Users\<you>\Desktop\blackbox\blackbox.py"
     ```
   - **Start in:** (no quotes)
     ```
     C:\Users\<you>\Desktop\blackbox
     ```
   - **OK**

6. **Conditions tab**
   - Uncheck **Start the task only if the computer is on AC power**
   - Uncheck **Stop if the computer switches to battery power**

7. **Settings tab**
   - Uncheck **Stop the task if it runs longer than**
   - Check **Run task as soon as possible after a scheduled start is missed**
   - **If the task is already running:** `Do not start a new instance`

8. **OK**, then enter your Windows password when prompted (needed for "run
   whether user is logged on or not").

9. **Test:** right-click the task → **Run**. Confirm `pythonw.exe` appears in
   Task Manager → Details, then `python query.py last 10`.

10. **Stop:** right-click the task → **End**. Disable the trigger to stop it
    coming back at boot.

## Verifying

| Source | Test | Check |
| --- | --- | --- |
| Process | launch notepad | `python query.py process notepad.exe` |
| File | save a file on Desktop | `python query.py last 10` |
| USB | insert a stick | `python query.py usb` |
| Network | load a site | `python query.py last 20` |

## Notes

- Under `pythonw.exe` there is no console, so the stdout copy of each event is
  discarded. The DB is the record. Swap to `python.exe` in the Actions tab
  temporarily if you need to see startup errors.
- `blackbox.db-wal` / `blackbox.db-shm` appear next to the DB; that is WAL mode,
  which lets `query.py` read while the recorder writes. Don't delete them while
  it is running.
- Everything under the script's own folder is excluded from file monitoring.
  Without that, writing an event to the DB would generate a file event, which
  would write another event, forever.
- Command line is captured via psutil after the fact, so very short-lived
  processes log `"cmdline": null` — the PID, parent PID, and image name still
  come from the WMI trace and are always present.

## Troubleshooting

**Task runs but no events**
Point the action at `python.exe` instead of `pythonw.exe` and run the task from
a console to see the traceback. Usual cause: wrong interpreter, so `wmi` or
`watchdog` is missing.

**No `process_create` events, everything else works**
Task is not elevated. Re-check **Run with highest privileges**.

**Only a handful of file events, none from Desktop**
Task is running as `SYSTEM` or a different account. Fix the account in the
General tab, or hardcode absolute paths in `MONITORED_FOLDERS`.

**`database is locked`**
Two instances are running. Settings tab must be `Do not start a new instance`.
