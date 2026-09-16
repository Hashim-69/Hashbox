# BlackBox Event Recorder

Records process creation, outbound network connections, file activity in
Desktop/Documents/Downloads, and USB volume insert/remove into
`C:\ProgramData\Hashbox\blackbox.db`. Rows older than 30 days are pruned hourly.

Edit the constants at the top of `blackbox.py` to change folders, poll
interval, or retention.

## Where this must live

Both of these matter, and both are about the same thing — this process runs
**elevated at every boot**, so anything it reads or executes must not be
writable by a non-administrator:

- **The script does not belong on your Desktop.** Your profile is writable
  without elevation, so any process running as you could append a line to
  `blackbox.py` and have it execute with administrator rights at the next
  boot. Put it somewhere only administrators can write.
- **The database does not belong next to the script.** It holds 30 days of
  command lines, file paths and network destinations. On Desktop it inherits
  that folder's ACL and is readable by anything running as you.

## Install

Run all of this from an **elevated** terminal. Without elevation
`Win32_ProcessStartTrace` fails and `psutil.net_connections` cannot see other
accounts' sockets.

1. Put the code somewhere non-administrators cannot modify:

   ```
   mkdir "C:\Program Files\Hashbox"
   copy blackbox.py query.py requirements.txt "C:\Program Files\Hashbox\"
   ```

2. Create the data directory and lock it down. `/inheritance:r` drops the
   inherited permissions that would otherwise let your own account read it:

   ```
   mkdir "C:\ProgramData\Hashbox"
   icacls "C:\ProgramData\Hashbox" /inheritance:r /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F"
   ```

   Verify with `icacls "C:\ProgramData\Hashbox"` — only those two entries
   should be listed. From then on `query.py` also needs an elevated terminal,
   which is the point.

3. Install the pinned dependencies and run it:

   ```
   pip install -r requirements.txt
   python "C:\Program Files\Hashbox\blackbox.py"
   ```

   Ctrl+C to stop.

   For supply-chain protection, generate hashes once and install with
   `--require-hashes` — a compromised package release would otherwise run
   elevated:

   ```
   pip hash <downloaded-wheel>
   pip install --require-hashes -r requirements.txt
   ```

Query it (elevated, per step 2):

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
   - Check **Do not store password**. The task still starts at boot before
     anyone logs in, and your Windows password is never saved with it. What
     that gives up is access to network shares and EFS-encrypted files, and
     the recorder uses neither.
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
     "C:\Program Files\Hashbox\blackbox.py"
     ```
   - **Start in:** (no quotes)
     ```
     C:\Program Files\Hashbox
     ```
     Point these at the protected copy from the Install step, not at a copy in
     your profile — a task with highest privileges pointed at a user-writable
     script is a local privilege escalation waiting to happen.
   - **OK**

6. **Conditions tab**
   - Uncheck **Start the task only if the computer is on AC power**
   - Uncheck **Stop if the computer switches to battery power**

7. **Settings tab**
   - Uncheck **Stop the task if it runs longer than**
   - Check **Run task as soon as possible after a scheduled start is missed**
   - **If the task is already running:** `Do not start a new instance`

8. **OK**. With **Do not store password** checked there is no password prompt.

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
- Command lines are passed through a redaction denylist before being stored, so
  `--password`, `--token`, `-H` (standalone and attached), mysql-style
  `-p<value>` and recognisable key shapes (`ghp_`, `sk-`, `AKIA`, …) are
  replaced with `<redacted>`. **This is damage reduction, not a guarantee** — no
  denylist knows every tool's flags, and things like `curl -u user:pass` still
  get through. The directory ACL from the Install step is the real control;
  treat the DB as sensitive regardless.
- The `-p` rule intentionally does not fire on values that could be a flag name
  or that start with a colon, so `powershell -psconsolefile`,
  `msbuild -p:Config=Release` and `tar -pxvf` are recorded intact. The trade is
  that an all-alphanumeric password passed as `-psecret123` is not redacted.
  Redaction that fires on benign arguments destroys the log's forensic value,
  which is the thing the recorder exists to provide.
- The DB is not tamper-evident. Anyone who can read it can also delete rows, so
  it is evidence for you, not evidence against a determined attacker who
  already has administrator rights on this machine.

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

**`PermissionError` from `query.py`, or "no database at ..."**
Expected after the `icacls` step — the DB is readable by administrators only.
Run `query.py` from an elevated terminal. If it persists, confirm the recorder
actually created `C:\ProgramData\Hashbox\blackbox.db`; an elevated task writes
there, a non-elevated manual run may not be able to.
