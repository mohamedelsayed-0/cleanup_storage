# Mac Storage Cleanup Tool

A local, dependency-free Mac storage cleanup assistant focused on developer-heavy junk: package caches, ML model caches, virtual environments, `node_modules`, Xcode build artifacts, and large Downloads files.

Everything runs from one terminal script:

```bash
python3 cleanup.py
```

The script scans, ranks cleanup candidates by size, writes a Markdown report, asks terminal questions for target selection, and requires typing exactly `DELETE` before removing anything.

## Files

- `cleanup.py`: the full scanner, reporter, organizer, approval prompt, deletion logic, and logger.
- `cleanup_report.md`: generated Markdown report.
- `cleanup_log.txt`: appended deletion log.

## Safety Model

The cleaner does not auto-delete anything. It refuses protected system/user roots, symlinks, source control metadata, and git repository roots.

Protected roots include:

- `~/Documents`
- `~/Desktop`
- `~/Pictures`
- `~/Movies`
- `~/Music`
- `~/Applications`
- `/System`
- `/Library`
- `/usr`
- `/bin`
- `/sbin`
- `/Applications`

The scanner still checks known developer locations such as `~/Desktop/Projects` for junk subfolders like `node_modules`, but it never suggests deleting the project directory itself.

## Usage

Run a scan and generate `cleanup_report.md` without deleting anything:

```bash
python3 cleanup.py --dry-run
```

Run the interactive terminal cleanup flow:

```bash
python3 cleanup.py
```

The prompt accepts selections like:

```text
1 2 5
all
none
```

`all` only selects recommended `SAFE` items. Any deletion still requires typing exactly:

```text
DELETE
```

## Useful Options

Scan a specific developer root:

```bash
python3 cleanup.py --dry-run --scan-root ~/Desktop/Projects
```

Lower the target threshold:

```bash
python3 cleanup.py --dry-run --min-target-mb 25
```

Change the report/log paths:

```bash
python3 cleanup.py --report cleanup_report.md --log cleanup_log.txt
```

## Cleanup Categories

High-priority targets:

- HuggingFace cache
- Torch cache
- pip cache
- Homebrew cache
- Xcode DerivedData
- Conda environments
- `node_modules`
- Python virtual environments

Medium-priority targets:

- Large files in `~/Downloads`
- `.dmg`, `.pkg`, and `.zip` files in `~/Downloads`
- Large videos found in scanned developer roots
- Docker reclaimable storage, reported as manual-only

Low-priority targets:

- `__pycache__` folders
- User logs
- App cache subfolders

## Organizer

The terminal output and report include a recommended organizer summary for large files. It groups review items into buckets such as installers, archives, videos, and large files. This is advisory only; the tool does not move or rename files automatically.
